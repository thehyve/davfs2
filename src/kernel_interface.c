/*  dav_fuse.c: interface to the fuse kernel module FUSE_KERNEL_VERSION 7.
    Copyright (C) 2006, 2007, 2008. 2009, 2020 Werner Baumann

    This file is part of davfs2.

    davfs2 is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    davfs2 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with davfs2; if not, write to the Free Software Foundation,
    Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. */


#include "config.h"

#include <errno.h>
#include <error.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LIBINTL_H
#include <libintl.h>
#endif
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/wait.h>

#include <ne_ssl.h>

#include "defaults.h"
#include "mount_davfs.h"
#include "cache.h"
#include "kernel_interface.h"
#include "fuse_kernel.h"

#ifdef ENABLE_NLS
#define _(String) gettext(String)
#else
#define _(String) String
#endif


/* Constants from Linux headers */
/*==============================*/

#ifndef MISC_MAJOR
#define MISC_MAJOR 10
#endif
#ifndef FUSE_MINOR
#define FUSE_MINOR 229
#endif


/* Data Types */
/*============*/

/* There is no struct fuse_create_out in fuse_kernel.h. */

struct create_out {
    struct fuse_entry_out entry;
    struct fuse_open_out open;
};


/* Private constants */
/*===================*/

/* Name of the device to communicate with the
   kernel file system. */
#define FUSE_DEV_NAME "fuse"

/* Minimum minor version of fuse. */
#define FUSE_MIN_MINOR 13


/* Private global variables */
/*==========================*/

/* File descriptor of the fuse device. */
static int fuse_device;

/* The mountpoint. */
const char *mountpoint;

/* Buffer used for communication with the kernel module (in and out). */
static size_t buf_size;
static char *buf;
/* Header of incomming calls. */
static struct fuse_in_header *ih;
/* Header of outgoing replies. */
static struct fuse_out_header *oh;
/* Start of upcall specific structure. */
static char *upcall;
/* Start of upcall specific reply structure. */
static char *reply;

/* Time to wait for upcalls before calling dav_tidy_cache(). */
static time_t idle_time;

/* Send debug messages to syslog if dbg != 0. */
static int debug;

/* fuse wants the nodeid of the root node to be 1, so we have to translate
   between the real nodeid and what fuse wants. */
static uint64_t root;


/* Private function prototypes */
/*=============================*/

/* Functions to handle upcalls fromthe kernel module. */

static uint32_t
fuse_access(void);

static uint32_t
fuse_create(void);

static uint32_t
fuse_getattr(void);

static uint32_t
fuse_init(void);

static uint32_t
fuse_lookup(void);

static uint32_t
fuse_mkdir(void);

static uint32_t
fuse_mknod(void);

static uint32_t
fuse_open(void);

static uint32_t
fuse_read(void);

static uint32_t
fuse_release(void);

static uint32_t
fuse_rename(void);

static uint32_t
fuse_setattr(void);

static uint32_t
fuse_stat(void);

static uint32_t
fuse_write(void);

static uint32_t
not_implemented(const char *msg);


/* Auxiliary functions. */

static off_t
write_dir_entry(int fd, off_t off, const dav_node *node, const char *name);

static void
set_attr(struct fuse_attr *attr, const dav_node *node);


/* Public functions */
/*==================*/

void
dav_init_kernel_interface(const char *url, const char *mpoint,
                          const dav_args *args)
{
    debug = args->debug & DAV_DBG_KERNEL;
    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                           "Initializing kernel interface");

    mountpoint = mpoint;

    buf_size = args->buf_size * 1024;
    if (buf_size < (FUSE_MIN_READ_BUFFER + 1024))
        buf_size = FUSE_MIN_READ_BUFFER + 1024;
    buf = malloc(buf_size);
    if (!buf)
        error(EXIT_FAILURE, errno, _("can't allocate message buffer"));

    ih = (struct fuse_in_header *) buf;
    oh = (struct fuse_out_header *) buf;
    upcall = buf + sizeof(struct fuse_in_header);
    reply = buf + sizeof(struct fuse_out_header);

    idle_time = args->delay_upload;
    if (idle_time > args->lock_refresh / 2)
        idle_time = args->lock_refresh / 2;

    char *path = NULL;
    if (asprintf(&path, "%s/%s", DAV_DEV_DIR, FUSE_DEV_NAME) < 0) abort();

    fuse_device = open(path, O_RDWR | O_NONBLOCK);

    if (fuse_device <= 0) {
        error(0, 0, _("loading kernel module fuse"));
        int ret;
        pid_t pid = fork();
        if (pid == 0) {
            execl("/sbin/modprobe", "modprobe", "fuse", NULL);
            _exit(EXIT_FAILURE);
        } else if (pid < 0) {
            ret = -1;
        } else {
            if (waitpid(pid, &ret, 0) != pid)
                ret = -1;
        }

        if (ret) {
            error(0, 0, _("loading kernel module fuse failed"));
        } else {
            fuse_device = open(path, O_RDWR | O_NONBLOCK);
        }

        if (fuse_device <= 0) {
            error(0, 0, _("waiting for %s to be created"), path);
            sleep(2); 
            fuse_device = open(path, O_RDWR | O_NONBLOCK);
        }
    }

    free(path);
    if (fuse_device <= 0)
        error(EXIT_FAILURE, 0, _("can't open fuse device"));

    char *mdata = NULL;
    if (asprintf(&mdata, "fd=%i,rootmode=%o,user_id=%i,group_id=%i,"
                 "allow_other,max_read=%lu", fuse_device, args->dir_mode,
                 args->fsuid, args->fsgid,
                 (unsigned long int) (buf_size - 1024)) < 0) abort();

    if (mount(url, mpoint, "fuse", args->mopts, mdata) != 0)
        error(EXIT_FAILURE, errno, _("mounting failed"));

    free(mdata);
}


void
dav_run_msgloop(volatile int *keep_on_running)
{
    dav_register_kernel_interface(&write_dir_entry);

    int unmounting = 0;

    struct timeval tv;
    tv.tv_sec = idle_time;
    tv.tv_usec = 0;
    time_t last_tidy_cache = time(NULL);

    while (1) {

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fuse_device, &fds);
        int ret = select(fuse_device + 1, &fds, NULL, NULL, &tv);
        if (debug)
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "SELECT: %i", ret);

        if (!*keep_on_running && !unmounting) {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), _("unmounting %s"),
                   mountpoint);
            unmounting = 1;
            pid_t pid = fork();
            if (pid == 0) {
                execl("/bin/umount", "umount", "-il", mountpoint, NULL);
                _exit(EXIT_FAILURE);
            }
        }

        if (ret > 0) {
            ssize_t bytes_read = read(fuse_device, buf, buf_size);
            if (bytes_read <= 0) {
                if (debug)
                    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "READ: %s",
                           strerror(errno));
                if (bytes_read == 0 || errno == EINTR || errno == EAGAIN ||
                        errno == ENOENT) {
                    if (time(NULL) < (last_tidy_cache + idle_time)) {
                        tv.tv_sec = last_tidy_cache + idle_time - time(NULL);
                    } else {
                        tv.tv_sec = 0;
                    }
                    continue;
                }
                break;
            }
        } else if (ret == 0) {
            if (dav_tidy_cache() == 0) {
                tv.tv_sec = idle_time;
                last_tidy_cache = time(NULL);
            } else {
                tv.tv_sec = 0;
            }
            continue;
        } else {
            if (errno == EINTR)
                continue;
            break;
        }

        if (ih->nodeid == 1)
              ih->nodeid = root;

        switch (ih->opcode) {
        case FUSE_LOOKUP:
            oh->len = fuse_lookup();
            break;
        case FUSE_FORGET:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                       "FUSE_FORGET: no reply");
            oh->len = 0;
            break;
        case FUSE_GETATTR:
            oh->len = fuse_getattr();
            break;
        case FUSE_SETATTR:
            oh->len = fuse_setattr();
            break;
        case FUSE_READLINK:
            oh->len = not_implemented("FUSE_READLINK:");
            break;
        case FUSE_SYMLINK:
            oh->len = not_implemented("FUSE_SYMLINK:");
            break;
        case FUSE_MKNOD:
            oh->len = fuse_mknod();
            break;
        case FUSE_MKDIR:
            oh->len = fuse_mkdir();
            break;
        case FUSE_UNLINK:
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                                   "FUSE_UNLINK %llu: n=0x%llx",
                                   (unsigned long long) ih->unique,
                                   (unsigned long long) ih->nodeid);
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
                       ih->uid, ih->gid, ih->pid);
            }
            oh->error = dav_remove((dav_node *) ((size_t) ih->nodeid), upcall,
                                   ih->uid);
            if (oh->error)
                oh->error *= -1;
            oh->len = sizeof(struct fuse_out_header);
            break;
        case FUSE_RMDIR:
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                                   "FUSE_RMDIR %llu: n=0x%llx",
                                   (unsigned long long) ih->unique,
                                   (unsigned long long) ih->nodeid);
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
                       ih->uid, ih->gid, ih->pid);
            }
            oh->error = dav_rmdir((dav_node *) ((size_t) ih->nodeid), upcall,
                                  ih->uid);
            if (oh->error)
                oh->error *= -1;
            oh->len = sizeof(struct fuse_out_header);
            break;
        case FUSE_RENAME:
            oh->len = fuse_rename();
            break;
        case FUSE_LINK:
            oh->len = not_implemented("FUSE_LINK:");
            break;
        case FUSE_OPEN:
            oh->len = fuse_open();
            break;
        case FUSE_READ:
            oh->len = fuse_read();
            break;
        case FUSE_WRITE:
            oh->len = fuse_write();
            break;
        case FUSE_STATFS:
            oh->len = fuse_stat();
            break;
        case FUSE_RELEASE:
            oh->len = fuse_release();
            last_tidy_cache = 0;
            break;
        case FUSE_FSYNC:
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                                   "FUSE_FSYNC %llu: n=0x%llx",
                                   (unsigned long long) ih->unique,
                                   (unsigned long long) ih->nodeid);
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
                       ih->uid, ih->gid, ih->pid);
            }
            oh->error = dav_sync((dav_node *) ((size_t) ih->nodeid));
            if (oh->error)
                oh->error *= -1;
            oh->len = sizeof(struct fuse_out_header);
            break;
        case FUSE_SETXATTR:
            oh->len = not_implemented("FUSE_SETXATTR:");
            break;
        case FUSE_GETXATTR:
            oh->len = not_implemented("FUSE_GETXATTR:");
            break;
        case FUSE_LISTXATTR:
            oh->len = not_implemented("FUSE_LISTXATTR:");
            break;
        case FUSE_REMOVEXATTR:
            oh->len = not_implemented("FUSE_REMOVEXATTR:");
            break;
        case FUSE_FLUSH:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                       "FUSE_FLUSH: ignored");
            oh->error = 0;
            oh->len = sizeof(struct fuse_out_header);
            break;
        case FUSE_INIT:
            oh->len = fuse_init();
            break;
        case FUSE_OPENDIR:
            oh->len = fuse_open();
            break;
        case FUSE_READDIR:
            oh->len = fuse_read();
            break;
        case FUSE_RELEASEDIR:
            oh->len = fuse_release();
            break;
        case FUSE_FSYNCDIR:
            oh->len = not_implemented("FUSE_FSYNCDIR:");
            break;
        case FUSE_GETLK:
            oh->len = not_implemented("FUSE_GETLK:");
            break;
        case FUSE_SETLK:
            oh->len = not_implemented("FUSE_SETLK:");
            break;
        case FUSE_SETLKW:
            oh->len = not_implemented("FUSE_SETLKW:");
            break;
        case FUSE_ACCESS:
            oh->len = fuse_access();
            break;
        case FUSE_CREATE:
            oh->len = fuse_create();
            break;
        case FUSE_INTERRUPT:
            oh->len = not_implemented("FUSE_INTERRUPT:");
            break;
        case FUSE_BMAP:
            oh->len = not_implemented("FUSE_BMAP:");
            break;
        case FUSE_DESTROY:
            oh->len = not_implemented("FUSE_DESTROY:");
            break;
        case FUSE_IOCTL:
            oh->len = not_implemented("FUSE_IOCTL:");
            break;
        case FUSE_POLL:
            oh->len = not_implemented("FUSE_POLL:");
            break;
        case FUSE_NOTIFY_REPLY:
            oh->len = not_implemented("FUSE_NOTIFY_REPLY:");
            break;
        case FUSE_BATCH_FORGET:
            oh->len = not_implemented("FUSE_BATCH_FORGET:");
            break;
        case FUSE_FALLOCATE:
            oh->len = not_implemented("FUSE_FALLOCATE:");
            break;
        default:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                       "UNKNOWN FUSE CALL %i", ih->opcode);
            oh->error = -ENOSYS;
            oh->len = sizeof(struct fuse_out_header);
            break;
        }

        if (debug && oh->len)
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "RET: %s",
                   strerror(-oh->error));

        ssize_t n = 0;
        ssize_t w = 0;
        while (n < oh->len && w >= 0) {
            w = write(fuse_device, buf + n, oh->len - n);
            n += w;
        }

        if (time(NULL) < (last_tidy_cache + idle_time)) {
            tv.tv_sec = last_tidy_cache + idle_time - time(NULL);
        } else {
            dav_tidy_cache();
            tv.tv_sec = idle_time;
            last_tidy_cache = time(NULL);
        }

    }
}


/* Private functions */
/*===================*/

/* Functions to handle upcalls fromthe kernel module.
   The cache module only uses data types from the C-library. For file access,
   mode and the like it only uses symbolic constants defined in the C-library.
   So the main porpose of this functions is to translate from kernel specific
   types and constants to types and constants from the C-library, and back.
   All of this functions return the amount of data in buf that is to be
   send to the kernel module. */

static uint32_t
fuse_access(void)
{
    struct fuse_access_in *in = (struct fuse_access_in *) upcall;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_ACCESS %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  m=0x%x",
               in->mask);
    }

    oh->error = dav_access((dav_node *) ((size_t) ih->nodeid), ih->uid,
                           in->mask);

    if (oh->error)
        oh->error *= -1;

    return sizeof(struct fuse_out_header);
}


static uint32_t
fuse_create(void)
{
    struct fuse_create_in *in = (struct fuse_create_in *) upcall;
    char *name = upcall + sizeof(struct fuse_create_in);
    struct create_out *out = (struct create_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_CREATE %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  f=0x%x m=0%o um=0%o",
               in->flags, in->mode, in->umask);
    }

    int created = 0;
    dav_node *node = NULL;
    oh->error = dav_lookup(&node, (dav_node *) ((size_t) ih->nodeid), name,
                           ih->uid);

    if (!oh->error) {
        if (!node) {
            oh->error = -EIO;
            return sizeof(struct fuse_out_header);
        } else if (in->flags & O_EXCL) {
            oh->error = -EEXIST;
            return sizeof(struct fuse_out_header);
        }
    } else if (oh->error == ENOENT) {
        oh->error = dav_create(&node, (dav_node *) ((size_t) ih->nodeid), name,
                               ih->uid, in->mode & DAV_A_MASK);
        if (oh->error || !node) {
            if (!oh->error)
                oh->error = EIO;
            oh->error *= -1;
            return sizeof(struct fuse_out_header);
        }
        created = 1;
    } else {
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    int fd = 0;
    oh->error = dav_open(&fd, node, in->flags & ~(O_EXCL | O_CREAT), ih->uid, 1);

    if (oh->error || !fd) {
        if (created)
            dav_remove((dav_node *) ((size_t) ih->nodeid), name, ih->uid);
        if (!oh->error)
            oh->error = EIO;
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    out->entry.nodeid = (size_t) node;
    out->entry.generation = out->entry.nodeid;
    out->entry.entry_valid = 1;
    out->entry.attr_valid = 1;
    out->entry.entry_valid_nsec = 0;
    out->entry.attr_valid_nsec = 0;
    set_attr(&out->entry.attr, node);

    out->open.open_flags = in->flags & (O_ACCMODE | O_APPEND);
    out->open.fh = fd;
    out->open.padding = 0;

    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  fd %i", fd);

    return sizeof(struct fuse_out_header) + sizeof(struct create_out);
}


static uint32_t
fuse_getattr(void)
{
    struct fuse_getattr_in *in = (struct fuse_getattr_in *) upcall;
    struct fuse_attr_out *out = (struct fuse_attr_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_GETATTR %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  f=0x%x fh=%llu",
               in->getattr_flags, (unsigned long long int) in->fh);
    }

    oh->error = dav_getattr((dav_node *) ((size_t) ih->nodeid), ih->uid);

    if (oh->error) {
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    set_attr(&out->attr, (dav_node *) ((size_t) ih->nodeid));
    out->attr_valid = 1;
    out->attr_valid_nsec = 0;
    out->dummy = 0;

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out);
}


static uint32_t
fuse_init(void)
{
    struct fuse_init_in *in = (struct fuse_init_in *) upcall;
    struct fuse_init_out *out = (struct fuse_init_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_INIT %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  verson=%u.%u",
               in->major, in->minor);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  ra=%u f=0x%x",
               in->max_readahead, in->flags);
    }

    if (in->major < FUSE_KERNEL_VERSION
        || (in->major == FUSE_KERNEL_VERSION && in->minor < FUSE_MIN_MINOR)) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
               "FATAL: Kernel-version too old.");
        oh->error = -ENOSYS;
        return sizeof(struct fuse_out_header);
    }

    if (in->major > FUSE_KERNEL_VERSION) {
        oh->error = 0;
        out->major = FUSE_KERNEL_VERSION;
        return sizeof(struct fuse_out_header);
    }

    dav_node *node;
    oh->error = dav_root(&node, ih->uid);

    if (oh->error || !node) {
        if (!oh->error)
            oh->error = EIO;
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    root = (size_t) node;
    out->major = FUSE_KERNEL_VERSION;
    if (in->minor > FUSE_KERNEL_MINOR_VERSION) {
        out->minor = FUSE_KERNEL_MINOR_VERSION;
    } else {
        out->minor = in->minor;
    }
    out->max_readahead = 0;
    out->flags = 0;
    out->max_background = 0;
    out->congestion_threshold = 0;
    out->max_write = buf_size - 1024;

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_init_out);
}


static uint32_t
fuse_lookup(void)
{
    char * name = upcall;
    struct fuse_entry_out *out = (struct fuse_entry_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_LOOKUP %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  %s", name);
    }

    dav_node *node = NULL;
    oh->error = dav_lookup(&node, (dav_node *) ((size_t) ih->nodeid), name,
                           ih->uid);

    if (oh->error || !node) {
        if (!oh->error)
            oh->error = EIO;
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    out->nodeid = (uint64_t) ((size_t) node);
    out->generation = out->nodeid;
    out->entry_valid = 1;
    out->attr_valid = 1;
    out->entry_valid_nsec = 0;
    out->attr_valid_nsec = 0;
    set_attr(&out->attr, node);

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out);
}


static uint32_t
fuse_mkdir(void)
{
    struct fuse_mkdir_in *in = (struct fuse_mkdir_in *) upcall;
    char *name = upcall + sizeof(struct fuse_mkdir_in);
    struct fuse_entry_out *out = (struct fuse_entry_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_MKDIR %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  m=0%o um=0%o %s",
               in->mode, in->umask, name);
    }

    dav_node *node = NULL;
    oh->error = dav_mkdir(&node, (dav_node *) ((size_t) ih->nodeid), name,
                          ih->uid, in->mode & DAV_A_MASK);

    if (oh->error || !node) {
        if (!oh->error)
            oh->error = EIO;
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    out->nodeid = (size_t) node;
    out->generation = out->nodeid;
    out->entry_valid = 1;
    out->attr_valid = 1;
    out->entry_valid_nsec = 0;
    out->attr_valid_nsec = 0;
    set_attr(&out->attr, node);

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out);
}


static uint32_t
fuse_mknod(void)
{
    struct fuse_mknod_in *in = (struct fuse_mknod_in *) upcall;
    char *name = upcall + sizeof(struct fuse_mknod_in);
    struct fuse_entry_out *out = (struct fuse_entry_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_MKNOD %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  m=0%o r=%u um=0%o",
               in->mode, in->rdev, in->umask);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  %s", name);
    }

    if (!S_ISREG(in->mode)) {
        oh->error = -ENOTSUP;
        return sizeof(struct fuse_out_header);
    }

    dav_node *node = NULL;
    oh->error = dav_create(&node, (dav_node *) ((size_t) ih->nodeid), name,
                           ih->uid, in->mode & DAV_A_MASK);

    if (oh->error || !node) {
        if (!oh->error)
            oh->error = EIO;
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    out->nodeid = (size_t) node;
    out->generation = out->nodeid;
    out->entry_valid = 1;
    out->attr_valid = 1;
    out->entry_valid_nsec = 0;
    out->attr_valid_nsec = 0;
    set_attr(&out->attr, node);

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out);
}


static uint32_t
fuse_open(void)
{
    struct fuse_open_in *in = (struct fuse_open_in *) upcall;
    struct fuse_open_out *out = (struct fuse_open_out *) reply;

    if (debug) {
        if (ih->opcode == FUSE_OPENDIR) {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                   "FUSE_OPENDIR %llu: n=0x%llx",
                   (unsigned long long) ih->unique,
                   (unsigned long long) ih->nodeid);
        } else {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                   "FUSE_OPEN %llu: n=0x%llx",
                   (unsigned long long) ih-> unique,
                   (unsigned long long) ih->nodeid);
        }
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  f=0x%x", in->flags);
    }

    int fd = 0;
    oh->error = dav_open(&fd, (dav_node *) ((size_t) ih->nodeid), in->flags,
                         ih->uid, 0);

    if (oh->error || !fd) {
        if (!oh->error)
            oh->error = EIO;
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    out->open_flags = in->flags & (O_ACCMODE | O_APPEND);
    out->fh = fd;
    out->padding = 0;

    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  fd %i", fd);

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out);
}


static uint32_t
fuse_read(void)
{
    struct fuse_read_in *in = (struct fuse_read_in *) upcall;

    if (debug) {
        if (ih->opcode == FUSE_READDIR) {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                   "FUSE_READDIR %llu: n=0x%llx",
                   (unsigned long long) ih->unique,
                   (unsigned long long) ih->nodeid);
        } else {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                   "FUSE_READ %llu: n=0x%llx",
                   (unsigned long long) ih-> unique,
                   (unsigned long long) ih->nodeid);
        }
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  fh=%llu, off=%llu, sz=%u",
               (unsigned long long) in->fh, (unsigned long long) in->offset,
               in->size);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  rf=0x%x, f=0x%x",
               in->read_flags, in->flags);
    }

    if (in->size > (buf_size - sizeof(struct fuse_out_header))) {
        oh->error = -EINVAL;
        return sizeof(struct fuse_out_header);
    }

    ssize_t len;
    oh->error = dav_read(&len, (dav_node *) ((size_t) ih->nodeid),
                         in->fh, reply, in->size, in->offset);

    if (oh->error)
        oh->error *= -1;

    return len + sizeof(struct fuse_out_header);
}


static uint32_t
fuse_release(void)
{
    struct fuse_release_in *in = (struct fuse_release_in *) upcall;

    if (debug) {
        if (ih->opcode == FUSE_RELEASEDIR) {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                   "FUSE_RELEASEDIR %llu: n=0x%llx",
                   (unsigned long long) ih->unique,
                   (unsigned long long) ih->nodeid);
        } else {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                   "FUSE_RELEASE %llu: n=0x%llx",
                   (unsigned long long) ih->unique,
                   (unsigned long long) ih->nodeid);
        }
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  fh=%llu, f=0x%x, rf=0x%x",
               (unsigned long long) in->fh, in->flags, in->release_flags);
    }

    oh->error = dav_close((dav_node *) ((size_t) ih->nodeid), in->fh,
                          in->flags, ih->pid, 0);

    if (oh->error)
        oh->error *= -1;

    return sizeof(struct fuse_out_header);
}


static uint32_t
fuse_rename(void)
{
    struct fuse_rename_in *in = (struct fuse_rename_in *) upcall;
    char *old = upcall + sizeof(struct fuse_rename_in);
    char *new = old + strlen(old) + 1;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_RENAME %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  %s", old);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n=0x%llx %s",
               (unsigned long long) in->newdir, new);
    }

    if (in->newdir == 1)
        in->newdir = root;
    oh->error = dav_rename((dav_node *) ((size_t) ih->nodeid), old,
                           (dav_node *) ((size_t) in->newdir), new, ih->uid);

    if (oh->error)
        oh->error *= -1;

    return sizeof(struct fuse_out_header);
}


static uint32_t
fuse_setattr(void)
{
    struct fuse_setattr_in *in = (struct fuse_setattr_in *) upcall;
    struct fuse_attr_out *out = (struct fuse_attr_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_SETATTR %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  v=0x%x sz=%llu",
               in->valid, (unsigned long long) in->size);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  at=%llu mt=%llu",
               (unsigned long long) in->atime, (unsigned long long) in->mtime);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  m=0%o uid=%u gid=%u",
               in->mode, in->uid, in->gid);
    }

    oh->error = dav_setattr((dav_node *) ((size_t) ih->nodeid), ih->uid,
                            in->valid & FATTR_MODE, in->mode,
                            in->valid & FATTR_UID, in->uid,
                            in->valid & FATTR_GID, in->gid,
                            in->valid & FATTR_ATIME, in->atime,
                            in->valid & FATTR_MTIME, in->mtime,
                            in->valid & FATTR_SIZE, in->size);

    if (oh->error) {
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    set_attr(&out->attr, (dav_node *) ((size_t) ih->nodeid));
    out->attr_valid = 1;
    out->attr_valid_nsec = 0;
    out->dummy = 0;

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out);
}


static uint32_t
fuse_stat(void)
{
    struct fuse_statfs_out *out = (struct fuse_statfs_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_STATFS %llu: n=0x%llx",
               (unsigned long long) ih->unique,
               (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
    }

    dav_stat *st = dav_statfs();
    if (!st) {
        oh->error = -ENOSYS;
        return sizeof(struct fuse_out_header);
    }

    out->st.blocks = st->blocks;
    out->st.bfree = st->bavail;
    out->st.bavail = st->bavail;
    out->st.bsize = st->bsize;
    out->st.files = st->files;
    out->st.ffree = st->ffree;
    out->st.namelen = st->namelen;
    out->st.frsize = 0;
    out->st.padding = 0;
    int i;
    for (i = 0; i < 6; i++)
        out->st.spare[i] = 0;

    oh->error = 0;
    return sizeof(struct fuse_out_header) + sizeof(struct fuse_statfs_out);
}


static uint32_t
fuse_write(void)
{
    struct fuse_write_in *in = (struct fuse_write_in *) upcall;
    struct fuse_write_out *out = (struct fuse_write_out *) reply;

    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "FUSE_WRITE %llu: n=0x%llx",
                   (unsigned long long) ih->unique,
                   (unsigned long long) ih->nodeid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  u=%u g=%u p=%u",
               ih->uid, ih->gid, ih->pid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  fh=%llu, off=%llu, sz=%u",
               (unsigned long long) in->fh, (unsigned long long) in->offset,
               in->size);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  wf=0x%x, f=0x%x",
               in->write_flags, in->flags);
    }

    if (in->size > (buf_size - sizeof(struct fuse_in_header)
                    - sizeof(struct fuse_write_in))) {
        oh->error = -EINVAL;
        return sizeof(struct fuse_out_header);
    }

    size_t size;
    oh->error = dav_write(&size, (dav_node *) ((size_t) ih->nodeid),
                          in->fh, upcall + sizeof(struct fuse_write_in),
                          in->size, in->offset);

    if (oh->error) {
        oh->error *= -1;
        return sizeof(struct fuse_out_header);
    }

    out->size = size;
    out->padding = 0;

    return sizeof(struct fuse_out_header) + sizeof(struct fuse_write_out);
}

static uint32_t
not_implemented(const char *msg)
{
    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "%s", msg);

    oh->error = -ENOSYS;

    return sizeof(struct fuse_out_header);
}


/* Auxiliary functions. */

/* Writes a struct fuse_dirent to file with file descriptor fd.
   fd     : An open file descriptor to write to.
   off    : The current file size.
   name   : File name; if NULL, the last, empty entry is written.
   return value : New size of the file. -1 in case of an error. */
static off_t
write_dir_entry(int fd, off_t off, const dav_node *node, const char *name)
{
    if (!name)
        return off;

    struct fuse_dirent entry;
    size_t head = offsetof(struct fuse_dirent, name);
    size_t reclen = (head + strlen(name) + sizeof(uint64_t) -1)
                    & ~(sizeof(uint64_t) - 1);

    entry.ino = (((size_t) node) == root) ? 1 : (size_t) node;
    entry.off = off + reclen;
    entry.namelen = strlen(name);
    entry.type = (node->mode & S_IFMT) >> 12;

    size_t size = 0;
    ssize_t ret = 0;
    while (ret >= 0 && size < head) {
        ret = write(fd, (char *) &entry + size, head - size);
        size += ret;
    }
    if (size != head)
        return -1;

    ret = 0;
    while (ret >= 0 && size < (head + entry.namelen)) {
        ret = write(fd, name + size - head, entry.namelen - size + head);
        size += ret;
    }
    if (size != (head + entry.namelen))
        return -1;

    ret = 0;
    while (ret >= 0 && size < reclen) {
        ret = write(fd, "\0", 1);
        size += ret;
    }
    if (size != reclen)
        return -1;

    return off + reclen;
}


static void
set_attr(struct fuse_attr *attr, const dav_node *node)
{
    attr->ino = (((size_t) node) == root) ? 1 : (size_t) node;
    attr->size = node->size;
    attr->blocks = (node->size + 511) / 512;
    attr->atime = node->atime;
    attr->mtime = node->mtime;
    attr->ctime = node->ctime;
    attr->atimensec = 0;
    attr->mtimensec = 0;
    attr->ctimensec = 0;
    attr->mode = node->mode;
    if (S_ISDIR(node->mode)) {
        attr->nlink = node->nref;
    } else {
        attr->nlink = 1;
    }
    attr->uid = node->uid;
    attr->gid = node->gid;
    attr->rdev = 0;
    attr->blksize = buf_size - 1024;
    attr->padding = 0;
}
