/*  kernel_interface.h: interface to fuse and coda kernel mocule.
    Copyright (C) 2006, 2007, 2008, 2009 Werner Baumann

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


#ifndef DAV_KERNEL_INTERFACE_H
#define DAV_KERNEL_INTERFACE_H


/* Function prototypes */
/*=====================*/

/* Opens the device for communication with the kernel file system, if possible
   mounts the file system and updates the interface data (dev,
   dav_ran_msgloop_fn, mdata, kernel_fs and buf_size).
   In case of an error it prints an error message and terminates the program.
   url       : Server url.
   mpoint    : Mount point.
   args      : arguments. */
void
dav_init_kernel_interface(const char *url, const char *mpoint,
                          const dav_args *args);


/* Message loop for fuse kernel module with major number 7.
   keep_on_running : Pointer to run flag. */
void
dav_run_msgloop(volatile int *keep_on_running);


#endif /* DAV_KERNEL_INTERFACE_H */
