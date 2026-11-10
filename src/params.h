
#include <stdio.h>
#include <fuse.h>
#include <dirent.h>

#ifndef _PARAMS_H_
#define _PARAMS_H_

#define FUSE_USE_VERSION 31

struct vfs_state {
    const char *rootdir;        /* backing directory (usually root) */
    const char *mountpoint;     /* where vfs is mounted */
    
    int root_fd;                /* file descriptor for root */
};

struct vfs_dirp {
    DIR *dp;                    /* dir stream pointer */
    struct dirent *entry;       /* pointer to current dir entry */
    off_t offset;
};

#endif