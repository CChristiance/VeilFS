
#define FUSE_USE_VERSION 31

#include <stdio.h>
#include <fuse.h>
#include <dirent.h>
#include <stddef.h>

#ifndef _PARAMS_H_
#define _PARAMS_H_

struct veilfs_state {
    char *rootdir;        /* backing directory (usually root) */
    char *mountpoint;     /* where vfs is mounted */
    char *logpath;
    char *log_rel;
    
    int root_fd;                /* file descriptor for root */
    int log_fd;                 /* file descriptor for current log file */

    int needRecursionCheck;     /* true if mountpoint exists under root, otherwise false */
};

struct veilfs_dirp {
    DIR *dp;                    /* dir stream pointer */
    struct dirent *entry;       /* pointer to current dir entry */
    off_t offset;
};

struct cli_opts {
    int   logging;
    char *logpath;   /* heap-allocated by fuse_opt_parse */
    char *root;      /* heap-allocated by fuse_opt_parse */
};

#define CLI_OPT(tmpl, field, val) { tmpl, offsetof(struct cli_opts, field), val }
static const struct fuse_opt cli_spec[] = {
    CLI_OPT("-l",                  logging, 1),
    CLI_OPT("--logging",           logging, 1),
    CLI_OPT("-lc %s",              logpath, 0),
    CLI_OPT("--logging_custom=%s", logpath, 0),
    CLI_OPT("--logging_custom %s", logpath, 0),
    CLI_OPT("-r %s",               root,    0),
    CLI_OPT("--root=%s",           root,    0),
    CLI_OPT("--root %s",           root,    0),
    FUSE_OPT_END
};

#endif