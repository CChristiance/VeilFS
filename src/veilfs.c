/* 
    Veil File System
    NCSU -- CSC-501 -- Fall 2026
    CJ Christiance - sachris3@ncsu.edu

    Built upon code from libfuse's passthrough_fh.c, version 3.14.0
*/

#define _GNU_SOURCE

#include "config.h"
#include "params.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sched.h>
#include <fuse.h>

static inline struct vfs_state *get_state(void) {
    return fuse_get_context()->private_data;
}

static inline struct vfs_dirp *get_dirp(struct fuse_file_info *fi) {
    return (struct vfs_dirp *) (uintptr_t) fi->fh;
}

static inline const char *rel_path(const char *path) {
    return (path[1] == '\0') ? "." : path + 1;
}

/* Mask: 4 = read, 2 = write, 1 = execute */
static inline const char vfs_can_access(const struct stat *stbuf, const struct fuse_context *context, int mask) {
    if (context->uid == 0) return 1;    // allow root to always access
    
    mode_t bits;

    // get the three relevant permission bits (8-6 for uid match, 5-3 for gid match, else 2-0)
    if (context->uid == stbuf->st_uid) bits = (stbuf->st_mode >> 6) & 7;
    else if (context->gid == stbuf->st_gid) (stbuf->st_mode >> 3) & 7;
    else bits = stbuf->st_mode & 7;

    return (bits & mask) == mask;
}

static void *vfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void) conn;
  
    unshare(CLONE_NEWNS);   // prevent mount propagation

    cfg->use_ino = 1;
    cfg->nullpath_ok = 0;   // path is needed when using fstatat, openat, etc.
    // cfg->entry_timeout = 0;
    // cfg->attr_timeout = 0;
    // cfg->negative_timeout = 0;

    return fuse_get_context()->private_data;

    // return NULL;
}

// TODO: hide mounting point to prevent recursion
// TODO: files still show even when required read perms are absent
static int vfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    // (void) fi;
    int res = 0;
    struct vfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();  // holds uid, gid, pid, etc. for the calling process

    // (void) path;
    (void) fi;

    // if (fi) res = fstat(fi->fh, stbuf);
    // else res = lstat(path, stbuf);
    
    // store file information from the real file location into stbuf
    res = fstatat(state->root_fd, rel_path(path), stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1) return -errno;

    // prevent user from looking up hidden entries by name
    if (!vfs_can_access(stbuf, context, R_OK)) return -ENOENT;

    // if (fstatat(state->root_fd, rel_path(path), stbuf, AT_SYMLINK_NOFOLLOW)) return -errno;

    return 0;
}

static int vfs_opendir(const char *path, struct fuse_file_info *fi) {
    int res;
    struct vfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();
    struct vfs_dirp *d = malloc(sizeof(struct vfs_dirp));
    if (d == NULL) return -ENOMEM;

    // get file descriptor
    int fd = openat(state->root_fd, rel_path(path), fi->flags | O_CLOEXEC);
    if (fd == -1) {
        free(d);
        return -errno;
    }

    // convert the fd into a DIR stream
    d->dp = fdopendir(fd);
    // d->dp = opendir(path);
    if (d->dp == NULL) {
        free(d);
        return -errno;
    }

    d->offset = 0;
    d->entry = NULL;

    fi->fh = (unsigned long) d;
    return 0;
}

static int vfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
			struct fuse_file_info *fi, enum fuse_readdir_flags flags) {

    // (void) offset;
    // (void) fi;
    // (void) flags;
    (void) path;
    
    struct vfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();
    struct vfs_dirp *d = get_dirp(fi);
    struct stat stbuf;
    // struct stat *stbuf = &st;

    int res;
    // check if user has read permissions
    // if (fi) res = fstat(fi->fh, stbuf);
    // point stbuf and stat at the real storage and fd
    if (fi) res = fstat(dirfd(d->dp), &stbuf);
    else res = fstatat(state->root_fd, rel_path(path), &stbuf, AT_SYMLINK_NOFOLLOW);
    if (!vfs_can_access(&stbuf, context, R_OK)) return -ENOENT;
    // if (res == -1) return -errno;
    
    // if (context->uid == stbuf->st_uid) {
    //     if (!(stbuf->st_mode & S_IRUSR)) return -ENOENT;
    // } else if (context->gid == stbuf->st_gid) {
    //     if (!(stbuf->st_mode & S_IRGRP)) return -ENOENT;
    // } else {
    //     if (!(stbuf->st_mode & S_IROTH)) return -ENOENT;
    // }
    // end of perms check

    // int fd = openat(state->root_fd, rel_path(path), O_RDONLY | O_DIRECTORY);
    // if (fd == -1) return -errno;

    // DIR *dp = fdopendir(fd);
    // if (!dp) {
    //     close(fd);
    //     return -errno;
    // }

    rewinddir(d->dp);

    struct dirent *de;
    while ((de = readdir(d->dp)) != NULL) {
        struct stat entst;    // stat for each entry

        // never filter out "." and ".."
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            if (fstatat(dirfd(d->dp), de->d_name, &entst, AT_SYMLINK_NOFOLLOW) == -1) continue;
            if (!vfs_can_access(&entst, context, R_OK)) continue;
        }
        
        filler(buf, de->d_name, NULL, 0, 0);
    }

    return 0;

//     if (offset != d->offset) {
// #ifndef __FREEBSD__
//         seekdir(d->dp, offset);
// #else
//         seekdir(d->dp, offset-1);
// #endif
//         d->entry = NULL;
//         d->offset = offset;
//     }
//     while(1) {
//         // struct stat st;
//         off_t nextoff;
//         enum fuse_fill_dir_flags fill_flags = 0;

//         if (!d->entry) {
//             d->entry = readdir(d->dp);
//             if (!d->entry) break;
//         }
// #ifdef HAVE_FSTATAT
//         if (flags & FUSE_READDIR_PLUS) {
//             int res;

//             res = fstatat(dirfd(d->dp), d->entry->d_name, &st, AT_SYMLINK_NOFOLLOW);

//             if (res != -1) fill_flags |= FUSE_FILL_DIR_PLUS;
//         }
// #endif
//         if(!(fill_flags & FUSE_FILL_DIR_PLUS)) {
//             memset(&st, 0, sizeof(st));
//             st.st_ino = d->entry->d_ino;
//             st.st_mode = d->entry->d_type << 12;
//         }
//         nextoff = telldir(d->dp);
// #ifdef __FREEBSD__
//         nextoff++;
// #endif
//         if (filler(buf, d->entry->d_name, &st, nextoff, fill_flags)) break;
        
//         d->entry = NULL;
//         d->offset = nextoff;
//     }

    return 0;
}

static int vfs_releasedir(const char *path, struct fuse_file_info *fi) {
    (void) path;
    struct vfs_dirp *d = get_dirp(fi);
    closedir(d->dp);
    free(d);
    return 0;
}

static int vfs_open(const char *path, struct fuse_file_info *fi) {
    struct vfs_state *state = get_state();
    int fd;

    // fd = open(path, fi->flags);
    fd = openat(state->root_fd, rel_path(path), fi->flags | O_CLOEXEC);
    if (fd == -1) return -errno;

    fi->fh = fd;
    return 0;
}

static int vfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void) path;

    // struct vfs_state *state = get_state();
    int res = 0;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1) return -errno;

    return res;
}

static int vfs_release(const char *path, struct fuse_file_info *fi) {
    (void) path;
    // (void) fi;

    // struct vfs_state *state = get_state();
    // close(path);

    close(fi->fh);

    return 0;
}

static void vfs_usage() {
    // fprintf(stderr, "Usage: veilfs <rootDir> <mountPoint>\n");
    fprintf(stderr, "Usage: veilfs [mountPoint]\n");
    abort();
}

const static struct fuse_operations vfs_oper = {
    .init = vfs_init,
    .getattr = vfs_getattr,
    .opendir = vfs_opendir,
    .readdir = vfs_readdir,
    .releasedir = vfs_releasedir,
    .open = vfs_open,
    .read = vfs_read,
    .release = vfs_release,
};

// TODO: write test cases
// TODO: track # of files exposed to unprivileged users during tests
    // Desired result: 0
// TODO: track # of instances EACCES for privileged files is returned instead of ENOENT
    // Desired result: 0
// TODO: track # of times the tests bypassed the FUSE FS
    // Desired result: 0
// TODO: track throughput (wall-clock time and ops per second)
    // Desired result: At most 2x default wall-time and at least 50% of default ops per second
int main(int argc, char *argv[]) {
    /* in order for sudo to work, the daemon must have root privileges */
    /* allow the program to run, but send an alert */
    if ((getuid() != 0) && (geteuid() != 0)) {
        fprintf(stderr, "FUSE is running without root privileges\n");
    }

    /* by passing vfs_state state into fuse_main, information 
       can be shared across filesystem ops */
    struct vfs_state *state = calloc(1, sizeof(*state));
    // sanity check for correct args
    // if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
    //     vfs_usage();

    // TODO: mount on system start instead of requiring manual start
    state->root_fd = open("/", O_PATH | O_DIRECTORY);   // FUSE daemon will serve from root

    // TODO: user has to cd into the mountpoint, make it so they start there
    // TODO: user can cd out of the mountpoint
    // TODO: when at mountpoint, the user sees their directory as the mountpoint instead of root

    umask(0);

    // insert -oallow_other, default_permissions into args to allow kernel to also enforce access
    // struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    // for (int i = 0; i < argc; i++) {
    //     if (fuse_opt_add_arg(&args, argv[i]) == -1) return 1;
    // }
    // if (fuse_opt_insert_arg(&args, 1, "-oallow_other,default_permissions") == -1) {
    //     fprintf(stderr, "Failed to insert args into fuse_args struct, terminating...\n");
    //     fuse_opt_free_args(&args);
    //     return 1;
    // }

    fprintf(stderr, "Using FUSE library version: %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

    fprintf(stderr, "Calling fuse main...\n");
    // int ret = fuse_main(args.argc, args.argv, &vfs_oper, state);

    // release heap mem owned by args
    // fuse_opt_free_args(&args);
    // return ret;
    return fuse_main(argc, argv, &vfs_oper, state);
}