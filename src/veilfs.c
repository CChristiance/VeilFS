/* 
    Veil File System
    NCSU -- CSC-501 -- Fall 2026
    CJ Christiance - sachris3@ncsu.edu

    Built upon code from libfuse's passthrough_fh.c, version 3.14.0
*/

#include "config.h"
#include "params.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <fuse.h>

static struct vfs_state *get_state(void) {
    return fuse_get_context()->private_data;
}

static inline struct vfs_dirp *get_dirp(struct fuse_file_info *fi) {
    return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

static const char *rel_path(const char *path) {
    return (path[1] == '\0') ? "." : path + 1;
}

static void *vfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void) conn;

    cfg->use_ino = 1;
    cfg->nullpath_ok = 1;
    cfg->entry_timeout = 0;
    cfg->attr_timeout = 0;
    cfg->negative_timeout = 0;

    return NULL;
}

// TODO: hide mounting point to prevent recursion
static int vfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    // (void) fi;
    int res = 0;
    struct vfs_state *state = get_state();

    (void) path;

    if (fi) res = fstat(fi->fh, stbuf);
    else res = lstat(path, stbuf);

    if (res == -1) return -errno;

    // if (fstatat(state->root_fd, rel_path(path), stbuf, AT_SYMLINK_NOFOLLOW)) return -errno;

    return 0;
}

static int vfs_opendir(const char *path, struct fuse_file_info *fi) {
    int res;
    struct vfs_dirp *d = malloc(sizeof(struct vfs_dirp));
    if (d == NULL) return -ENOMEM;

    d->dp = opendir(path);
    if (d->dp == NULL) {
        res = -errno;
        free(d);
        return res;
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
    
    struct vfs_dirp *d = get_dirp(fi);
    struct vfs_state *state = get_state();

    if (offset != d->offset) {
#ifndef __FREEBSD__
        seekdir(d->dp, offset);
#else
        seekdir(d->dp, offset-1);
#endif
        d->entry = NULL;
        d->offset = offset;
    }
    while(1) {
        struct stat st;
        off_t nextoff;
        enum fuse_fill_dir_flags fill_flags = 0;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry) break;
        }
#ifdef HAVE_FSTATAT
        if (flags & FUSE_READDIR_PLUS) {
            int res;

            res = fstatat(dirfd(d->dp), d->entry->d_name, &st, AT_SYMLINK_NOFOLLOW);

            if (res != -1) fill_flags |= FUSE_FILL_DIR_PLUS;
        }
#endif
        if(!(fill_flags & FUSE_FILL_DIR_PLUS)) {
            memset(&st, 0, sizeof(st));
            st.st_ino = d->entry->d_ino;
            st.st_mode = d->entry->d_type << 12;
        }
        nextoff = telldir(d->dp);
#ifdef __FREEBSD__
        nextoff++;
#endif
        if (filler(buf, d->entry->d_name, &st, nextoff, fill_flags)) break;
        
        d->entry = NULL;
        d->offset = nextoff;
    }

    // int fd = openat(state->root_fd, rel_path(path), O_RDONLY | O_DIRECTORY);

    return 0;
}

static int vfs_releasedir(const char *path, struct fuse_file_info *fi) {
    struct vfs_dirp *d = get_dirp(fi);
    (void) path;
    closedir(d->dp);
    free(d);
    return 0;
}

static int vfs_open(const char *path, struct fuse_file_info *fi) {
    struct vfs_state *state = get_state();
    int fd;

    fd = open(path, fi->flags);
    if (fd == -1) return -errno;

    fi->fh = fd;
    return 0;
}

static int vfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void) path;

    struct vfs_state *state = get_state();
    int res = 0;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1) return -errno;

    return res;
}

static int vfs_release(const char *path, struct fuse_file_info *fi) {
    (void) path;

    struct vfs_state *state = get_state();

    close(fi->fh);

    return 0;
}

static void vfs_usage() {
    fprintf(stderr, "Usage: veilfs <rootDir> <mountPoint>\n");
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

int main(int argc, char *argv[]) {
    struct vfs_state *state = calloc(1, sizeof(*state));
    // sanity check for correct args
    // if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
    //     vfs_usage();
    // state->rootpath = argv[1];  /* steal backing dir from args so FUSE only sees mountpoint and options */
    // argv[1] = argv[0];
    // argv++;
    // argc--;

    // state->root_fd = open(state->rootpath, O_RDONLY | O_DIRECTORY);
    umask(0);

    fprintf(stderr, "Using FUSE library version: %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

    // TODO: mount on system start instead of requiring a call
    // vfs_data->rootdir = realpath(argv[argc-2], NULL);
    // argv[argc-2] = argv[argc-1];
    // argv[argc-1] = NULL;
    // argc--;

    fprintf(stderr, "Calling fuse main...\n");
    // return fuse_main(argc, argv, &vfs_oper, state);
    return fuse_main(argc, argv, &vfs_oper, NULL);
}