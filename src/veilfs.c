/* 
    Veil File System
    NCSU -- CSC-501 -- Fall 2026
    CJ Christiance - sachris3@ncsu.edu

    Built upon code from libfuse's passthrough_fh.c, version 3.14.0
*/

#define _GNU_SOURCE

#include "config.h"
#include "params.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <sched.h>
#include <fuse.h>

struct saved_ids { uid_t uid; gid_t gid };

/* ===== HELPER FUNCTIONS ===== */

/* Save uid and gid of daemon; required for each callback modifying the FS
   Omitting save_ids and restore_ids from such a callback creates a critical vulnerability
   when running VeilFS as root. */
static inline const void save_ids(struct saved_ids *s) {
    struct fuse_context *context = fuse_get_context();
    s->uid = setfsuid(context->uid);
    s->gid = setfsgid(context->gid);
}

/* Restore uid and gid of daemon; required for each callback modifying the FS
   Omitting save_ids and restore_ids from such a callback creates a critical vulnerability
   when running VeilFS as root. */
static inline const void restore_ids(struct saved_ids *s) {
    setfsuid(s->uid);
    setfsgid(s->gid);
}

static inline struct veilfs_state *get_state(void) {
    return fuse_get_context()->private_data;
}

static inline struct veilfs_dirp *get_dirp(struct fuse_file_info *fi) {
    return (struct veilfs_dirp *) (uintptr_t) fi->fh;
}

// strip leading slash, unless path is "\"
static inline const char *rel_path(const char *path) {
    return (path[1] == '\0') ? "." : path + 1;
}

static int under_mountpoint(const char *path, const struct veilfs_state *state) {
    size_t n = strlen(state->mountpoint);
    return strncmp(path, state->mountpoint, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

/* Mask: 4 = read, 2 = write, 1 = execute */
static inline const int veilfs_can_access(const struct stat *stbuf, const struct fuse_context *context, int mask) {
    if (context->uid == 0) return 1;    // allow root to always access
    
    mode_t bits;

    // get the three relevant permission bits (8-6 for uid match, 5-3 for gid match, else 2-0)
    if (context->uid == stbuf->st_uid) bits = (stbuf->st_mode >> 6) & 7;
    else if (context->gid == stbuf->st_gid) bits = (stbuf->st_mode >> 3) & 7;
    else bits = stbuf->st_mode & 7;

    return (bits & mask) == mask;
}

static void *veilfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void) conn;
  
    unshare(CLONE_NEWNS);   // prevent mount propagation

    // cfg->use_ino = 0;
    cfg->nullpath_ok = 0;   // path is needed when using fstatat, openat, etc.

    // needed to keep VeilFS in sync with base filesystem (and disable caching)
    cfg->entry_timeout = 0;
    cfg->attr_timeout = 0;
    cfg->negative_timeout = 0;

    return fuse_get_context()->private_data;

    // return NULL;
}

/* ===== END OF HELPER FUNCTIONS ===== */

static int veilfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    LOG_OP(path);
    int res = 0;
    struct veilfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();  // holds uid, gid, pid, etc. for the calling process
    (void) fi;
    
    // hide mounting point to prevent recursion
    if (under_mountpoint(path, state)) return -ENOENT;

    // store file information from the real file location into stbuf
    res = fstatat(state->root_fd, rel_path(path), stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1) return -errno;

    // prevent user from looking up hidden entries by name
    // directories show if they have either read or exec bits, files need read bit
    if (stbuf->st_mode & S_IFDIR) {
        if (!veilfs_can_access(stbuf, context, R_OK) && 
            !veilfs_can_access(stbuf, context, X_OK)) {
            LOG_OP(path);
            return -ENOENT;
        }
    } else {
        if (!veilfs_can_access(stbuf, context, R_OK)) {
            LOG_OP(path);
            return -ENOENT;
        }
    }

    return 0;
}

static int veilfs_readlink(const char *path, char *buf, size_t size) {
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int veilfs_mknod(const char *path, mode_t mode, dev_t rdev) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_mkdir(const char *path, mode_t mode) {
    struct fuse_context *context = fuse_get_context();
    struct saved_ids *s;
    save_ids(&s);
	int res;

	res = mkdir(path, mode);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_rmdir(const char *path) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	res = rmdir(path);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_symlink(const char *from, const char *to) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	res = symlink(from, to);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_rename(const char *from, const char *to, unsigned int flags) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	if (flags)
		return -EINVAL;

	res = rename(from, to);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_link(const char *from, const char *to) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	res = link(from, to);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_unlink(const char *path) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	res = unlink(path);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	if(fi)
		res = fchmod(fi->fh, mode);
	else
		res = chmod(path, mode);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	if (fi)
		res = fchown(fi->fh, uid, gid);
	else
		res = lchown(path, uid, gid);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	if(fi)
		res = ftruncate(fi->fh, size);
	else
		res = truncate(path, size);

	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

static int veilfs_opendir(const char *path, struct fuse_file_info *fi) {
    int res;
    struct veilfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();
    struct veilfs_dirp *d = malloc(sizeof(struct veilfs_dirp));
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
        close(fd);
        return -errno;
    }

    d->offset = 0;
    d->entry = NULL;

    fi->fh = (unsigned long) d;
    return 0;
}

static int veilfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
			struct fuse_file_info *fi, enum fuse_readdir_flags flags) {

    // (void) offset;
    // (void) fi;
    // (void) flags;
    (void) path;
    
    struct veilfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();
    struct veilfs_dirp *d = get_dirp(fi);
    struct stat stbuf;

    int res;
    // check if user has read permissions
    if (fi) res = fstat(dirfd(d->dp), &stbuf);
    else res = fstatat(state->root_fd, rel_path(path), &stbuf, AT_SYMLINK_NOFOLLOW);
    if (!veilfs_can_access(&stbuf, context, R_OK)) {
        LOG_OP(path);
        return -ENOENT;
    }

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
        char full[PATH_MAX];
        int len = snprintf(full, sizeof(full), "%s%s%s", state->rootdir, (state->rootdir[0] == '/' && state->rootdir[1] == '\0') ? "" : "/", de->d_name);
        if (len < 0 || (size_t)len >= sizeof(full)) continue;
            if (under_mountpoint(full, state)) continue; // don't list out mount point
            if (fstatat(dirfd(d->dp), de->d_name, &entst, AT_SYMLINK_NOFOLLOW) == -1) continue;
            if (!veilfs_can_access(&entst, context, R_OK)) continue;
        }
        
        filler(buf, de->d_name, NULL, 0, 0);
    }

    return 0;
}

static int veilfs_releasedir(const char *path, struct fuse_file_info *fi) {
    (void) path;
    struct veilfs_dirp *d = get_dirp(fi);
    closedir(d->dp);
    free(d);
    return 0;
}

static int veilfs_open(const char *path, struct fuse_file_info *fi) {
    struct veilfs_state *state = get_state();
    int fd;

    // fd = open(path, fi->flags);
    fd = openat(state->root_fd, rel_path(path), fi->flags | O_CLOEXEC);
    if (fd == -1) return -errno;

    fi->fh = fd;
    return 0;
}

static int veilfs_read(const char *path, char *buf, size_t size, off_t offset, 
            struct fuse_file_info *fi) {
    (void) path;

    // struct veilfs_state *state = get_state();
    int res = 0;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1) return -errno;

    return res;
}

static int veilfs_write(const char *path, const char *buf, size_t size, off_t offset, 
            struct fuse_file_info *fi) {
    struct saved_ids *s;
    save_ids(&s);

	int res;

	(void) path;
	res = pwrite(fi->fh, buf, size, offset);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return res;
}

static int veilfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct saved_ids *s;
    save_ids(&s);
	int fd;

	fd = open(path, fi->flags, mode);
	if (fd == -1) {
        restore_ids(&s);
		return -errno;
    }

	fi->fh = fd;
    restore_ids(&s);
	return 0;
}

static int veilfs_statfs(const char *path, struct statvfs *stbuf) {
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int veilfs_release(const char *path, struct fuse_file_info *fi) {
    (void) path;
    // (void) fi;

    // struct veilfs_state *state = get_state();
    // close(path);

    close(fi->fh);

    return 0;
}

// TODO
static int veilfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    struct saved_ids *s;
    save_ids(&s);
	int res;
	(void) path;

#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif
		res = fsync(fi->fh);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}

// TOOD
#ifdef HAVE_UTIMENSAT
static int veilfs_utimens(const char *path, const struct timespec ts[2], 
            struct fuse_file_info *fi) {
    struct saved_ids *s;
    save_ids(&s);
	int res;

	/* don't use utime/utimes since they follow symlinks */
	if (fi)
		res = futimens(fi->fh, ts);
	else
		res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
        restore_ids(&s);
		return -errno;
    }

    restore_ids(&s);
	return 0;
}
#endif

static void veilfs_usage() {
    // fprintf(stderr, "Usage: veilfs <rootDir> <mountPoint>\n");
    fprintf(stderr, "Usage: veilfs [mountPoint]\n");
    abort();

    // fprintf(stderr, "Usage: veilfs [rootDir] [mountPoint]\n\
    //         Optional arguments:\n\
    //         \t-l, --logging         requires root, log certain behavior to /var/log/veilfs/veilfs.log\n\
    //         \t");

    // abort();
}

// clean up filesystem on exit
static void veilfs_destroy() {

}

const static struct fuse_operations veilfs_oper = {
    .init = veilfs_init,
    .getattr = veilfs_getattr,
    .readlink = veilfs_readlink,
    .mknod = veilfs_mknod,
    .mkdir = veilfs_mkdir,
    .rmdir = veilfs_rmdir,
    .symlink = veilfs_symlink,
    .rename = veilfs_rename,
    .link = veilfs_link,
    .unlink = veilfs_unlink,
    .chmod = veilfs_chmod,
    .chown = veilfs_chown,
    .truncate = veilfs_truncate,
    .opendir = veilfs_opendir,
    .readdir = veilfs_readdir,
    .releasedir = veilfs_releasedir,
    .open = veilfs_open,
    .read = veilfs_read,
    .write = veilfs_write,
    .create = veilfs_create,
    .statfs = veilfs_statfs,
    .release = veilfs_release,
    .fsync = veilfs_fsync,
    .destroy = veilfs_destroy,
#ifdef HAVE_UTIMENSAT
    .utimens = veilfs_utimens,
#endif
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
    int fd = -1;
    if ((getuid() != 0) && (geteuid() != 0)) {
        fprintf(stderr, "VeilFS daemon is running without root privileges, \
                         certain aspects will not work / are disabled.\n");
    }

    /* by passing veilfs_state state into fuse_main, information 
       can be shared across filesystem ops */
    struct veilfs_state *state = calloc(1, sizeof(*state));
    state->logpath = LOG_PATH; // TODO: add option for custom logging directories

    struct stat st;
    if (mkdir(state->logpath, 0700) != 0 &&
        (errno != EEXIST || stat(state->logpath, &st) != 0 ||
        !S_ISDIR(st.st_mode) || access(state->logpath, W_OK | X_OK) != 0)) {
        perror("Log directory");
        fprintf(stderr, "Logging disabled: could not create/access %s\n", state->logpath);
    } else {
        char filepath[PATH_MAX];
        int len = snprintf(filepath, sizeof(filepath), "%s/veilfs.log", state->logpath);
        if (len > 0 && (size_t)len < sizeof(filepath)) {
            fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (fd == -1) perror("open log");
        }
    }

    // sanity check for correct args
    // if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
    //     veilfs_usage();

    state->log_fd = fd;
    state->root_fd = open("/", O_PATH | O_DIRECTORY);   // FUSE daemon will serve from root
    state->rootdir = "/";
    state->mountpoint = realpath(argv[argc-1], NULL);
    fprintf(stderr, "mountpoint: %s\n", state->mountpoint);

    // TODO: as an option: user has to cd into the mountpoint, make it so they start there
    // TODO: launcher to prevent user from cd-ing out of the mountpoint

    // umask(0);

    // insert -oallow_other, default_permissions into args to allow kernel to also enforce access
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    for (int i = 0; i < argc; i++) {
        if (fuse_opt_add_arg(&args, argv[i]) == -1) return 1;
    }
    if (fuse_opt_insert_arg(&args, 1, "-oallow_other,default_permissions") == -1) {
        fprintf(stderr, "Failed to insert args into fuse_args struct, terminating...\n");
        fuse_opt_free_args(&args);
        return 1;
    }

    fprintf(stderr, "Using FUSE library version: %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

    fprintf(stderr, "Calling fuse main...\n");
    int ret = fuse_main(args.argc, args.argv, &veilfs_oper, state);

    // release heap mem owned by args
    fuse_opt_free_args(&args);
    return ret;
    // return fuse_main(argc, argv, &veilfs_oper, state);
}