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
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <sched.h>
#include <fuse.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

struct saved_ids { uid_t uid; gid_t gid; };

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

static int is_mountpoint_path(const char *path, const struct veilfs_state *state) {
    if (!state->needRecursionCheck) return 0;

    char full[PATH_MAX];
    int len;
    if (state->rootdir[0] == '/' && state->rootdir[1] == '\0')
        len = snprintf(full, sizeof(full), "%s", path);
    else
        len = snprintf(full, sizeof(full), "%s%s", state->rootdir, path);
    if (len < 0 || (size_t)len >= sizeof(full)) return 0;

    return under_mountpoint(full, state);
}

static inline void strip_metadata(const struct fuse_context *context, struct stat *stbuf) {
    stbuf->st_size = 0;
    stbuf->st_nlink = 0;
    if (context->uid != stbuf->st_uid) stbuf->st_uid = -1;
    if (context->gid != stbuf->st_gid) stbuf->st_gid = -1;
    stbuf->st_size = 0;
    stbuf->st_blocks = 0;

# ifdef __USE_XOPEN2K8
    stbuf->st_atim.tv_sec = 0;
    stbuf->st_atim.tv_nsec = 0;
    stbuf->st_mtim.tv_sec = 0;
    stbuf->st_mtim.tv_nsec = 0;
    stbuf->st_ctim.tv_sec = 0;
    stbuf->st_ctim.tv_nsec = 0;
#else
    stbuf->st_atime = 0;
    stbuf->st_atimensec = 0;
    stbuf->st_mtime = 0;
    stbuf->st_mtimensec = 0;
    stbuf->st_ctime = 0;
    stbuf->st_ctimensec = 0;
# endif
}

#define GROUP_CACHE_TTL 5   /* seconds before re-reading the group database */

/* Check if the caller belongs to `gid`, as primary or supplementary group.
   Uses a small per-thread cache so getattr/readdir don't hit the group
   database on every call. */
static int caller_in_group(const struct fuse_context *context, gid_t gid) {
    if (context->gid == gid) return 1;

    static __thread uid_t   c_uid;
    static __thread time_t  c_time;
    static __thread gid_t  *c_groups;
    static __thread int     c_n;
    static __thread int     c_valid;

    time_t now = time(NULL);
    if (!c_valid || c_uid != context->uid || now - c_time >= GROUP_CACHE_TTL) {
        free(c_groups);
        c_groups = NULL;
        c_n = 0;

        struct passwd pw, *res = NULL;
        char buf[4096];
        if (getpwuid_r(context->uid, &pw, buf, sizeof(buf), &res) == 0 && res) {
            int n = 32;
            gid_t *g = malloc(n * sizeof(*g));
            while (g) {
                int cap = n;
                int r = getgrouplist(res->pw_name, res->pw_gid, g, &cap);
                if (r != -1) { c_n = r; break; }
                n = (cap > n) ? cap : n * 2;
                gid_t *t = realloc(g, n * sizeof(*g));
                if (!t) { free(g); g = NULL; break; }
                g = t;
            }
            c_groups = g;
        }
        c_uid = context->uid;
        c_time = now;
        c_valid = 1;
    }

    for (int i = 0; i < c_n; i++)
        if (c_groups[i] == gid) return 1;
    return 0;
}

/* Mask: 4 = read, 2 = write, 1 = execute */
static inline const int veilfs_can_access(struct stat *stbuf, const struct fuse_context *context, int mask) {
    if (context->uid == 0) return 1;    // allow root to always access

    mode_t bits;

    // owner class, else group class (primary or supplementary), else other
    if (context->uid == stbuf->st_uid) bits = (stbuf->st_mode >> 6) & 7;
    else if (caller_in_group(context, stbuf->st_gid)) bits = (stbuf->st_mode >> 3) & 7;
    else bits = stbuf->st_mode & 7;

    // no read permissions, so strip metadata
    if (!(bits & R_OK)) strip_metadata(context, stbuf);

    return (bits & mask);
}

static void *veilfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void) conn;
  
    unshare(CLONE_NEWNS);   // prevent mount propagation

    // cfg->use_ino = 0;
    cfg->nullpath_ok = 0;   // path is needed when using fstatat, openat, etc.

    // needed to keep VeilFS in sync with base filesystem (and disable caching)
    cfg->entry_timeout    = 0;
    cfg->attr_timeout     = 0;
    cfg->negative_timeout = 0;

    return fuse_get_context()->private_data;
}

/* ===== END OF HELPER FUNCTIONS ===== */

static int veilfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    int res = 0;
    struct veilfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();  // holds uid, gid, pid, etc. for the calling process
    (void) fi;
    
    // hide mounting point to prevent recursion
    // if (state->needRecursionCheck && under_mountpoint(path, state)) return -ENOENT;
    if (is_mountpoint_path(path, state)) return -ENOENT;

    // store file information from the real file location into stbuf
    res = fstatat(state->root_fd, rel_path(path), stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1) return -errno;

    // prevent user from looking up hidden entries by name
    // directories show if they have either read or exec bits, files need read bit
    if (stbuf->st_mode & S_IFDIR) {
        if (!veilfs_can_access(stbuf, context, R_OK | W_OK | X_OK)) {
            if (state->log_fd >= 0) LOG_OP(path);
            return -ENOENT;
        }
    } else {
        if (!veilfs_can_access(stbuf, context, R_OK | W_OK | X_OK)) {
            if (state->log_fd >= 0) LOG_OP(path);
            return -ENOENT;
        }
    }

    return 0;
}

static int veilfs_readlink(const char *path, char *buf, size_t size) {
    struct veilfs_state *state = get_state();
    ssize_t res = readlinkat(state->root_fd, rel_path(path), buf, size - 1);
    if (res == -1) return -errno;
    buf[res] = '\0';
    return 0;
}

static int veilfs_mknod(const char *path, mode_t mode, dev_t rdev) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res;

    if (S_ISFIFO(mode))
        res = mkfifoat(state->root_fd, rel_path(path), mode);
    else
        res = mknodat(state->root_fd, rel_path(path), mode, rdev);

    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_mkdir(const char *path, mode_t mode) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res = mkdirat(state->root_fd, rel_path(path), mode);
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}


static int veilfs_rmdir(const char *path) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res = unlinkat(state->root_fd, rel_path(path), AT_REMOVEDIR);
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_symlink(const char *from, const char *to) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res = symlinkat(from, state->root_fd, rel_path(to));
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_rename(const char *from, const char *to, unsigned int flags) {
    struct veilfs_state *state = get_state();
    if (flags) return -EINVAL;
    struct saved_ids s;
    save_ids(&s);
    int res = renameat(state->root_fd, rel_path(from), state->root_fd, rel_path(to));
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_link(const char *from, const char *to) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res = linkat(state->root_fd, rel_path(from), state->root_fd, rel_path(to), 0);
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_unlink(const char *path) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res = unlinkat(state->root_fd, rel_path(path), 0);
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res;
    if (fi)
        res = fchmod(fi->fh, mode);
    else
        res = fchmodat(state->root_fd, rel_path(path), mode, 0);
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res;
    if (fi)
        res = fchown(fi->fh, uid, gid);
    else
        res = fchownat(state->root_fd, rel_path(path), uid, gid, AT_SYMLINK_NOFOLLOW);
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res;
    if (fi) {
        res = ftruncate(fi->fh, size);
    } else {
        int fd = openat(state->root_fd, rel_path(path), O_WRONLY | O_CLOEXEC);
        if (fd == -1) {
            res = -1;
        } else {
            res = ftruncate(fd, size);
            int saved = errno;
            close(fd);
            errno = saved;
        }
    }
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}

static int veilfs_opendir(const char *path, struct fuse_file_info *fi) {
    int res;
    struct veilfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();
    struct veilfs_dirp *d = malloc(sizeof(struct veilfs_dirp));
    struct stat stbuf;
    if (d == NULL) return -ENOMEM;

    if (is_mountpoint_path(path, state)) return -ENOENT;

    // get file descriptor
    int fd = openat(state->root_fd, rel_path(path), fi->flags | O_CLOEXEC);
    if (fd == -1) {
        free(d);
        return -errno;
    }

    // convert the fd into a DIR stream
    d->dp = fdopendir(fd);
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

    (void) path;
    
    struct veilfs_state *state = get_state();
    struct fuse_context *context = fuse_get_context();
    struct veilfs_dirp *d = get_dirp(fi);
    struct stat stbuf;

    if (is_mountpoint_path(path, state)) return -ENOENT;

    int res;
    // check if user has read permissions
    if (fi) res = fstat(dirfd(d->dp), &stbuf);
    else res = fstatat(state->root_fd, rel_path(path), &stbuf, AT_SYMLINK_NOFOLLOW);
    if (!veilfs_can_access(&stbuf, context, R_OK)) {
        if (state->log_fd >= 0) LOG_OP(path);
        return -ENOENT;
    }

    rewinddir(d->dp);

    struct dirent *de;
    while ((de = readdir(d->dp)) != NULL) {
        struct stat entst;    // stat for each entry

        // never filter out "." and ".."
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            char child[PATH_MAX];
            int len = snprintf(child, sizeof(child), "%s%s%s",
                            path, (path[0] == '/' && path[1] == '\0') ? "" : "/", de->d_name);
            if (len < 0 || (size_t)len >= sizeof(child)) continue;
            if (is_mountpoint_path(child, state)) continue;
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
    fd = openat(state->root_fd, rel_path(path), fi->flags | O_CLOEXEC);
    if (fd == -1) return -errno;

    fi->fh = fd;
    return 0;
}

static int veilfs_read(const char *path, char *buf, size_t size, off_t offset, 
            struct fuse_file_info *fi) {
    (void) path;

    int res = 0;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1) return -errno;

    return res;
}

static int veilfs_write(const char *path, const char *buf, size_t size, off_t offset, 
            struct fuse_file_info *fi) {
    struct saved_ids s;
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
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int fd = openat(state->root_fd, rel_path(path), fi->flags | O_CLOEXEC, mode);
    int err = errno;
    restore_ids(&s);
    if (fd == -1) return -err;
    fi->fh = fd;
    return 0;
}

static int veilfs_statfs(const char *path, struct statvfs *stbuf) {
    struct veilfs_state *state = get_state();
    (void) path;
    if (fstatvfs(state->root_fd, stbuf) == -1) return -errno;
    return 0;
}

static int veilfs_release(const char *path, struct fuse_file_info *fi) {
    (void) path;

    close(fi->fh);

    return 0;
}

static int veilfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    struct saved_ids s;
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

#ifdef HAVE_UTIMENSAT
static int veilfs_utimens(const char *path, const struct timespec ts[2],
                          struct fuse_file_info *fi) {
    struct veilfs_state *state = get_state();
    struct saved_ids s;
    save_ids(&s);
    int res;
    if (fi)
        res = futimens(fi->fh, ts);
    else
        res = utimensat(state->root_fd, rel_path(path), ts, AT_SYMLINK_NOFOLLOW);
    int err = errno;
    restore_ids(&s);
    return res == -1 ? -err : 0;
}
#endif

// clean up filesystem on exit
static void veilfs_destroy() {
    struct fuse_context *context = fuse_get_context();
    struct veilfs_state *state = get_state();

    close(state->log_fd);
    close(state->root_fd);
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

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct cli_opts opts = {0};
    struct veilfs_state *state = NULL;
    int ret = 1;

    // prevent daemon's mask from stripping perms
    umask(0);

    /* in order for sudo to work, the daemon must have root privileges */
    /* allow the program to run, but send an alert */
    int fd = -1;
    if (geteuid() != 0) {
        fprintf(stderr, "VeilFS daemon requires root privileges.\n");
        goto out;
    }

    /* strips options from args to handle here */
    if (fuse_opt_parse(&args, &opts, cli_spec, NULL) == -1) goto out;

    /* mountpoint must be the last remaining argument */
    if (args.argc < 2 || args.argv[args.argc - 1][0] == '-') {
        fprintf(stderr, "Usage: %s [-l | -lc PATH] [-r PATH] [FUSE options] MOUNTPOINT\n",
                argv[0]);
        goto out;
    }

    /* state is shared with all filesystem ops via fuse_main's private_data */
    state = calloc(1, sizeof(*state));
    if (!state) { perror("calloc"); goto out; }
    state->log_fd  = -1;
    state->root_fd = -1;

    if (opts.logpath) opts.logging = 1;    /* -lc implies logging */
    state->logpath = opts.logpath ? opts.logpath : LOG_PATH;
    if (opts.logging) {
        state->log_fd = open_log(state->logpath);
        if (state->log_fd == -1)
            fprintf(stderr, "Logging disabled: could not use %s\n", state->logpath);
    }

        state->rootdir = realpath(opts.root ? opts.root : "/", NULL);
    if (!state->rootdir) {
        fprintf(stderr, "Invalid root '%s': %s\n", opts.root ? opts.root : "/", strerror(errno));
        goto out;
    }
    state->root_fd = open(state->rootdir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (state->root_fd == -1) {
        fprintf(stderr, "Could not open root '%s': %s\n", state->rootdir, strerror(errno));
        goto out;
    }

    if (state->log_fd >= 0) {
        char *abs = realpath(state->logpath, NULL);
        if (abs) {
            size_t rn = strlen(state->rootdir);
            if (strcmp(state->rootdir, "/") == 0) {
                state->log_rel = strdup(abs);
            } else if (strncmp(abs, state->rootdir, rn) == 0 && abs[rn] == '/') {
                state->log_rel = strdup(abs + rn);
            }
            state->logpath = abs;
        }
    }

    state->mountpoint = realpath(args.argv[args.argc - 1], NULL);
    if (!state->mountpoint) {
        fprintf(stderr, "Invalid mountpoint '%s': %s\n", args.argv[args.argc - 1], strerror(errno));
        goto out;
    } else if (strcmp(state->mountpoint, "/") == 0) {
        fprintf(stderr, "Mountpoint cannot be '/': %s\n", strerror(errno));
        goto out;
    }
    fprintf(stderr, "mountpoint: %s\nroot: %s\n", state->mountpoint, state->rootdir);

    /* let the kernel also enforce access for extra layer of safety */
    if (fuse_opt_insert_arg(&args, 1, "-oallow_other,default_permissions") == -1) {
        fprintf(stderr, "Failed to insert FUSE args\n");
        goto out;
    }

    /* check if recursion check is needed */
    size_t n = strlen(state->rootdir);
    int mntUnderRoot = 0;
    if (strncmp(state->mountpoint, state->rootdir, n) == 0) {
        if (n == 1 && state->rootdir[0] == '/') {
            mntUnderRoot = 1;
        } else {
            char c = state->mountpoint[n];
            mntUnderRoot = (c == '/');
        }
    }
    state->needRecursionCheck = mntUnderRoot;

    fprintf(stderr, "Using FUSE library version: %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);
    ret = fuse_main(args.argc, args.argv, &veilfs_oper, state);

out:
    if (state) {
        if (state->log_fd  >= 0) close(state->log_fd);
        if (state->root_fd >= 0) close(state->root_fd);
        free(state->rootdir);
        free(state->mountpoint);
        free(state);
    }
    free(opts.logpath);
    free(opts.root);
    fuse_opt_free_args(&args);
    return ret;
}