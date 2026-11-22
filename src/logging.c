#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fuse.h>
#include "logging.h"

static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

static int is_log_path(const char *path, const char *logpath) {
    size_t len = strlen(logpath);
    return strncmp(path, logpath, len) == 0 &&
           (path[len] == '\0' || path[len] == '/');
}

static void get_cmdline(pid_t pid, char *buf, size_t size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", (int)pid);

    int fd = open(proc_path, O_RDONLY);
    if (fd == -1) { snprintf(buf, size, "?"); return; }

    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n <= 0) { snprintf(buf, size, "?"); return; }

    // argv is NUL-separated; also strip newlines so a process can't forge log lines
    for (ssize_t i = 0; i < n; i++)
        if (buf[i] == '\0' || buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
    buf[n] = '\0';
}

// Returns the fd to keep logging to: a new fd if the log was rotated,
// otherwise the original fd (including when rotation fails).
static int rotate_log_if_needed(struct veilfs_state *state) {
    int fd = state->log_fd;
    struct stat st;
    if (fstat(fd, &st) == -1 || st.st_size <= SZ_1MB)
        return fd;

    char cur[PATH_MAX], old[PATH_MAX];
    int len = snprintf(cur, sizeof(cur), "%s/veilfs.log", state->logpath);
    if (len < 0 || (size_t)len >= sizeof(cur)) return fd;

    // find the next unused veilfs_n.log
    int n = 1;
    do {
        len = snprintf(old, sizeof(old), "%s/veilfs_%d.log", state->logpath, n++);
        if (len < 0 || (size_t)len >= sizeof(old)) return fd;
    } while (access(old, F_OK) == 0);

    // rename the full log, then start a fresh veilfs.log
    if (rename(cur, old) == -1) return fd;

    int new_fd = open(cur, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (new_fd == -1) return fd;   // keep writing to the renamed file

    close(fd);
    return new_fd;
}

// log timestamp, user info, invoked syscall, and file/directory they tried to access
void veilfs_log(struct fuse_context *context, const char *op, const char *path) {
    fprintf(stderr, "Logging...\n");
    struct veilfs_state *state = context->private_data;
    if (state->log_fd < 0) return;
    if (path && is_log_path(path, state->logpath)) return

    state->log_fd = rotate_log_if_needed(state);

    char timestamp[24];
    get_timestamp(timestamp, sizeof(timestamp));

    char cmd[256];
    get_cmdline(context->pid, cmd, sizeof(cmd));

    dprintf(state->log_fd, "%s - uid=%d pid=%d op=%s path=%s cmd=%s\n",
            timestamp, context->uid, (int)context->pid, op, path ? path : "-", cmd);
}