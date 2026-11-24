
#include <fuse.h>
#include "params.h"

#ifndef _LOGGING_H_
#define _LOGGING_H_

#define LOG_PATH "/var/log/veilfs"
#define SZ_1MB 1048576    // 1 MB
#define LOG_OP(path) veilfs_log(fuse_get_context(), __func__, (path))

void veilfs_log(struct fuse_context *context, const char *op, const char *path);
int open_log(const char *dir);

#endif