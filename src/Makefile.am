bin_PROGRAMS = veilfs
veilfs_SOURCES = veilfs.c config.h params.h

veilfs_CPPFLAGS = \
    -I$(top_builddir) \
    -DFUSE_USE_VERSION=30

veilfs_CFLAGS = $(FUSE3_CFLAGS)
veilfs_LDADD = $(FUSE3_LIBS)