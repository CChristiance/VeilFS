bin_PROGRAMS = veilfs
veilfs_SOURCES = veilfs.c params.h

veilfs_CPPFLAGS = -I$(top_builddir) $(FUSE3_CFLAGS) -DFUSE_USE_VERSION=31
veilfs_LDADD = $(FUSE3_LIBS)