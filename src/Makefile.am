bin_PROGRAMS = veilfs
veilfs_SOURCES = veilfs.c logging.c params.h logging.h

veilfs_CPPFLAGS = -I$(top_builddir) $(FUSE3_CFLAGS) -DFUSE_USE_VERSION=31
veilfs_CFLAGS = $(AM_CFLAGS) -finstrument-functions
veilfs_LDADD = $(FUSE3_LIBS)
