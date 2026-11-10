AC_INIT([VeilFS], [0.1.0])
AC_CONFIG_SRCDIR([src/veilfs.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([FUSE3], [fuse3 >= 3.0])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT