#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([tox], [0.0.0], [http://tox.im])
AC_CONFIG_AUX_DIR(configure_aux)
AC_CONFIG_SRCDIR([toxcore/net_crypto.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.10 -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

if test "x${prefix}" = "xNONE"; then
    prefix="${ac_default_prefix}"
fi

DEPSEARCH=
LIBSODIUM_SEARCH_HEADERS=
LIBSODIUM_SEARCH_LIBS=

AC_ARG_WITH(dependency-search,
    AC_HELP_STRING([--with-dependency-search=DIR],
                   [search for dependencies in DIR, i.e. look for libraries in
                    DIR/lib and for headers in DIR/include]),
    [
        DEPSEARCH="$withval"
    ]
)

if test -n "$DEPSEARCH"; then
    CFLAGS="$CFLAGS -I$DEPSEARCH/include"
    CPPFLAGS="$CPPFLAGS -I$DEPSEARCH/include"
    LDFLAGS="$LDFLAGS -L$DEPSEARCH/lib"
    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$DEPSEARCH/lib/pkgconfig
fi

AC_ARG_WITH(libsodium-headers,
        AC_HELP_STRING([--with-libsodium-headers=DIR],
                       [search for libsodium header files in DIR]),
        [
            LIBSODIUM_SEARCH_HEADERS="$withval"
            AC_MSG_NOTICE([Will search for libsodium header files in $withval])
        ]
)

AC_ARG_WITH(libsodium-libs,
        AC_HELP_STRING([--with-libsodium-libs=DIR],
                       [search for libsodium libraries in DIR]),
        [
            LIBSODIUM_SEARCH_LIBS="$withval"
            AC_MSG_NOTICE([Will search for libsodium libraries in $withval])
        ]
)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

AC_CANONICAL_HOST
case $host_os in
    *mingw*)
        WIN32="yes"
    ;;
esac
AM_CONDITIONAL(WIN32, test "x$WIN32" = "xyes")

# Checks for libraries.
LIBSODIUM_LIBS=
LIBSODIUM_LDFLAGS=
LDFLAGS_SAVE="$LDFLAGS"
if test -n "$LIBSODIUM_SEARCH_LIBS"; then
    LDFLAGS="-L$LIBSODIUM_SEARCH_LIBS"
    AC_CHECK_LIB(sodium, randombytes_random,
        [
            LIBSODIUM_LDFLAGS="-L$LIBSODIUM_SEARCH_LIBS"
            LIBSODIUM_LIBS="-lsodium"
        ],
        [
            AC_MSG_ERROR([required library libsodium was not found in requested location $LIBSODIUM_SEARCH_LIBS])
        ]
    )
else
    AC_CHECK_LIB(sodium, randombytes_random,
        [],
        [
            AC_MSG_ERROR([required library libsodium was not found on your system, please check http://download.libsodium.org/libsodium/releases/]) 
        ]
    )
fi

LDFLAGS="$LDFLAGS_SAVE"
AC_SUBST(LIBSODIUM_LIBS)
AC_SUBST(LIBSODIUM_LDFLAGS)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

LIBSODIUM_CFLAGS=
CFLAGS_SAVE="$CFLAGS"
CPPFLAGS_SAVE="$CPPFLAGS"
if test -n "$LIBSODIUM_SEARCH_HEADERS"; then
    CFLAGS="-I$LIBSODIUM_SEARCH_HEADERS"
    CPPFLAGS="-I$LIBSODIUM_SEARCH_HEADERS"
    AC_CHECK_HEADER(sodium.h,
        [
            LIBSODIUM_CFLAGS="-I$LIBSODIUM_SEARCH_HEADERS"
        ],
        [
            AC_MSG_ERROR([header files for required library libsodium was not found in requested location $LIBSODIUM_SEARCH_HEADERS])
        ]
    )
else
    AC_CHECK_HEADER(sodium.h,
        [],
        [
            AC_MSG_ERROR([header files for required library libsodium was not found on your system, please check http://download.libsodium.org/libsodium/releases/])
        ]
    )
fi
CFLAGS="$CFLAGS_SAVE"
CPPFLAGS="$CPPFLAGS_SAVE"
AC_SUBST(LIBSODIUM_CFLAGS)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset socket strchr])

# pkg-config based tests
PKG_PROG_PKG_CONFIG

if test -n "$PKG_CONFIG"; then
    PKG_CHECK_MODULES([NCURSES], [ncurses], [],
        [
            AC_MSG_ERROR([$NCURSES_PKG_ERRORS])
        ])

    if test "$WIN32" != "xyes"; then
        PKG_CHECK_MODULES([LIBCONFIG], [libconfig],
            [
                BUILD_DHT_BOOTSTRAP_DAEMON="yes"
            ],
            [
                AC_MSG_WARN([$LIBCONFIG_PKG_ERRORS])
                AC_MSG_NOTICE([libconfig not available, will not build DHT botstrap daemon])
            ])
    fi
else
    AC_MSG_WARN([pkg-config was not found on your sytem])
    AC_CHECK_HEADER(curses.h,
        [],
        [
            AC_MSG_ERROR([header files for required library ncurses was not found on your system])
        ]
    )
    AC_CHECK_LIB(ncurses, clear,
        [],
        [
            AC_MSG_ERROR([required library ncurses was not found on the system])
        ],
        [
            -ltinfo
        ]
    )

    if test "$WIN32" != "xyes"; then
        AC_CHECK_HEADER(libconfig.h,
            [
                BUILD_DHT_BOOTSTRAP_DAEMON="yes"
            ],
            [
                AC_MSG_WARN([header files for library libconfig was not found on your system])
            ]
        )

        AC_CHECK_LIB(config, config_read,
            [
                BUILD_DHT_BOOTSTRAP_DAEMON="yes"
                LIBCONFIG_LIBS="-lconfig"
                AC_SUBST(LIBCONFIG_LIBS)
            ],
            [
                AC_MSG_WARN([library libconfig was not found on the system])
                BUILD_DHT_BOOTSTRAP_DAEMON="no"
            ]
        )
    fi
fi
AM_CONDITIONAL(BUILD_DHT_BOOTSTRAP_DAEMON, test "x$BUILD_DHT_BOOTSTRAP_DAEMON" = "xyes")

AC_CONFIG_FILES([Makefile
                 build/Makefile])
AC_OUTPUT
