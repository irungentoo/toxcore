#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([tox], [0.0.0], [http://tox.im])
AC_CONFIG_AUX_DIR(configure_aux)
AC_CONFIG_SRCDIR([toxcore/net_crypto.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.10 -Wall subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])

LIBTOXCORE_LT_VERSION=0:0:0
dnl
dnl            current:revision:age
dnl
dnl current:  increment if interfaces have been added, removed or changed
dnl revision: increment if source code has changed, set to zero if current is
dnl           incremented
dnl age:      increment if interfaces have been added, set to zero if
dnl           interfaces have been removed or changed
EXTRA_LT_LDFLAGS="-version-info $LIBTOXCORE_LT_VERSION"

if test "x${prefix}" = "xNONE"; then
    prefix="${ac_default_prefix}"
fi

BUILD_DHT_BOOTSTRAP_DAEMON="yes"
BUILD_NTOX="yes"
BUILD_TESTS="yes"

NCURSES_FOUND="no"
LIBCONFIG_FOUND="no"
LIBCHECK_FOUND="no"

AC_ARG_ENABLE([tests],
    [AC_HELP_STRING([--disable-tests], [build unit tests (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_TESTS="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_TESTS="yes"
        fi
    ]
)

AC_ARG_ENABLE([ntox],
    [AC_HELP_STRING([--disable-ntox], [build nTox client (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_NTOX="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_NTOX="yes"
        fi
    ]
)

AC_ARG_ENABLE([dht-bootstrap-daemon],
    [AC_HELP_STRING([--disable-dht-bootstrap-daemon], [build DHT bootstrap daemon (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_DHT_BOOTSTRAP_DAEMON="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_DHT_BOOTSTRAP_DAEMON="yes"
        fi
    ]
)

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
            AC_MSG_NOTICE([will search for libsodium header files in $withval])
        ]
)

AC_ARG_WITH(libsodium-libs,
        AC_HELP_STRING([--with-libsodium-libs=DIR],
                       [search for libsodium libraries in DIR]),
        [
            LIBSODIUM_SEARCH_LIBS="$withval"
            AC_MSG_NOTICE([will search for libsodium libraries in $withval])
        ]
)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

WIN32=no
AC_CANONICAL_HOST
case $host_os in
    *mingw*)
        WIN32="yes"
        EXTRA_LT_LDFLAGS="$EXTRA_LT_LDFLAGS -no-undefined"
    ;;
    *solaris*)
        LIBS="$LIBS -lssp -lsocket -lnsl"
    ;;
    *freebsd*)
        LDFLAGS="$LDFLAGS -L/usr/local/lib"
        CFLAGS="$CFLAGS -I/usr/local/include"
        CPPFLAGS="$CPPFLAGS -I/usr/local/include"
    ;;
esac
AM_CONDITIONAL(WIN32, test "x$WIN32" = "xyes")

AC_SUBST(EXTRA_LT_LDFLAGS)

# Checks for libraries.
LIBSODIUM_LIBS=
LIBSODIUM_LDFLAGS=
LDFLAGS_SAVE="$LDFLAGS"
if test -n "$LIBSODIUM_SEARCH_LIBS"; then
    LDFLAGS="-L$LIBSODIUM_SEARCH_LIBS $LDFLAGS"
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
    CFLAGS="-I$LIBSODIUM_SEARCH_HEADERS $CFLAGS"
    CPPFLAGS="-I$LIBSODIUM_SEARCH_HEADERS $CPPFLAGS"
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
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset socket strchr malloc])

# pkg-config based tests
PKG_PROG_PKG_CONFIG

if test -n "$PKG_CONFIG"; then
    if test "x$BUILD_TESTS" = "xyes"; then
        PKG_CHECK_MODULES([CHECK], [check],
            [
                LIBCHECK_FOUND="yes"
            ],
            [
                AC_MSG_WARN([libcheck not found, not building unit tests: $CHECK_PKG_ERRORS])
                BUILD_TESTS="no"
            ])
    fi

    if test "x$BUILD_DHT_BOOTSTRAP_DAEMON" = "xyes"; then
        PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.4.6],
            [
                LIBCONFIG_FOUND="yes"
            ],
            [
                AC_MSG_WARN([$LIBCONFIG_PKG_ERRORS])
                AC_MSG_WARN([libconfig not available, will not build DHT bootstrap daemon])
                BUILD_DHT_BOOTSTRAP_DAEMON="no"
            ])
    fi

    if test "x$BUILD_NTOX" = "xyes"; then
        PKG_CHECK_MODULES([NCURSES], [ncurses],
            [
                NCURSES_FOUND="yes"
            ],
            [
                AC_MSG_WARN([$NCURSES_PKG_ERRORS])
            ])
    fi
else
    AC_MSG_WARN([pkg-config was not found on your system])
fi

if (test "x$BUILD_NTOX" = "xyes") && (test "x$NCURSES_FOUND" != "xyes"); then
    AC_PATH_PROG([CURSES_CONFIG], [ncurses5-config], [no])
    if test "x$CURSES_CONFIG" != "xno"; then
        AC_MSG_CHECKING(ncurses cflags)
        NCURSES_CFLAGS=`${CURSES_CONFIG} --cflags`
        AC_MSG_RESULT($NCURSES_CFLAGS)

        AC_MSG_CHECKING(ncurses libraries)
        NCURSES_LIBS=`${CURSES_CONFIG} --libs`
        AC_MSG_RESULT($NCURSES_LIBS)

        AC_SUBST(NCURSES_CFLAGS)
        AC_SUBST(NCURSES_LIBS)
        NCURSES_FOUND="yes"
    fi

    if test "x$NCURSES_FOUND" != "xyes"; then
        AC_CHECK_HEADER([curses.h],
            [],
            [
                AC_MSG_WARN([not building nTox client because headers for the curses library were not found on your system])
                BUILD_NTOX="no"
            ]
        )
        if test "x$BUILD_NTOX" = "xyes"; then
            if test "x$WIN32" = "xyes"; then
                AC_CHECK_LIB([pdcurses], [clear],
                    [
                        NCURSES_LIBS="-lpdcurses"
                        AC_SUBST(NCURSES_LIBS)
                    ],
                    [
                        AC_MSG_ERROR([required library pdcurses was not found on your system])
                        BUILD_NTOX="no"
                    ]
                )
            else
                AC_CHECK_LIB([ncurses], [clear],
                    [
                        NCURSES_LIBS="-lncurses"
                        AC_SUBST(NCURSES_LIBS)
                    ],
                    [
                        unset ac_cv_lib_ncurses_clear
                        AC_CHECK_LIB([ncurses], [clear],
                            [
                                NCURSES_LIBS="-lncurses -ltinfo"
                                AC_SUBST(NCURSES_LIBS)
                            ],
                            [
                                AC_MSG_WARN([not building nTox client because required library ncurses was not found on your system])
                                BUILD_NTOX="no"
                            ],
                            [
                                -ltinfo
                            ]
                        )
                    ]
                )
            fi
        fi
    fi
fi

if (test "x$BUILD_DHT_BOOTSTRAP_DAEMON" = "xyes") && \
   (test "x$LIBCONFIG_FOUND" = "xno"); then
    AC_CHECK_HEADER(libconfig.h,
        [],
        [
            AC_MSG_WARN([header files for library libconfig was not found on your system, not building DHT bootstrap daemon])
            BUILD_DHT_BOOTSTRAP_DAEMON="no"
        ]
    )

    if test "x$BUILD_DHT_BOOTSTRAP_DAEMON" = "xyes"; then
        AC_CHECK_LIB(config, config_read,
            [],
            [
                AC_MSG_WARN([library libconfig was not found on the system])
                BUILD_DHT_BOOTSTRAP_DAEMON="no"
            ]
        )
    fi
fi

if (test "x$BUILD_TESTS" = "xyes") && (test "x$LIBCHECK_FOUND" = "xno"); then
    AC_CHECK_HEADER([check.h],
        [],
        [
            AC_MSG_WARN([header file for check library was not found on your system, unit tests will be disabled])
            BUILD_TESTS="no"
        ]
    )

    if test "x$BUILD_TESTS" = "xyes"; then
        AC_CHECK_LIB([check], [suite_create],
            [],
            [
                AC_MSG_WARN([library check was not found on the system, unit tests will be disabled])
                BUILD_TESTS="no"
            ]
       )
    fi
fi

if test "x$WIN32" = "xyes"; then
    AC_CHECK_LIB(ws2_32, main,
        [
            WINSOCK2_LIBS="-lws2_32"
            AC_SUBST(WINSOCK2_LIBS)
        ],
        [
            AC_MSG_ERROR([required library was not found on the system, please check your MinGW installation])
        ]
    )
fi

AM_CONDITIONAL(BUILD_DHT_BOOTSTRAP_DAEMON, test "x$BUILD_DHT_BOOTSTRAP_DAEMON" = "xyes")

AM_CONDITIONAL(BUILD_TESTS, test "x$BUILD_TESTS" = "xyes")
AM_CONDITIONAL(BUILD_NTOX, test "x$BUILD_NTOX" = "xyes")

AC_CONFIG_FILES([Makefile
                 build/Makefile
                 libtoxcore.pc
                ])
AC_OUTPUT
