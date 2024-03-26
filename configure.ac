#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([tox], [0.2.19])
AC_CONFIG_AUX_DIR(configure_aux)
AC_CONFIG_SRCDIR([toxcore/net_crypto.c])
AM_INIT_AUTOMAKE([foreign 1.10 -Wall -Werror subdir-objects tar-ustar])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])

EXTRA_LT_LDFLAGS=

if test "x${prefix}" = "xNONE"; then
    prefix="${ac_default_prefix}"
fi

BUILD_DHT_BOOTSTRAP_DAEMON="no"
BUILD_DHT_BOOTSTRAP="no"
BUILD_TESTS="yes"
BUILD_AV="yes"
BUILD_TESTING="yes"

LIBCONFIG_FOUND="no"
SET_SO_VERSION="yes"

AC_ARG_ENABLE([soname-versions],
    [AC_HELP_STRING([--enable-soname-versions], [enable soname versions (must be disabled for android) (default: enabled)]) ],
    [
        if test "x$enableval" = "xno"; then
            SET_SO_VERSION="no"
        elif test "x$enableval" = "xyes"; then
            SET_SO_VERSION="yes"
        fi
    ]
)
AM_CONDITIONAL(SET_SO_VERSION, test "x$SET_SO_VERSION" = "xyes")

AC_ARG_ENABLE([randombytes-stir],
    [AC_HELP_STRING([--enable-randombytes-stir], [use randombytes_stir() instead of sodium_init() for faster startup on android (default: disabled)]) ],
    [
        if test "x$enableval" = "xyes"; then
            AC_DEFINE([USE_RANDOMBYTES_STIR], [1], [randombytes_stir() instead of sodium_init()])
        fi
    ]
)

AC_ARG_WITH(log-level,
    AC_HELP_STRING([--with-log-level=LEVEL],
                   [Logger levels: TRACE; DEBUG; INFO; WARNING; ERROR ]),
    [
        if test "x$withval" = "xTRACE"; then
            AC_DEFINE([MIN_LOGGER_LEVEL], [LOGGER_LEVEL_TRACE], [Logger_Level value])

        elif test "x$withval" = "xDEBUG"; then
            AC_DEFINE([MIN_LOGGER_LEVEL], [LOGGER_LEVEL_DEBUG], [Logger_Level value])

        elif test "x$withval" = "xINFO"; then
            AC_DEFINE([MIN_LOGGER_LEVEL], [LOGGER_LEVEL_INFO], [Logger_Level value])

        elif test "x$withval" = "xWARNING"; then
            AC_DEFINE([MIN_LOGGER_LEVEL], [LOGGER_LEVEL_WARNING], [Logger_Level value])

        elif test "x$withval" = "xERROR"; then
            AC_DEFINE([MIN_LOGGER_LEVEL], [LOGGER_LEVEL_ERROR], [Logger_Level value])
        else
            AC_MSG_WARN([Invalid logger level: $withval. Using default.])
        fi
    ]
)

PKG_PROG_PKG_CONFIG

AC_ARG_ENABLE([av],
    [AC_HELP_STRING([--disable-av], [build AV support libraries (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_AV="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_AV="yes"
        fi
    ]
)

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

AC_ARG_ENABLE([daemon],
    [AC_HELP_STRING([--enable-daemon], [build DHT bootstrap daemon (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_DHT_BOOTSTRAP_DAEMON="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_DHT_BOOTSTRAP_DAEMON="yes"
        fi
    ]
)

AC_ARG_ENABLE([dht-bootstrap],
    [AC_HELP_STRING([--enable-dht-bootstrap], [build DHT bootstrap utility (default: disabled)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_DHT_BOOTSTRAP="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_DHT_BOOTSTRAP="yes"
        fi
    ]
)


AC_ARG_ENABLE([rt],
    [AC_HELP_STRING([--disable-rt], [Disables the librt check (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            DISABLE_RT="yes"
        elif test "x$enableval" = "xyes"; then
            DISABLE_RT="no"
        fi
    ]
)

AC_ARG_ENABLE([testing],
    [AC_HELP_STRING([--disable-testing], [build various testing tools (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_TESTING="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_TESTING="yes"
        fi
    ]
)

AC_ARG_ENABLE([[epoll]],
  [AS_HELP_STRING([[--enable-epoll[=ARG]]], [enable epoll support (yes, no, auto) [auto]])],
    [enable_epoll=${enableval}],
    [enable_epoll='auto']
  )

AC_ARG_ENABLE([[ipv6]],
  [AS_HELP_STRING([[--disable-ipv6[=ARG]]], [use ipv4 in tests (yes, no, auto) [auto]])],
    [use_ipv6=${enableval}],
    [use_ipv6='auto']
  )

if test "$use_ipv6" != "yes"; then
  AC_DEFINE([USE_IPV6],[0],[define to 0 to force ipv4])
fi

AX_HAVE_EPOLL
if test "$enable_epoll" != "no"; then
  if test "${ax_cv_have_epoll}" = "yes"; then
    AC_DEFINE([TCP_SERVER_USE_EPOLL],[1],[define to 1 to enable epoll support])
    enable_epoll='yes'
  else
    if test "$enable_epoll" = "yes"; then
      AC_MSG_ERROR([[Support for epoll was explicitly requested but cannot be enabled on this platform.]])
    fi
    enable_epoll='no'
  fi
fi

DEPSEARCH=
LIBSODIUM_SEARCH_HEADERS=
LIBSODIUM_SEARCH_LIBS=

AC_ARG_WITH(dependency-search,
    AC_HELP_STRING([--with-dependency-search=DIR],
                   [search for dependencies in DIR, i.e., look for libraries in
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
AC_PROG_CC_C99

if test "x$ac_cv_prog_cc_c99" = "xno" ; then
    AC_MSG_ERROR([c-toxcore requires a C99 compatible compiler])
fi

AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

WIN32=no
MACH=no
AC_CANONICAL_HOST
case $host_os in
    *mingw*)
        WIN32="yes"
        EXTRA_LT_LDFLAGS="$EXTRA_LT_LDFLAGS -no-undefined"
    ;;
    *solaris*)
        LIBS="$LIBS -lssp -lsocket -lnsl"
    ;;
    *qnx*)
        LIBS="$LIBS -lsocket"
    ;;
    *freebsd*|*openbsd*)
        LDFLAGS="$LDFLAGS -L/usr/local/lib"
        CFLAGS="$CFLAGS -I/usr/local/include"
        CPPFLAGS="$CPPFLAGS -I/usr/local/include"
    ;;
    darwin*)
        MACH=yes
    ;;
esac
AM_CONDITIONAL(WIN32, test "x$WIN32" = "xyes")

AC_SUBST(EXTRA_LT_LDFLAGS)

# Needed math flags for some compilers

MATH_LDFLAGS="-lm"
AC_SUBST(MATH_LDFLAGS)

# Checks for libraries.
AC_CHECK_FUNCS([explicit_bzero memset_s])
PKG_CHECK_MODULES([LIBSODIUM], [libsodium],
    [
        LIBSODIUM_FOUND="yes"
    ],
    [
        LIBSODIUM_FOUND="no"
    ])

if test "x$LIBSODIUM_FOUND" = "xno"; then
    LIBSODIUM_LIBS=
    LIBSODIUM_LDFLAGS=
    LDFLAGS_SAVE="$LDFLAGS"
    if test -n "$LIBSODIUM_SEARCH_LIBS"; then
        LDFLAGS="-L$LIBSODIUM_SEARCH_LIBS $LDFLAGS"
        AC_CHECK_LIB(sodium, crypto_pwhash_scryptsalsa208sha256,
            [
                LIBSODIUM_LDFLAGS="-L$LIBSODIUM_SEARCH_LIBS"
                LIBSODIUM_LIBS="-lsodium"
            ],
            [
                AC_MSG_ERROR([required library libsodium was not found in requested location $LIBSODIUM_SEARCH_LIBS or library version is too old])
            ]
        )
    else
        AC_CHECK_LIB(sodium, crypto_pwhash_scryptsalsa208sha256,
            [],
            [
                AC_MSG_ERROR([required library libsodium was not found on your system, please check http://download.libsodium.org/libsodium/releases/ or library version is too old])
            ]
        )
    fi

    LDFLAGS="$LDFLAGS_SAVE"
    AC_SUBST(LIBSODIUM_LIBS)
    AC_SUBST(LIBSODIUM_LDFLAGS)
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])


if test "x$LIBSODIUM_FOUND" = "xno"; then
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
                AC_MSG_ERROR([header files for required library libsodium were not found in requested location $LIBSODIUM_SEARCH_HEADERS])
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
fi

# Checks for library functions.
if (test "x$WIN32" != "xyes") && (test "x$MACH" != "xyes") && (test "x${host_os#*openbsd}" = "x$host_os") && (test "x$DISABLE_RT" != "xyes"); then
    AC_CHECK_LIB(rt, clock_gettime,
        [
            RT_LIBS="-lrt"
            AC_SUBST(RT_LIBS)
        ],
        [
            AC_MSG_ERROR([required library rt was not found on your system])
        ]
    )
fi


AX_PTHREAD(
    [],
    [
        AC_MSG_ERROR([required library pthread was not found on your system])
    ]
)

AC_CHECK_LIB([pthread], [pthread_self],
    [
        PTHREAD_LDFLAGS="-lpthread"
        AC_SUBST(PTHREAD_LDFLAGS)
    ]
)

if test "x$BUILD_AV" = "xyes"; then
    PKG_CHECK_MODULES([OPUS], [opus],
        [],
        [
            AC_MSG_WARN([disabling AV support $OPUS_PKG_ERRORS])
            BUILD_AV="no"
        ]
    )
fi

if test "x$BUILD_AV" = "xyes"; then
    PKG_CHECK_MODULES([VPX], [vpx],
        [],
        [
            AC_MSG_WARN([disabling AV support $VPX_PKG_ERRORS])
            BUILD_AV="no"
        ]
    )
fi

if test "x$BUILD_AV" = "xyes"; then
    # toxcore lib needs an global?
    # So far this works okay
    AV_LIBS="$OPUS_LIBS $VPX_LIBS"
    AC_SUBST(AV_LIBS)

    AV_CFLAGS="$OPUS_CFLAGS $VPX_CFLAGS"
    AC_SUBST(AV_CFLAGS)
fi

if test -n "$PKG_CONFIG"; then
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
else
    AC_MSG_WARN([pkg-config was not found on your system, will search for libraries manually])
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

if test "x$WIN32" = "xyes"; then
    AC_CHECK_LIB(ws2_32, main,
        [
            WINSOCK2_LIBS="-liphlpapi -lws2_32"
            AC_SUBST(WINSOCK2_LIBS)
        ],
        [
            AC_MSG_ERROR([required library was not found on the system, please check your MinGW installation])
        ]
    )
fi

AM_CONDITIONAL(BUILD_DHT_BOOTSTRAP_DAEMON, test "x$BUILD_DHT_BOOTSTRAP_DAEMON" = "xyes")
AM_CONDITIONAL(BUILD_DHT_BOOTSTRAP, test "x$BUILD_DHT_BOOTSTRAP" = "xyes")
AM_CONDITIONAL(BUILD_TESTS, test "x$BUILD_TESTS" = "xyes")
AM_CONDITIONAL(BUILD_AV, test "x$BUILD_AV" = "xyes")
AM_CONDITIONAL(BUILD_TESTING, test "x$BUILD_TESTING" = "xyes")
AM_CONDITIONAL(WIN32, test "x$WIN32" = "xyes")

AC_CONFIG_FILES([Makefile
                 build/Makefile
                 libtoxcore.pc
                 tox.spec
                ])

AM_COND_IF(BUILD_AV,
  [
    AC_CONFIG_FILES([libtoxav.pc])
  ],)

AC_OUTPUT
