#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([tox], [0.0.0], [https://tox.im])
AC_CONFIG_AUX_DIR(configure_aux)
AC_CONFIG_SRCDIR([toxcore/net_crypto.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.10 -Wall subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])

EXTRA_LT_LDFLAGS=

LIBTOXCORE_LT_VERSION=0:0:0
LIBTOXAV_LT_VERSION=0:0:0
dnl
dnl            current:revision:age
dnl
dnl current:  increment if interfaces have been added, removed or changed
dnl revision: increment if source code has changed, set to zero if current is
dnl           incremented
dnl age:      increment if interfaces have been added, set to zero if
dnl           interfaces have been removed or changed

if test "x${prefix}" = "xNONE"; then
    prefix="${ac_default_prefix}"
fi

BUILD_DHT_BOOTSTRAP_DAEMON="no"
BUILD_NTOX="no"
BUILD_TESTS="yes"
BUILD_AV="yes"
BUILD_TESTING="yes"

LOGGING="no"
LOGGING_OUTNAM="libtoxcore.log"

NCURSES_FOUND="no"
LIBCONFIG_FOUND="no"
LIBCHECK_FOUND="no"
WANT_NACL="no"
ADD_NACL_OBJECTS_TO_PKGCONFIG="yes"

TOXCORE_LT_LDFLAGS="-version-info $LIBTOXCORE_LT_VERSION"
TOXAV_LT_LDFLAGS="-version-info $LIBTOXAV_LT_VERSION"

AC_ARG_ENABLE([soname-versions],
    [AC_HELP_STRING([--enable-soname-versions], [enable soname versions (must be disabled for android) (default: enabled)]) ],
    [
        if test "x$enableval" = "xno"; then
            TOXCORE_LT_LDFLAGS="-avoid-version"
            TOXAV_LT_LDFLAGS="-avoid-version"
        fi
    ]
)

AC_SUBST(TOXCORE_LT_LDFLAGS)
AC_SUBST(TOXAV_LT_LDFLAGS)

AC_ARG_ENABLE([nacl],
    [AC_HELP_STRING([--enable-nacl], [use nacl instead of libsodium (default: disabled)]) ],
    [
        if test "x$enableval" = "xno"; then
            WANT_NACL="no"
        elif test "x$enableval" = "xyes"; then
            WANT_NACL="yes"
        fi
    ]
)

AC_ARG_ENABLE([randombytes-stir],
    [AC_HELP_STRING([--enable-randombytes-stir], [use randombytes_stir() instead of sodium_init() for faster startup on android (default: disabled)]) ],
    [
        if test "x$enableval" = "xyes"; then
            if test "x$WANT_NACL" = "xyes"; then
                AC_MSG_WARN([randombytes_stir() is not available with NaCl library])
            else
                AC_DEFINE([USE_RANDOMBYTES_STIR], [1], [randombytes_stir() instead of sodium_init()])
            fi
        fi
    ]
)

AC_ARG_ENABLE([logging],
    [AC_HELP_STRING([--enable-logging], [enable logging (default: auto)]) ],
    [
        if test "x$enableval" = "xyes"; then
            LOGGING="yes"
            
            AC_DEFINE([LOGGING], [], [If logging enabled])
            AC_DEFINE([LOGGER_LEVEL], [DEBUG], [LoggerLevel value])
            AC_DEFINE_UNQUOTED([LOGGER_OUTPUT_FILE], ["$LOGGING_OUTNAM"], [Output of logger])
        fi
    ]
)

AC_ARG_WITH(logger-level,
    AC_HELP_STRING([--with-logger-level=LEVEL],
                   [Logger levels: INFO; DEBUG; WARNING; ERROR ]),
    [
        if test "x$LOGGING" = "xno"; then
            AC_MSG_WARN([Logging disabled!])
        else
            if test "x$withval" = "xINFO"; then
                AC_DEFINE([LOGGER_LEVEL], [INFO], [LoggerLevel value])
                
            elif test "x$withval" = "xDEBUG"; then
                AC_DEFINE([LOGGER_LEVEL], [DEBUG], [LoggerLevel value])
                
            elif test "x$withval" = "xWARNING"; then
                AC_DEFINE([LOGGER_LEVEL], [WARNING], [LoggerLevel value])
                
            elif test "x$withval" = "xERROR"; then
                AC_DEFINE([LOGGER_LEVEL], [ERROR], [LoggerLevel value])
            else
                AC_MSG_WARN([Invalid logger level: $withval. Using default 'DEBUG'])
            fi
        fi
    ]
)

AC_ARG_WITH(logger-path,
    AC_HELP_STRING([--with-logger-path=DIR],
                   [Path of logger output]),
    [
        if test "x$LOGGING" = "xno"; then
            AC_MSG_WARN([Logging disabled!])
        else
            AC_DEFINE_UNQUOTED([LOGGER_OUTPUT_FILE], ["$withval""/""$LOGGING_OUTNAM"], [Output of logger])
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

AC_ARG_ENABLE([ntox],
    [AC_HELP_STRING([--enable-ntox], [build nTox client (default: auto)]) ],
    [
        if test "x$enableval" = "xno"; then
            BUILD_NTOX="no"
        elif test "x$enableval" = "xyes"; then
            BUILD_NTOX="yes"
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
NACL_SEARCH_HEADERS=
NACL_SEARCH_LIBS=

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

AC_ARG_WITH(nacl-headers,
        AC_HELP_STRING([--with-nacl-headers=DIR],
                       [search for nacl<F2> header files in DIR]),
        [
            NACL_SEARCH_HEADERS="$withval"
            AC_MSG_NOTICE([will search for nacl header files in $withval])
        ]
)

AC_ARG_WITH(nacl-libs,
        AC_HELP_STRING([--with-nacl-libs=DIR],
                       [search for nacl libraries in DIR]),
        [
            NACL_SEARCH_LIBS="$withval"
            AC_MSG_NOTICE([will search for nacl libraries in $withval])
        ]
)

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

if test "x$WANT_NACL" = "xyes"; then
    enable_shared=no
    enable_static=yes
fi

# Checks for programs.
AC_PROG_CC
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
    *freebsd*|*openbsd*)
        LDFLAGS="$LDFLAGS -L/usr/local/lib"
        CFLAGS="$CFLAGS -I/usr/local/include"
        CPPFLAGS="$CPPFLAGS -I/usr/local/include"
        ADD_NACL_OBJECTS_TO_PKGCONFIG="no"
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

if test "x$WANT_NACL" = "xyes"; then
    NACL_LIBS=
    NACL_LDFLAGS=
    NACL_OBJECTS=
    NACL_OBJECTS_PKGCONFIG=
    LDFLAGS_SAVE="$LDFLAGS"
    if test -n "$NACL_SEARCH_LIBS"; then
        LDFLAGS="-L$NACL_SEARCH_LIBS $LDFLAGS"
        AC_CHECK_LIB(nacl, random,
            [
                NACL_LDFLAGS="-L$NACL_SEARCH_LIBS"
                NACL_LIBS="-lnacl"
            ],
            [
                AC_MSG_ERROR([library nacl was not found in requested location $NACL_SEARCH_LIBS])
            ]
        )
    else
        AC_CHECK_LIB(nacl, random,
            [],
            [
                AC_MSG_ERROR([you enabled nacl support, but library nacl was not found on your system])
            ]
        )
    fi

    if (test -f "$NACL_SEARCH_LIBS/cpucycles.o") &&
       (test -f "$NACL_SEARCH_LIBS/randombytes.o"); then
        NACL_OBJECTS="$NACL_SEARCH_LIBS/cpucycles.o $NACL_SEARCH_LIBS/randombytes.o"
        if test "x$ADD_NACL_OBJECTS_TO_PKGCONFIG" = "xyes"; then
            NACL_OBJECTS_PKGCONFIG="$NACL_OBJECTS"
        fi
    else
        AC_MSG_ERROR([required NaCl object files cpucycles.o randombytes.o not found, please specify their location using the --with-nacl-libs parameter])
    fi

    LDFLAGS="$LDFLAGS_SAVE"
    AC_SUBST(NACL_LIBS)
    AC_SUBST(NACL_LDFLAGS)
    AC_SUBST(NACL_OBJECTS)
    AC_SUBST(NACL_OBJECTS_PKGCONFIG)
else
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
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])


if test "x$WANT_NACL" = "xyes"; then
    NACL_CFLAGS=
    CFLAGS_SAVE="$CFLAGS"
    CPPFLAGS_SAVE="$CPPFLAGS"
    if test -n "$NACL_SEARCH_HEADERS"; then
        CFLAGS="-I$NACL_SEARCH_HEADERS $CFLAGS"
        CPPFLAGS="-I$NACL_SEARCH_HEADERS $CPPFLAGS"
        AC_CHECK_HEADER(crypto_box.h,
            [
                NACL_CFLAGS="-I$NACL_SEARCH_HEADERS"
            ],
            [
                AC_MSG_ERROR([header files for library nacl were not found in requested location $NACL_SEARCH_HEADERS])
            ]
        )
    else
        AC_CHECK_HEADER(crypto_box.h,
            [],
            [
                AC_MSG_ERROR([you enabled nacl support, but nacl header files were not found on your system])
            ]
        )
    fi
    CFLAGS="$CFLAGS_SAVE"
    CPPFLAGS="$CPPFLAGS_SAVE"
    AC_SUBST(NACL_CFLAGS)
    AC_DEFINE([VANILLA_NACL], [1], [use nacl instead of libsodium])
else
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
AC_C_BIGENDIAN


# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([gettimeofday memset socket strchr malloc])
if (test "x$WIN32" != "xyes") && (test "x$MACH" != "xyes") && (test "x$DISABLE_RT" != "xyes"); then
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
    ## What about pthread?
    AV_LIBS="$OPUS_LIBS $VPX_LIBS -pthread"
    AC_SUBST(AV_LIBS)

    AV_CFLAGS="$OPUS_CFLAGS $VPX_CFLAGS"
    AC_SUBST(AV_CFLAGS)
fi

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
    AC_MSG_WARN([pkg-config was not found on your system, will search for libraries manually])
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
            WINSOCK2_LIBS="-liphlpapi -lws2_32"
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
AM_CONDITIONAL(BUILD_AV, test "x$BUILD_AV" = "xyes")
AM_CONDITIONAL(BUILD_TESTING, test "x$BUILD_TESTING" = "xyes")
AM_CONDITIONAL(WIN32, test "x$WIN32" = "xyes")

AC_CONFIG_FILES([Makefile
                 build/Makefile
                 libtoxcore.pc
                ])

AM_COND_IF(BUILD_AV,
  [
    AC_CONFIG_FILES([libtoxav.pc])
  ],)

AC_OUTPUT
