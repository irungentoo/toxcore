lib_LTLIBRARIES += libtoxencryptsave.la

libtoxencryptsave_la_include_HEADERS = \
                        ../toxencryptsave/toxencryptsave.h

libtoxencryptsave_la_includedir = $(includedir)/tox

libtoxencryptsave_la_SOURCES = ../toxencryptsave/toxencryptsave.h \
                        ../toxencryptsave/toxencryptsave.c


if WITH_NACL
libtoxencryptsave_la_SOURCES += ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/crypto_pwhash_scryptsalsa208sha256.h \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/crypto_scrypt.h \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/pbkdf2-sha256.c \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/runtime.h \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/utils.c \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/crypto_scrypt-common.c \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/export.h \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/pbkdf2-sha256.h \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/runtime.c \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/scrypt_platform.c \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/sysendian.h \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/utils.h \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c \
                        ../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c
endif

libtoxencryptsave_la_CFLAGS =   -I$(top_srcdir) \
                        -I$(top_srcdir)/toxcore \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(PTHREAD_CFLAGS)

libtoxencryptsave_la_LDFLAGS =  $(TOXCORE_LT_LDFLAGS) \
                        $(EXTRA_LT_LDFLAGS) \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        $(MATH_LDFLAGS) \
                        $(RT_LIBS) \
                        $(WINSOCK2_LIBS)

libtoxencryptsave_la_LIBADD =   $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NAC_LIBS) \
                        $(PTHREAD_LIBS) \
                        libtoxcore.la
