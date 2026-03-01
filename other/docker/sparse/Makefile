SOURCES		:= $(wildcard tox*/*.c tox*/*/*.c) \
		   third_party/cmp/cmp.c
OBJECTS		:= $(SOURCES:.c=.o)

CFLAGS		:= $(shell pkg-config --cflags libsodium opus vpx)
CPPFLAGS	:= -DSPARSE -DTCP_SERVER_USE_EPOLL=1 -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE

SPARSE_FLAGS	:=				\
	-Wsparse-error				\
	-Wpedantic				\
	-Waddress				\
	-Waddress-space				\
	-Wbitwise				\
	-Wbitwise-pointer			\
	-Wcast-from-as				\
	-Wcast-to-as				\
	-Wcast-truncate				\
	-Wconstant-suffix			\
	-Wconstexpr-not-const			\
	-Wcontext				\
	-Wdecl					\
	-Wdefault-bitfield-sign			\
	-Wdesignated-init			\
	-Wdo-while				\
	-Wenum-mismatch				\
	-Wexternal-function-has-definition	\
	-Wflexible-array-array			\
	-Wflexible-array-nested			\
	-Wflexible-array-union			\
	-Wimplicit-int				\
	-Winit-cstring				\
	-Wint-to-pointer-cast			\
	-Wmemcpy-max-count			\
	-Wnon-pointer-null			\
	-Wnewline-eof				\
	-Wold-initializer			\
	-Wold-style-definition			\
	-Wone-bit-signed-bitfield		\
	-Woverride-init				\
	-Woverride-init-all			\
	-Wparen-string				\
	-Wpast-deep-designator			\
	-Wpedantic				\
	-Wpointer-to-int-cast			\
	-Wptr-subtraction-blows			\
	-Wreturn-void				\
	-Wshadow				\
	-Wshift-count-negative			\
	-Wshift-count-overflow			\
	-Wsizeof-bool				\
	-Wstrict-prototypes			\
	-Wpointer-arith				\
	-Wsparse-error				\
	-Wtautological-compare			\
	-Wtransparent-union			\
	-Wtypesign				\
	-Wundef					\
	-Wuninitialized				\
	-Wunion-cast				\
	-Wvla

SMATCH_FLAGS := $(foreach i,$(shell smatch --show-checks | grep -o 'check_.*'),--enable=$i)

analyse: $(OBJECTS)

%.o: %.c
	@echo "Processing $<"
	@sparse $(CFLAGS) $(CPPFLAGS) $(SPARSE_FLAGS) $<
#	@smatch $(CFLAGS) $(CPPFLAGS) $(SMATCH_FLAGS) $<
#	@sparse-llvm $(CFLAGS) $(CPPFLAGS) $< > /dev/null
