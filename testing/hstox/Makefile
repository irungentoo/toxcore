# Don't bind to a CPU core. afl-fuzz doesn't release them again.
export AFL_NO_AFFINITY := 1

CFLAGS	:=					\
	-std=gnu99				\
	-Wall					\
	-g3					\
	-DCONFIGURED=1				\
	-Imsgpack-c/include			\
	-I../../toxcore				\

LDFLAGS	:= -pthread -lsodium
ifeq ($(shell echo 'int main(){}' | $(CC) -lrt -xc -o /dev/null - && echo true),true)
LDFLAGS	+= -lrt
endif

SOURCES	:= $(filter-out %_main.c,$(wildcard *.c msgpack-c/src/*.c ../../toxcore/*.c))
HEADERS := $(shell find . -name "*.h")

ifeq ($(wildcard test-findings/master/fuzzer_stats),)
TEST_INPUTS := test-inputs
else
TEST_INPUTS := -
endif

# All the possible test flavours.
PROGRAMS :=			\
	test_main-cov		\
	test_main-cov-asan	\
	test_main-vanilla	\
	test_main-vanilla-asan

ifneq ($(shell which afl-clang),)
AFL_CLANG := afl-clang
endif

ifneq ($(shell which afl-clang-fast),)
AFL_CLANG := afl-clang-fast
endif

ifneq ($(AFL_CLANG),)
PROGRAMS +=			\
	fuzz_main-afl		\
	fuzz_main-afl-asan
endif

all: $(PROGRAMS)

check: test_main-sut
	./$< ./$<

master: fuzz_main-afl test-findings
	afl-fuzz -i$(TEST_INPUTS) -o test-findings -M master ./$<

slave%: fuzz_main-afl test-findings
	afl-fuzz -i test-inputs -o test-findings -S slave$* ./$<

%-afl: %.c $(SOURCES) $(HEADERS)
	$(AFL_CLANG) $(CFLAGS) -O3 $(filter %.c,$^) $(LDFLAGS) -o $@

%-afl-asan: %.c $(SOURCES) $(HEADERS)
	$(AFL_CLANG) $(CFLAGS) -O3 -fsanitize=address $(filter %.c,$^) $(LDFLAGS) -o $@

%-cov: %.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage $(filter %.c,$^) $(LDFLAGS) -o $@

%-cov-asan: %.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage -fsanitize=address $(filter %.c,$^) $(LDFLAGS) -o $@

%-vanilla: %.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) -o $@

%-vanilla-asan: %.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -fsanitize=address $(filter %.c,$^) $(LDFLAGS) -o $@

%-sut: toxcore-sut.hs %.c $(SOURCES) $(HEADERS)
	ghc -package hstox $<				\
		$(filter %.c,$^)			\
		$(foreach f,$(CFLAGS),-optc $f)		\
		$(foreach f,$(LDFLAGS),-optl $f)	\
		-o $@

ifneq ($(wildcard /Volumes),)
test-findings: /Volumes/RAM\ Disk
	mkdir -p "$</$@"
	ln -sf "$</$@" $@

/Volumes/RAM\ Disk:
	diskutil erasevolume HFS+ 'RAM Disk' `hdiutil attach -nomount ram://204800`
else
test-findings: /dev/shm
	mkdir -p "$</$@"
	test -d $@ || ln -sf "$</$@" $@
endif

clean:
	rm -rf $(wildcard *_main-* *.dSYM *.gcno *.gcda *.o *.hi test-findings/*)
