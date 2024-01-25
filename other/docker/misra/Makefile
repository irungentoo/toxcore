# See the following PDF for descriptions of each of the rules:
# http://my.ldrasoftware.co.uk/repository/miscellaneous/Misra-c_2012_compliance.pdf

# There should be no unused parameters in functions.
#
# Reason: callbacks often have unused parameters. Marking them explicitly isn't
# very helpful. A better diagnostic should be able to identify functions never
# used as callbacks and warn about unused parameters in those.
SUPPRESSIONS = 2.7
# The character sequences /* and // shall not be used within a comment.
#
# Reason: "//" appears in code examples and "http://" inside comments.
SUPPRESSIONS += 3.1
# Identifiers declared in the same scope and name space shall be distinct.
# Identifier not unique within 31 characters.
#
# Reason: Compilers we use allow longer identifier names.
SUPPRESSIONS += 5.2
# Macro identifiers shall be distinct.
# Identifier matches macro name in 31 chars.
#
# Reason: Compilers we use allow longer identifier names.
SUPPRESSIONS += 5.4
# The lowercase character 'l' shall not be used in a literal suffix.
#
# Reason: False positive. We don't use 'l', but this flags 'ulOutBufLen'.
SUPPRESSIONS += 7.3
# Operands shall not be of an inappropriate essential type.
#
# Reason: This diagnoses (1 << n) and wants us to use (1u << n). That's fair,
# but this diagnostic is impossible to fix for ((1u << n) >> m).
SUPPRESSIONS += 10.1
# Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category.
#
# Reason: This warns about ((unsigned)n == 0) and other constant comparisons.
SUPPRESSIONS += 10.4
# The value of a composite expression shall not be cast to a different essential type category or a wider essential type.
#
# TODO(iphydf): investigate.
SUPPRESSIONS += 10.8
# A conversion should not be performed from pointer to void into pointer to object.
#
# Reason: this is needed for generic callbacks to make any sense.
SUPPRESSIONS += 11.5
# The precedence of operators within expressions should be made explicit.
#
# Reason: this asks us to add a lot of extra parentheses that don't really help
# readability. We expect people to know basic precedence. GCC has a better
# diagnostic requiring parentheses around less common operators.
SUPPRESSIONS += 12.1
# The comma operator should not be used.
#
# Reason: We don't use the comma operator (cimple doesn't even parse it). This is
# all false positives.
SUPPRESSIONS += 12.3
# Evaluation of constant expressions should not lead to unsigned integer wrap-around.
#
# Reason: False positives on UINT64_MAX.
SUPPRESSIONS += 12.4
# A full expression containing an increment (++) or decrement (--) operator should have no other potential side effects other than that caused by the increment or decrement operator.
#
# TODO(iphydf): maybe fix?
SUPPRESSIONS += 13.3
# The controlling expression of an if statement and the controlling expression of an iteration-statement shall have essentially Boolean type.
#
# Reason: We actually follow this rule, but cppcheck's implementation is flawed and has false positives.
SUPPRESSIONS += 14.4
# The goto statement should not be used.
#
# TODO(iphydf): Get rid of goto.
SUPPRESSIONS += 15.1
# A function should have a single point of exit at the end.
#
# Reason: This doesn't make code much clearer. Sometimes this is useful for
# putting all the cleanup code in one spot, but often an early return improves
# readability.
SUPPRESSIONS += 15.5
# All if . . else if constructs shall be terminated with an else statement.
#
# TODO(iphydf): Why is this a good idea?
SUPPRESSIONS += 15.7
# An unconditional break statement shall terminate every switch-clause.
#
# Reason: This conflicts with "break unused after abort()". MISRA doesn't allow
# abort(), but we use it, so this rule must be disabled, too.
SUPPRESSIONS += 16.3
# Every switch statement shall have a default label.
#
# Reason: C compilers have better diagnostics for this (-Wswitch variants).
SUPPRESSIONS += 16.4
# The features of <stdarg.h> shall not be used.
#
# Reason: We use it for logging.
SUPPRESSIONS += 17.1
# Functions shall not call themselves, either directly or indirectly.
#
# Reason: Cimple is better at this diagnostic, recognising indirect recursion
# through callbacks.
SUPPRESSIONS += 17.2
# The value returned by a function having non-void return type shall be used.
#
# TODO(iphydf): Investigate.
SUPPRESSIONS += 17.7
# A function parameter should not be modified.
#
# TODO(iphydf): maybe fix?
SUPPRESSIONS += 17.8
# The +, -, += and -= operators should not be applied to an expression of pointer type.
# Use of pointer arithmetic.
#
# TODO(iphydf): Someday we won't be using pointer arithmetic.
SUPPRESSIONS += 18.4
# Flexible array members shall not be declared.
#
# TODO(iphydf): Fix.
SUPPRESSIONS += 18.7
# Variable-length array types shall not be used.
#
# TODO(iphydf): Fix.
SUPPRESSIONS += 18.8
# The union keyword should not be used.
#
# TODO(iphydf): Maybe we need a good linter to check that unions are used safely.
SUPPRESSIONS += 19.2
# #undef should not be used.
#
# Reason: We believe it should be used when #define is used in block scope.
SUPPRESSIONS += 20.5
# #define and #undef shall not be used on a reserved identifier or reserved macro name.
#
# Reason: Needed for feature test macros like _DEFAULT_SOURCE.
SUPPRESSIONS += 21.1
# The memory allocation and deallocation functions of <stdlib.h> shall not be used.
#
# Reason: We use malloc/free. Making our own allocators doesn't make the code
# safer.
SUPPRESSIONS += 21.3
# The Standard Library input/output routines shall not be used.
#
# Reason: Used in logging.
SUPPRESSIONS += 21.6
# The Standard Library termination functions of <stdlib.h> shall not be used.
# Use of abort, exit, etc.
#
# Reason: Used in LOGGER_FATAL.
SUPPRESSIONS += 21.8
# The Standard Library functions bsearch and qsort of <stdlib.h> shall not be used.
#
# TODO(iphydf): Why not use qsort?
SUPPRESSIONS += 21.9
# The Standard Library time and date routines shall not be used.
#
# TODO(iphydf): Probably stop using time().
SUPPRESSIONS += 21.10

CPPFLAGS := -DCMP_NO_FLOAT=1 -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE

FIND_FLAGS := -name "*.c"								\
			  -and -not -wholename "*/auto_tests/*"		\
			  -and -not -wholename "*/other/*"			\
			  -and -not -wholename "*/super_donators/*"	\
			  -and -not -wholename "*/third_party/*"
SOURCES := $(shell find /src/workspace/c-toxcore $(FIND_FLAGS))

analyse: $(DUMPS:.dump=.diag)
	cppcheck --error-exitcode=1 -j8 --addon=misra --suppress=doubleFree $(patsubst %,--suppress=misra-c2012-%,$(SUPPRESSIONS)) $(CPPFLAGS) $(SOURCES)
