FROM toxchat/c-toxcore:sources AS sources
FROM toxchat/infer:latest

COPY --from=sources /src/ /work/c-toxcore/
RUN infer capture -- clang++ -fsyntax-only \
  $(pkg-config --cflags libconfig libsodium opus vpx) \
  /work/c-toxcore/toxav/*.c \
  /work/c-toxcore/toxcore/*.c \
  /work/c-toxcore/toxcore/*/*.c \
  /work/c-toxcore/toxencryptsave/*.c
RUN ["infer", "analyze",\
 "--report-console-limit", "100",\
 "--jobs", "8",\
 "--no-bufferoverrun",\
 "--no-datalog",\
 "--print-active-checkers",\
 "--loop-hoisting",\
 "--quandary",\
 "--racerd",\
 "--starvation",\
 "--uninit",\
 "--disable-issue-type", "BUFFER_OVERRUN_L2",\
 "--disable-issue-type", "PULSE_UNNECESSARY_COPY",\
 "--enable-issue-type", "EXPENSIVE_EXECUTION_TIME",\
 "--enable-issue-type", "INVARIANT_CALL",\
 "--enable-issue-type", "PULSE_UNINITIALIZED_CONST",\
 "--enable-issue-type", "SENSITIVE_DATA_FLOW",\
 "--enable-issue-type", "UNTRUSTED_BUFFER_ACCESS",\
 "--enable-issue-type", "UNTRUSTED_HEAP_ALLOCATION",\
 "--disable-issue-type", "USE_AFTER_FREE_LATENT",\
 "--disable-issue-type", "STACK_VARIABLE_ADDRESS_ESCAPE",\
 "--disable-issue-type", "INVARIANT_CALL",\
 "--fail-on-issue"]
# In the above, the first 2 are disabled for extreme sensitivity and false
# positives, the ones at the end are probably decent, but have some false
# positives, so we can't fail-on-issue with them on.
# INVARIANT_CALL is pretty fun, but currently wrong, because it can't see
# through potential mutations via callbacks. Our code is bad and we should
# feel bad, but until that's fixed, the invariant checker doesn't work.
