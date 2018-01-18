genrule(
    name = "copy_headers",
    srcs = [
        "//c-toxcore/toxav:public",
        "//c-toxcore/toxcore:public",
        "//c-toxcore/toxencryptsave:public",
    ],
    outs = [
        "tox/toxav.h",
        "tox/tox.h",
        "tox/toxencryptsave.h",
    ],
    cmd = """
        cp $(location //c-toxcore/toxav:public) $(GENDIR)/c-toxcore/tox/toxav.h
        cp $(location //c-toxcore/toxcore:public) $(GENDIR)/c-toxcore/tox/tox.h
        cp $(location //c-toxcore/toxencryptsave:public) $(GENDIR)/c-toxcore/tox/toxencryptsave.h
    """,
)

cc_library(
    name = "headers",
    hdrs = [
        "tox/tox.h",
        "tox/toxav.h",
        "tox/toxencryptsave.h",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
)
