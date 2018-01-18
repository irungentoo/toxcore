cc_library(
    name = "helpers",
    testonly = True,
    hdrs = [
        "check_compat.h",
        "helpers.h",
    ],
)

[cc_test(
    name = src[:-2],
    size = "small",
    srcs = [src],
    copts = [
        "-std=c99",
        "-Wno-parentheses",
    ],
    deps = [
        ":helpers",
        "//c-toxcore/other:monolith",
        "//c-toxcore/testing:misc_tools",
        "//c-toxcore/toxav",
        "//c-toxcore/toxcore",
        "@check",
    ],
) for src in glob(["*_test.c"])]
