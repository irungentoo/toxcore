load("//tools:no_undefined.bzl", "cc_library")

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
        "-Wno-parentheses",
        "-Wno-sign-compare",
    ],
    deps = [
        ":helpers",
        "//c-toxcore/other:monolith",
        "//c-toxcore/testing:misc_tools",
        "//c-toxcore/toxav",
        "//c-toxcore/toxcore",
        "//c-toxcore/toxencryptsave",
        "@check",
    ],
) for src in glob(["*_test.c*"])]
