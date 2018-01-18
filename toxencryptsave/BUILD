filegroup(
    name = "public",
    srcs = ["toxencryptsave.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "toxencryptsave",
    srcs = [
        "toxencryptsave.c",
    ],
    hdrs = [
        "defines.h",
        "toxencryptsave.h",
    ],
    copts = [
        "-std=c99",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//c-toxcore/toxcore:crypto_core",
    ],
)

cc_library(
    name = "monolith",
    hdrs = glob([
        "*.c",
        "*.h",
    ]),
    visibility = ["//c-toxcore/other:__pkg__"],
)
