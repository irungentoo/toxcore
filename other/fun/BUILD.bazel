cc_binary(
    name = "cracker",
    srcs = ["cracker.c"],
    deps = [
        "//c-toxcore/testing:misc_tools",
        "@libsodium",
    ],
)

cc_binary(
    name = "sign",
    srcs = ["sign.c"],
    deps = [
        "//c-toxcore/testing:misc_tools",
        "@libsodium",
    ],
    copts = ["-w"],
)

cc_binary(
    name = "strkey",
    srcs = ["strkey.c"],
    deps = [
        "@libsodium",
    ],
    copts = ["-w"],
)
