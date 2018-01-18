filegroup(
    name = "public",
    srcs = ["toxav.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "toxav",
    srcs = [
        "audio.c",
        "bwcontroller.c",
        "groupav.c",
        "msi.c",
        "ring_buffer.c",
        "rtp.c",
        "toxav.c",
        "toxav_old.c",
        "video.c",
    ],
    hdrs = [
        "audio.h",
        "bwcontroller.h",
        "groupav.h",
        "msi.h",
        "ring_buffer.h",
        "rtp.h",
        "toxav.api.h",
        "toxav.h",
        "video.h",
    ],
    copts = [
        "-std=c99",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//c-toxcore/toxcore",
        "@libvpx",
        "@opus",
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
