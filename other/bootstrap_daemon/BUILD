cc_binary(
    name = "bootstrap_daemon",
    srcs = glob([
        "src/*.c",
        "src/*.h",
    ]),
    linkopts = ["-lconfig"],
    deps = [
        "//c-toxcore/other:bootstrap_node_packets",
        "//c-toxcore/toxcore",
    ],
)
