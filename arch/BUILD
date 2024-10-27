load("@cloud_hypervisor//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name = "arch",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    visibility = ["//visibility:public"],  # Add this if not already present
    deps = all_crate_deps(normal = True) + [
        "//hypervisor",
    ],
)
