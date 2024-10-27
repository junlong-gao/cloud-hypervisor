load("@cloud_hypervisor//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

exports_files(
    srcs = [
        "Cargo.toml",
    ],
)

rust_library(
    name = "arch",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    visibility = ["//visibility:public"],  # Add this if not already present
    deps = all_crate_deps(normal = True) + [
        "//third_party/cloud_hypervisor/src/hypervisor",
    ],
)
