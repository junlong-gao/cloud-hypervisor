load("@cloud_hypervisor//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name = "virtio-devices",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    proc_macro_deps = all_crate_deps(
        proc_macro = True,
    ),
    visibility = ["//visibility:public"],  # Add this if not already present
    deps = all_crate_deps(normal = True) + [
        "//block",
        "//event_monitor",
        "//net_gen",
        "//net_util",
        "//pci",
        "//rate_limiter",
        "//serial_buffer",
        "//vm-allocator",
        "//vm-device",
        "//vm-migration",
        "//vm-virtio",
    ],
)
