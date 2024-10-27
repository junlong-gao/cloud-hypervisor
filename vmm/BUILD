load("@cloud_hypervisor//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name = "vmm",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    crate_features = ["kvm"],
    proc_macro_deps = all_crate_deps(
        proc_macro = True,
    ),
    visibility = ["//visibility:public"],  # Add this if not already present
    deps = all_crate_deps(normal = True) + [
        "//arch",
        "//block",
        "//devices",
        "//event_monitor",
        "//hypervisor",
        "//net_util",
        "//option_parser",
        "//pci",
        "//rate_limiter",
        "//serial_buffer",
        "//tracer",
        "//virtio-devices",
        "//vm-allocator",
        "//vm-device",
        "//vm-migration",
        "//vm-virtio",
    ],
)
