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
        "//third_party/cloud_hypervisor/src/block",
        "//third_party/cloud_hypervisor/src/event_monitor",
        "//third_party/cloud_hypervisor/src/net_gen",
        "//third_party/cloud_hypervisor/src/net_util",
        "//third_party/cloud_hypervisor/src/pci",
        "//third_party/cloud_hypervisor/src/rate_limiter",
        "//third_party/cloud_hypervisor/src/serial_buffer",
        "//third_party/cloud_hypervisor/src/vm-allocator",
        "//third_party/cloud_hypervisor/src/vm-device",
        "//third_party/cloud_hypervisor/src/vm-migration",
        "//third_party/cloud_hypervisor/src/vm-virtio",
    ],
)
