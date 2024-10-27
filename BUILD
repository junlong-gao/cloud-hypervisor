load("@cloud_hypervisor//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")

exports_files(
    srcs = [
        "Cargo.lock",
        "Cargo.toml",
    ],
)

rust_library(
    name = "lib",
    srcs = ["src/lib.rs"],
    aliases = aliases(),
    crate_features = ["kvm"],
    rustc_env = {
        "CARGO_BIN_NAME": "cloud-hypervisor",
        "BUILD_VERSION": "b5d856b31a98ad81f4ada75bab410c3ec737cec5",
    },
    rustc_flags = [
        "-C",
        "opt-level=s",
        "-C",
        "lto=true",
        "-C",
        "codegen-units=1",
    ],
    visibility = ["//visibility:public"],  # Add this if not already present
    deps = all_crate_deps(normal = True) + [
        "//third_party/cloud_hypervisor/src/api_client",
        "//third_party/cloud_hypervisor/src/event_monitor",
        "//third_party/cloud_hypervisor/src/hypervisor",
        "//third_party/cloud_hypervisor/src/net_util",
        "//third_party/cloud_hypervisor/src/option_parser",
        "//third_party/cloud_hypervisor/src/tpm",
        "//third_party/cloud_hypervisor/src/tracer",
        "//third_party/cloud_hypervisor/src/vmm",
    ],
)

rust_binary(
    name = "cloud_hypervisor",
    srcs = [
        "src/main.rs",
    ],
    aliases = aliases(),
    crate_features = ["kvm"],
    rustc_env = {
        "CARGO_BIN_NAME": "cloud-hypervisor",
        "BUILD_VERSION": "b5d856b31a98ad81f4ada75bab410c3ec737cec5",
    },
    rustc_flags = [
        "-C",
        "opt-level=s",
        "-C",
        "lto=true",
        "-C",
        "codegen-units=1",
    ],
    visibility = ["//visibility:public"],  # Add this if not already present
    deps = all_crate_deps(normal = True) + [
        ":lib",
        "//third_party/cloud_hypervisor/src/api_client",
        "//third_party/cloud_hypervisor/src/event_monitor",
        "//third_party/cloud_hypervisor/src/hypervisor",
        "//third_party/cloud_hypervisor/src/net_util",
        "//third_party/cloud_hypervisor/src/option_parser",
        "//third_party/cloud_hypervisor/src/tpm",
        "//third_party/cloud_hypervisor/src/tracer",
        "//third_party/cloud_hypervisor/src/vmm",
    ],
)
