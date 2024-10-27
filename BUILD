load("@cloud_hypervisor//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "cloud_hypervisor",
    srcs = glob(["src/**/*.rs"]),
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
        "//api_client",
        "//event_monitor",
        "//hypervisor",
        "//net_util",
        "//option_parser",
        "//tpm",
        "//tracer",
        "//vmm",
    ],
)
