use std::env;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::mpsc::channel;
use std::sync::Mutex;

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use event_monitor::event;
use libc::EFD_NONBLOCK;
use log::{warn, LevelFilter};
use option_parser::OptionParser;
use seccompiler::SeccompAction;
use signal_hook::consts::SIGSYS;
use thiserror::Error;
#[cfg(feature = "dbus_api")]
use vmm::api::dbus::{dbus_api_graceful_shutdown, DBusApiOptions};
use vmm::api::http::http_api_graceful_shutdown;
use vmm::api::ApiAction;
use vmm::config::{RestoreConfig, VmParams};
use vmm::landlock::{Landlock, LandlockError};
use vmm::vm_config;
#[cfg(target_arch = "x86_64")]
use vmm::vm_config::SgxEpcConfig;
use vmm::vm_config::{
    BalloonConfig, DeviceConfig, DiskConfig, FsConfig, LandlockConfig, NetConfig, NumaConfig,
    PciSegmentConfig, PmemConfig, RateLimiterGroupConfig, TpmConfig, UserDeviceConfig, VdpaConfig,
    VmConfig, VsockConfig,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::block_signal;

pub fn prepare_default_values() -> (String, String, String) {
    (default_vcpus(), default_memory(), default_rng())
}

pub fn default_vcpus() -> String {
    format!(
        "boot={},max_phys_bits={}",
        vm_config::DEFAULT_VCPUS,
        vm_config::DEFAULT_MAX_PHYS_BITS
    )
}

pub fn default_memory() -> String {
    format!("size={}M", vm_config::DEFAULT_MEMORY_MB)
}

pub fn default_rng() -> String {
    format!("src={}", vm_config::DEFAULT_RNG_SOURCE)
}

pub struct Logger {
    output: Mutex<Box<dyn std::io::Write + Send>>,
    start: std::time::Instant,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = std::time::Instant::now();
        let duration = now.duration_since(self.start);

        if record.file().is_some() && record.line().is_some() {
            write!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:.6?}: <{}> {}:{}:{} -- {}\r\n",
                duration,
                std::thread::current().name().unwrap_or("anonymous"),
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            )
        } else {
            write!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:.6?}: <{}> {}:{} -- {}\r\n",
                duration,
                std::thread::current().name().unwrap_or("anonymous"),
                record.level(),
                record.target(),
                record.args()
            )
        }
        .ok();
    }
    fn flush(&self) {}
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create API EventFd: {0}")]
    CreateApiEventFd(#[source] std::io::Error),
    #[cfg(feature = "guest_debug")]
    #[error("Failed to create Debug EventFd: {0}")]
    CreateDebugEventFd(#[source] std::io::Error),
    #[error("Failed to create exit EventFd: {0}")]
    CreateExitEventFd(#[source] std::io::Error),
    #[error("Failed to open hypervisor interface (is hypervisor interface available?): {0}")]
    CreateHypervisor(#[source] hypervisor::HypervisorError),
    #[error("Failed to start the VMM thread: {0}")]
    StartVmmThread(#[source] vmm::Error),
    #[error("Error parsing config: {0}")]
    ParsingConfig(vmm::config::Error),
    #[error("Error creating VM: {0:?}")]
    VmCreate(vmm::api::ApiError),
    #[error("Error booting VM: {0:?}")]
    VmBoot(vmm::api::ApiError),
    #[error("Error restoring VM: {0:?}")]
    VmRestore(vmm::api::ApiError),
    #[error("Error parsing restore: {0}")]
    ParsingRestore(vmm::config::Error),
    #[error("Failed to join on VMM thread: {0:?}")]
    ThreadJoin(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    #[error("VMM thread exited with error: {0}")]
    VmmThread(#[source] vmm::Error),
    #[error("Error parsing --api-socket: {0}")]
    ParsingApiSocket(std::num::ParseIntError),
    #[error("Error parsing --event-monitor: {0}")]
    ParsingEventMonitor(option_parser::OptionParserError),
    #[cfg(feature = "dbus_api")]
    #[error("`--dbus-object-path` option isn't provided")]
    MissingDBusObjectPath,
    #[cfg(feature = "dbus_api")]
    #[error("`--dbus-service-name` option isn't provided")]
    MissingDBusServiceName,
    #[error("Error parsing --event-monitor: path or fd required")]
    BareEventMonitor,
    #[error("Error doing event monitor I/O: {0}")]
    EventMonitorIo(std::io::Error),
    #[error("Event monitor thread failed: {0}")]
    EventMonitorThread(#[source] vmm::Error),
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb: {0}")]
    ParsingGdb(option_parser::OptionParserError),
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb: path required")]
    BareGdb,
    #[error("Error creating log file: {0}")]
    LogFileCreation(std::io::Error),
    #[error("Error setting up logger: {0}")]
    LoggerSetup(log::SetLoggerError),
    #[error("Failed to gracefully shutdown http api: {0}")]
    HttpApiShutdown(#[source] vmm::Error),
    #[error("Failed to create Landlock object: {0}")]
    CreateLandlock(#[source] LandlockError),
    #[error("Failed to apply Landlock: {0}")]
    ApplyLandlock(#[source] LandlockError),
}

#[derive(Error, Debug)]
pub enum FdTableError {
    #[error("Failed to create event fd: {0}")]
    CreateEventFd(std::io::Error),
    #[error("Failed to obtain file limit: {0}")]
    GetRLimit(std::io::Error),
    #[error("Error calling fcntl with F_GETFD: {0}")]
    GetFd(std::io::Error),
    #[error("Failed to duplicate file handle: {0}")]
    Dup2(std::io::Error),
}

pub fn create_app(default_vcpus: String, default_memory: String, default_rng: String) -> Command {
    #[allow(clippy::let_and_return)]
    let app = Command::new("cloud-hypervisor")
        // 'BUILD_VERSION' is set by the build script 'build.rs' at
        // compile time
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("Launch a cloud-hypervisor VMM.")
        .arg_required_else_help(true)
        .group(ArgGroup::new("vm-config").multiple(true))
        .group(ArgGroup::new("vmm-config").multiple(true))
        .group(ArgGroup::new("logging").multiple(true))
        .arg(
            Arg::new("cpus")
                .long("cpus")
                .help(
                    "boot=<boot_vcpus>,max=<max_vcpus>,\
                    topology=<threads_per_core>:<cores_per_die>:<dies_per_package>:<packages>,\
                    kvm_hyperv=on|off,max_phys_bits=<maximum_number_of_physical_bits>,\
                    affinity=<list_of_vcpus_with_their_associated_cpuset>,\
                    features=<list_of_features_to_enable>",
                )
                .default_value(default_vcpus)
                .group("vm-config"),
        )
        .arg(
            Arg::new("platform")
                .long("platform")
                .help("num_pci_segments=<num_pci_segments>,iommu_segments=<list_of_segments>,serial_number=<dmi_device_serial_number>,uuid=<dmi_device_uuid>,oem_strings=<list_of_strings>")
                .num_args(1)
                .group("vm-config"),
        )
        .arg(
            Arg::new("memory")
                .long("memory")
                .help(
                    "Memory parameters \
                     \"size=<guest_memory_size>,mergeable=on|off,shared=on|off,\
                     hugepages=on|off,hugepage_size=<hugepage_size>,\
                     hotplug_method=acpi|virtio-mem,\
                     hotplug_size=<hotpluggable_memory_size>,\
                     hotplugged_size=<hotplugged_memory_size>,\
                     prefault=on|off,thp=on|off\"",
                )
                .default_value(default_memory)
                .group("vm-config"),
        )
        .arg(
            Arg::new("memory-zone")
                .long("memory-zone")
                .help(
                    "User defined memory zone parameters \
                     \"size=<guest_memory_region_size>,file=<backing_file>,\
                     shared=on|off,\
                     hugepages=on|off,hugepage_size=<hugepage_size>,\
                     host_numa_node=<node_id>,\
                     id=<zone_identifier>,hotplug_size=<hotpluggable_memory_size>,\
                     hotplugged_size=<hotplugged_memory_size>,\
                     prefault=on|off\"",
                )
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("firmware")
                .long("firmware")
                .help("Path to firmware that is loaded in an architectural specific way")
                .num_args(1)
                .group("vm-config"),
        )
        .arg(
            Arg::new("kernel")
                .long("kernel")
                .help(
                    "Path to kernel to load. This may be a kernel or firmware that supports a PVH \
                entry point (e.g. vmlinux) or architecture equivalent",
                )
                .num_args(1)
                .group("vm-config"),
        )
        .arg(
            Arg::new("initramfs")
                .long("initramfs")
                .help("Path to initramfs image")
                .num_args(1)
                .group("vm-config"),
        )
        .arg(
            Arg::new("cmdline")
                .long("cmdline")
                .help("Kernel command line")
                .num_args(1)
                .group("vm-config"),
        )
        .arg(
            Arg::new("rate-limit-group")
                .long("rate-limit-group")
                .help(RateLimiterGroupConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("disk")
                .long("disk")
                .help(DiskConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("landlock")
                .long("landlock")
                .num_args(0)
                .help(
                    "enable/disable Landlock.",
                )
                .action(ArgAction::SetTrue)
                .default_value("false")
                .group("vm-config"),
        )
        .arg(
            Arg::new("landlock-rules")
            .long("landlock-rules")
            .help(LandlockConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        )
        .arg(
            Arg::new("net")
                .long("net")
                .help(NetConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("rng")
                .long("rng")
                .help(
                    "Random number generator parameters \"src=<entropy_source_path>,iommu=on|off\"",
                )
                .default_value(default_rng)
                .group("vm-config"),
        )
        .arg(
            Arg::new("balloon")
                .long("balloon")
                .help(BalloonConfig::SYNTAX)
                .num_args(1)
                .group("vm-config"),
        )
        .arg(
            Arg::new("fs")
                .long("fs")
                .help(FsConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("pmem")
                .long("pmem")
                .help(PmemConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("serial")
                .long("serial")
                .help("Control serial port: off|null|pty|tty|file=</path/to/a/file>|socket=</path/to/a/file>")
                .default_value("null")
                .group("vm-config"),
        )
        .arg(
            Arg::new("console")
                .long("console")
                .help(
                    "Control (virtio) console: \"off|null|pty|tty|file=</path/to/a/file>,iommu=on|off\"",
                )
                .default_value("tty")
                .group("vm-config"),
        )
        .arg(
            Arg::new("device")
                .long("device")
                .help(DeviceConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("user-device")
                .long("user-device")
                .help(UserDeviceConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("vdpa")
                .long("vdpa")
                .help(VdpaConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("vsock")
                .long("vsock")
                .help(VsockConfig::SYNTAX)
                .num_args(1)
                .group("vm-config"),
        )
        .arg(
            Arg::new("pvpanic")
                .long("pvpanic")
                .help("Enable pvpanic device")
                .num_args(0)
                .action(ArgAction::SetTrue)
                .group("vm-config"),
        )
        .arg(
            Arg::new("numa")
                .long("numa")
                .help(NumaConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("pci-segment")
                .long("pci-segment")
                .help(PciSegmentConfig::SYNTAX)
                .num_args(1..)
                .group("vm-config"),
        )
        .arg(
            Arg::new("watchdog")
                .long("watchdog")
                .help("Enable virtio-watchdog")
                .num_args(0)
                .action(ArgAction::SetTrue)
                .group("vm-config"),
        )
        .arg(
            Arg::new("v")
                .short('v')
                .action(ArgAction::Count)
                .help("Sets the level of debugging output")
                .group("logging"),
        )
        .arg(
            Arg::new("log-file")
                .long("log-file")
                .help("Log file. Standard error is used if not specified")
                .num_args(1)
                .group("logging"),
        )
        .arg(
            Arg::new("api-socket")
                .long("api-socket")
                .help("HTTP API socket (UNIX domain socket): path=</path/to/a/file> or fd=<fd>.")
                .num_args(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::new("event-monitor")
                .long("event-monitor")
                .help("File to report events on: path=</path/to/a/file> or fd=<fd>")
                .num_args(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::new("restore")
                .long("restore")
                .help(RestoreConfig::SYNTAX)
                .num_args(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::new("seccomp")
                .long("seccomp")
                .num_args(1)
                .value_parser(["true", "false", "log"])
                .default_value("true"),
        )
        .arg(
            Arg::new("tpm")
                .long("tpm")
                .num_args(1)
                .help(TpmConfig::SYNTAX)
                .group("vmm-config"),
        );

    #[cfg(target_arch = "x86_64")]
    let app = app.arg(
        Arg::new("sgx-epc")
            .long("sgx-epc")
            .help(SgxEpcConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
    );

    #[cfg(target_arch = "x86_64")]
    let app = app.arg(
        Arg::new("debug-console")
            .long("debug-console")
            .help("Debug console: off|pty|tty|file=</path/to/a/file>,iobase=<port in hex>")
            .default_value("off,iobase=0xe9")
            .group("vm-config"),
    );

    #[cfg(feature = "guest_debug")]
    let app = app.arg(
        Arg::new("gdb")
            .long("gdb")
            .help("GDB socket (UNIX domain socket): path=</path/to/a/file>")
            .num_args(1)
            .group("vmm-config"),
    );

    #[cfg(feature = "dbus_api")]
    let app = app
        .arg(
            Arg::new("dbus-service-name")
                .long("dbus-service-name")
                .help("Well known name of the device")
                .num_args(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::new("dbus-object-path")
                .long("dbus-object-path")
                .help("Object path to serve the dbus interface")
                .num_args(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::new("dbus-system-bus")
                .long("dbus-system-bus")
                .action(ArgAction::SetTrue)
                .help("Use the system bus instead of a session bus")
                .num_args(0)
                .group("vmm-config"),
        );
    #[cfg(feature = "igvm")]
    let app = app.arg(
        Arg::new("igvm")
            .long("igvm")
            .help("Path to IGVM file to load.")
            .num_args(1)
            .group("vm-config"),
    );
    #[cfg(feature = "sev_snp")]
    let app = app.arg(
        Arg::new("host-data")
            .long("host-data")
            .help("Host specific data to SEV SNP guest")
            .num_args(1)
            .group("vm-config"),
    );
    #[cfg(feature = "pvmemcontrol")]
    let app = app.arg(
        Arg::new("pvmemcontrol")
            .long("pvmemcontrol")
            .help("Pvmemcontrol device")
            .num_args(0)
            .action(ArgAction::SetTrue)
            .group("vm-config"),
    );

    app.arg(
        Arg::new("version")
            .short('V')
            .long("version")
            .action(ArgAction::SetTrue)
            .help("Print version")
            .num_args(0),
    )
}

pub fn start_vmm(cmd_arguments: ArgMatches) -> Result<Option<String>, Error> {
    let log_level = match cmd_arguments.get_count("v") {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let log_file: Box<dyn std::io::Write + Send> = if let Some(ref file) =
        cmd_arguments.get_one::<String>("log-file")
    {
        Box::new(std::fs::File::create(std::path::Path::new(file)).map_err(Error::LogFileCreation)?)
    } else {
        Box::new(std::io::stderr())
    };

    log::set_boxed_logger(Box::new(Logger {
        output: Mutex::new(log_file),
        start: std::time::Instant::now(),
    }))
    .map(|()| log::set_max_level(log_level))
    .map_err(Error::LoggerSetup)?;

    let (api_socket_path, api_socket_fd) =
        if let Some(socket_config) = cmd_arguments.get_one::<String>("api-socket") {
            let mut parser = OptionParser::new();
            parser.add("path").add("fd");
            parser.parse(socket_config).unwrap_or_default();

            if let Some(fd) = parser.get("fd") {
                (
                    None,
                    Some(fd.parse::<RawFd>().map_err(Error::ParsingApiSocket)?),
                )
            } else if let Some(path) = parser.get("path") {
                (Some(path), None)
            } else {
                (
                    cmd_arguments
                        .get_one::<String>("api-socket")
                        .map(|s| s.to_string()),
                    None,
                )
            }
        } else {
            (None, None)
        };

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateApiEventFd)?;

    let api_request_sender_clone = api_request_sender.clone();
    let seccomp_action = if let Some(seccomp_value) = cmd_arguments.get_one::<String>("seccomp") {
        match seccomp_value as &str {
            "true" => SeccompAction::Trap,
            "false" => SeccompAction::Allow,
            "log" => SeccompAction::Log,
            val => {
                // The user providing an invalid value will be rejected
                panic!("Invalid parameter {val} for \"--seccomp\" flag");
            }
        }
    } else {
        SeccompAction::Trap
    };

    if seccomp_action == SeccompAction::Trap {
        // SAFETY: We only using signal_hook for managing signals and only execute signal
        // handler safe functions (writing to stderr) and manipulating signals.
        unsafe {
            signal_hook::low_level::register(signal_hook::consts::SIGSYS, || {
                eprint!(
                    "\n==== Possible seccomp violation ====\n\
                Try running with `strace -ff` to identify the cause and open an issue: \
                https://github.com/cloud-hypervisor/cloud-hypervisor/issues/new\n"
                );
                signal_hook::low_level::emulate_default_handler(SIGSYS).unwrap();
            })
        }
        .map_err(|e| eprintln!("Error adding SIGSYS signal handler: {e}"))
        .ok();
    }

    // SAFETY: Trivially safe.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }

    // Before we start any threads, mask the signals we'll be
    // installing handlers for, to make sure they only ever run on the
    // dedicated signal handling thread we'll start in a bit.
    for sig in &vmm::vm::Vm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            eprintln!("Error blocking signals: {e}");
        }
    }

    for sig in &vmm::Vmm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            eprintln!("Error blocking signals: {e}");
        }
    }

    let hypervisor = hypervisor::new().map_err(Error::CreateHypervisor)?;

    #[cfg(feature = "guest_debug")]
    let gdb_socket_path = if let Some(gdb_config) = cmd_arguments.get_one::<String>("gdb") {
        let mut parser = OptionParser::new();
        parser.add("path");
        parser.parse(gdb_config).map_err(Error::ParsingGdb)?;

        if parser.is_set("path") {
            Some(std::path::PathBuf::from(parser.get("path").unwrap()))
        } else {
            return Err(Error::BareGdb);
        }
    } else {
        None
    };
    #[cfg(feature = "guest_debug")]
    let debug_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateDebugEventFd)?;
    #[cfg(feature = "guest_debug")]
    let vm_debug_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateDebugEventFd)?;

    let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateExitEventFd)?;
    let landlock_enable = cmd_arguments.get_flag("landlock");

    #[allow(unused_mut)]
    let mut event_monitor = cmd_arguments
        .get_one::<String>("event-monitor")
        .as_ref()
        .map(|monitor_config| {
            let mut parser = OptionParser::new();
            parser.add("path").add("fd");
            parser
                .parse(monitor_config)
                .map_err(Error::ParsingEventMonitor)?;

            if parser.is_set("fd") {
                let fd = parser
                    .convert("fd")
                    .map_err(Error::ParsingEventMonitor)?
                    .unwrap();
                // SAFETY: fd is valid
                Ok(Some(unsafe { File::from_raw_fd(fd) }))
            } else if parser.is_set("path") {
                Ok(Some(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(parser.get("path").unwrap())
                        .map_err(Error::EventMonitorIo)?,
                ))
            } else {
                Err(Error::BareEventMonitor)
            }
        })
        .transpose()?
        .map(|event_monitor_file| {
            event_monitor::set_monitor(event_monitor_file).map_err(Error::EventMonitorIo)
        })
        .transpose()?;

    #[cfg(feature = "dbus_api")]
    let dbus_options = match (
        cmd_arguments.get_one::<String>("dbus-service-name"),
        cmd_arguments.get_one::<String>("dbus-object-path"),
    ) {
        (Some(name), Some(path)) => {
            // monitor is either set (file based) or not.
            // if it's not set, create one without file support.
            let mut monitor = match event_monitor.take() {
                Some(monitor) => monitor,
                None => event_monitor::set_monitor(None).map_err(Error::EventMonitorIo)?,
            };
            let options = DBusApiOptions {
                service_name: name.to_string(),
                object_path: path.to_string(),
                system_bus: cmd_arguments.get_flag("dbus-system-bus"),
                event_monitor_rx: monitor.subscribe(),
            };

            event_monitor = Some(monitor);
            Ok(Some(options))
        }
        (Some(_), None) => Err(Error::MissingDBusObjectPath),
        (None, Some(_)) => Err(Error::MissingDBusServiceName),
        (None, None) => Ok(None),
    }?;

    if let Some(monitor) = event_monitor {
        vmm::start_event_monitor_thread(
            monitor,
            &seccomp_action,
            landlock_enable,
            hypervisor.hypervisor_type(),
            exit_evt.try_clone().unwrap(),
        )
        .map_err(Error::EventMonitorThread)?;
    }

    event!("vmm", "starting");

    let vmm_thread_handle = vmm::start_vmm_thread(
        vmm::VmmVersionInfo::new(env!("BUILD_VERSION"), env!("CARGO_PKG_VERSION")),
        &api_socket_path,
        api_socket_fd,
        #[cfg(feature = "dbus_api")]
        dbus_options,
        api_evt.try_clone().unwrap(),
        api_request_sender_clone,
        api_request_receiver,
        #[cfg(feature = "guest_debug")]
        gdb_socket_path,
        #[cfg(feature = "guest_debug")]
        debug_evt.try_clone().unwrap(),
        #[cfg(feature = "guest_debug")]
        vm_debug_evt.try_clone().unwrap(),
        exit_evt.try_clone().unwrap(),
        &seccomp_action,
        hypervisor,
        landlock_enable,
    )
    .map_err(Error::StartVmmThread)?;

    let r: Result<(), Error> = (|| {
        #[cfg(feature = "igvm")]
        let payload_present = cmd_arguments.contains_id("kernel")
            || cmd_arguments.contains_id("firmware")
            || cmd_arguments.contains_id("igvm");
        #[cfg(not(feature = "igvm"))]
        let payload_present =
            cmd_arguments.contains_id("kernel") || cmd_arguments.contains_id("firmware");

        if payload_present {
            let vm_params = VmParams::from_arg_matches(&cmd_arguments);
            let vm_config = VmConfig::parse(vm_params).map_err(Error::ParsingConfig)?;

            // Create and boot the VM based off the VM config we just built.
            let sender = api_request_sender.clone();
            vmm::api::VmCreate
                .send(
                    api_evt.try_clone().unwrap(),
                    api_request_sender,
                    Box::new(vm_config),
                )
                .map_err(Error::VmCreate)?;
            vmm::api::VmBoot
                .send(api_evt.try_clone().unwrap(), sender, ())
                .map_err(Error::VmBoot)?;
        } else if let Some(restore_params) = cmd_arguments.get_one::<String>("restore") {
            vmm::api::VmRestore
                .send(
                    api_evt.try_clone().unwrap(),
                    api_request_sender,
                    RestoreConfig::parse(restore_params).map_err(Error::ParsingRestore)?,
                )
                .map_err(Error::VmRestore)?;
        }

        Ok(())
    })();

    if r.is_err() {
        if let Err(e) = exit_evt.write(1) {
            warn!("writing to exit EventFd: {e}");
        }
    }

    if landlock_enable {
        Landlock::new()
            .map_err(Error::CreateLandlock)?
            .restrict_self()
            .map_err(Error::ApplyLandlock)?;
    }

    vmm_thread_handle
        .thread_handle
        .join()
        .map_err(Error::ThreadJoin)?
        .map_err(Error::VmmThread)?;

    if let Some(api_handle) = vmm_thread_handle.http_api_handle {
        http_api_graceful_shutdown(api_handle).map_err(Error::HttpApiShutdown)?
    }

    #[cfg(feature = "dbus_api")]
    if let Some(chs) = vmm_thread_handle.dbus_shutdown_chs {
        dbus_api_graceful_shutdown(chs);
    }

    r.map(|_| api_socket_path)
}
