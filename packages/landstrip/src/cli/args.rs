// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::config::PolicyFormat;
#[allow(unused_imports)]
use crate::error::{Error, Mechanism};
#[cfg(target_os = "windows")]
use crate::platform::WindowsCommand;
#[cfg(unix)]
use crate::trap_fd::TrapFd;
use clap::builder::{PathBufValueParser, TypedValueParser};
use clap::{Args, Parser, Subcommand, error::ErrorKind};
use std::env;
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::num::NonZeroU16;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::str::FromStr;

const PROGRAM_NAME: &str = "landstrip";
#[cfg(target_os = "windows")]
const RESTRICTED_USER_RUNNER: &str = "landstrip-restricted-user-runner.exe";

#[derive(Debug)]
pub(super) struct Invocation {
    pub(super) debug: bool,
    pub(super) command: Command,
}

#[derive(Debug)]
pub(super) enum ParseOutcome {
    Invocation(Invocation),
    Display(clap::Error),
}

#[derive(Debug)]
pub(super) enum Command {
    Run(RunCommand),
    Check(PolicyRequest),
    Resolve(PolicyRequest),
    Doctor,
    #[cfg(target_os = "windows")]
    Windows(WindowsCommand),
    #[cfg(target_os = "windows")]
    Worker {
        request: PathBuf,
    },
}

#[derive(Debug)]
pub(super) struct RunCommand {
    pub(super) policy: PolicyInput,
    pub(super) cwd: PathBuf,
    #[cfg(unix)]
    pub(super) trap_fd: Option<TrapFd>,
    #[cfg(unix)]
    pub(super) inherited_fds: Vec<OwnedFd>,
    pub(super) tool: OsString,
    pub(super) tool_args: Vec<OsString>,
}

#[derive(Debug)]
pub(super) struct PolicyRequest {
    pub(super) policy: PolicyInput,
    pub(super) cwd: PathBuf,
    pub(super) tool: Option<OsString>,
}

#[derive(Debug, Args)]
pub(super) struct PolicyInput {
    /// Policy file; repeat to merge; use `-` for standard input.
    #[arg(short = 'p', long = "policy", value_name = "FILE", value_parser = parse_policy_path)]
    pub(super) paths: Vec<PathBuf>,

    /// Policy format. Required when a policy is read from standard input.
    #[arg(long = "policy-format", value_enum, value_name = "FORMAT")]
    format: Option<PolicyFormat>,
}

#[derive(Debug, Parser)]
#[command(
    name = PROGRAM_NAME,
    version,
    about = "OS-level sandbox runner",
)]
struct Cli {
    /// Enable debug logs.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Run a command inside the sandbox.
    Run(RunArgs),
    /// Check policy parsing, merging, resolution, and platform support.
    Check(PolicyRequestArgs),
    /// Print the final normalized policy as JSON.
    Resolve(PolicyRequestArgs),
    /// Verify that the current OS sandbox is operational and report capabilities.
    Doctor,
    #[cfg(target_os = "windows")]
    /// Manage Windows sandbox preparation and restricted-user provisioning.
    Windows(WindowsArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    policy: PolicyInput,

    /// Working directory for execution and relative path resolution.
    #[arg(
        long,
        value_name = "DIR",
        default_value = ".",
        value_parser = PathBufValueParser::new().try_map(std::path::absolute)
    )]
    cwd: PathBuf,

    #[cfg(unix)]
    /// Write traps to an already-open file descriptor.
    #[arg(long = "trap", value_name = "FD", value_parser = parse_fd)]
    trap_fd: Option<i32>,

    #[cfg(unix)]
    /// Preserve open descriptors across sandbox exec (grants access to those resources).
    #[arg(long = "inherit", value_name = "FD[,FD...]", value_delimiter = ',', value_parser = parse_fd)]
    inherited_fds: Vec<i32>,

    /// Program and arguments to run.
    #[arg(
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        value_name = "PROGRAM [ARGS...]"
    )]
    program: Vec<OsString>,
}

#[derive(Debug, Args)]
struct PolicyRequestArgs {
    #[command(flatten)]
    policy: PolicyInput,

    /// Working directory for execution and relative path resolution.
    #[arg(
        long,
        value_name = "DIR",
        default_value = ".",
        value_parser = PathBufValueParser::new().try_map(std::path::absolute)
    )]
    cwd: PathBuf,

    /// Include policy attached to this executable.
    #[arg(long, value_name = "PROGRAM")]
    tool: Option<OsString>,
}
#[cfg(target_os = "windows")]
#[derive(Debug, Args)]
struct WindowsArgs {
    #[command(subcommand)]
    command: WindowsAction,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Subcommand)]
enum WindowsAction {
    /// Install and activate restricted-user isolation.
    Install(WindowsInstallArgs),
    #[command(
        name = "prepare-appcontainer",
        about = "Grant AppContainer access to NUL and root directories (requests elevation)"
    )]
    PrepareAppContainer,
    /// Report the active Windows isolation implementation and its health.
    Status,
    /// Uninstall restricted-user isolation and return to `AppContainer`.
    Uninstall,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Args)]
struct WindowsInstallArgs {
    /// Restricted-network account pool size.
    #[arg(long, default_value_t = 8, value_parser = |v: &str| parse_count(v, 1, "restricted accounts"))]
    restricted_accounts: u16,

    /// Unrestricted-network account pool size.
    #[arg(long, default_value_t = 2, value_parser = |v: &str| parse_count(v, 0, "unrestricted accounts"))]
    unrestricted_accounts: u16,

    /// Permitted loopback proxy port range.
    #[arg(long, default_value = "60080-60111", value_name = "LOW-HIGH")]
    proxy_port_range: ProxyPortRange,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug)]
struct ProxyPortRange {
    low: u16,
    high: u16,
}

#[cfg(target_os = "windows")]
impl FromStr for ProxyPortRange {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (low, high) = value
            .split_once('-')
            .ok_or_else(|| "proxy port range must have the form LOW-HIGH".to_owned())?;
        let low = parse_port(low)?;
        let high = parse_port(high)?;
        if low > high {
            return Err("proxy port range must be ordered".to_owned());
        }
        if high - low > 64 {
            return Err("proxy port range may contain at most 65 ports".to_owned());
        }
        Ok(Self { low, high })
    }
}

pub(super) fn parse_cli() -> Result<ParseOutcome, Error> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_else(|| OsString::from(PROGRAM_NAME));
    let args = args.collect::<Vec<_>>();

    #[cfg(target_os = "windows")]
    if is_restricted_user_runner()? {
        return parse_worker(&args).map(ParseOutcome::Invocation);
    }

    parse_from(program, args)
}

fn parse_from(program: OsString, args: Vec<OsString>) -> Result<ParseOutcome, Error> {
    let cli = match Cli::try_parse_from(std::iter::once(program).chain(args)) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayVersion
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) =>
        {
            return Ok(ParseOutcome::Display(error));
        }
        Err(error) => {
            return Err(Error::Usage {
                message: error.to_string(),
            });
        }
    };

    let command = match cli.command {
        CliCommand::Run(args) => Command::Run(run_command(args)?),
        CliCommand::Check(args) => Command::Check(args.into()),
        CliCommand::Resolve(args) => Command::Resolve(args.into()),
        CliCommand::Doctor => Command::Doctor,
        #[cfg(target_os = "windows")]
        CliCommand::Windows(args) => Command::Windows(match args.command {
            WindowsAction::Install(args) => WindowsCommand::Install {
                restricted_accounts: args.restricted_accounts,
                unrestricted_accounts: args.unrestricted_accounts,
                proxy_port_low: args.proxy_port_range.low,
                proxy_port_high: args.proxy_port_range.high,
            },
            WindowsAction::PrepareAppContainer => WindowsCommand::PrepareAppContainer,
            WindowsAction::Status => WindowsCommand::Status,
            WindowsAction::Uninstall => WindowsCommand::Uninstall,
        }),
    };

    Ok(ParseOutcome::Invocation(Invocation {
        debug: cli.debug,
        command,
    }))
}

fn run_command(args: RunArgs) -> Result<RunCommand, Error> {
    let mut program = args.program.into_iter();
    let Some(tool) = program.next() else {
        return Err(Error::Usage {
            message: "a program is required".to_owned(),
        });
    };
    #[cfg(unix)]
    let inherited_fds = {
        let mut fds = args.inherited_fds;
        fds.sort_unstable();
        if fds.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Usage {
                message: "--inherit must not contain duplicate descriptors".to_owned(),
            });
        }
        if args.trap_fd.is_some_and(|fd| fds.contains(&fd)) {
            return Err(Error::Usage {
                message: "--inherit must not include --trap".to_owned(),
            });
        }
        fds.into_iter()
            .map(|fd| {
                // SAFETY: parse_fd validated this inherited descriptor. The
                // CLI owns it; duplicate and trap checks ensure unique ownership.
                unsafe { OwnedFd::from_raw_fd(fd) }
            })
            .collect()
    };
    Ok(RunCommand {
        policy: args.policy,
        cwd: args.cwd,
        #[cfg(unix)]
        trap_fd: args.trap_fd.map(|fd| {
            // SAFETY: parse_fd established that the inherited descriptor is open,
            // and `--trap` transfers its ownership to this process.
            TrapFd::from(unsafe { OwnedFd::from_raw_fd(fd) })
        }),
        #[cfg(unix)]
        inherited_fds,
        tool,
        tool_args: program.collect(),
    })
}

impl From<PolicyRequestArgs> for PolicyRequest {
    fn from(args: PolicyRequestArgs) -> Self {
        Self {
            policy: args.policy,
            cwd: args.cwd,
            tool: args.tool,
        }
    }
}

#[cfg(target_os = "windows")]
fn is_restricted_user_runner() -> Result<bool, Error> {
    let executable = env::current_exe()
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    Ok(executable
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(RESTRICTED_USER_RUNNER)))
}

#[cfg(target_os = "windows")]
fn parse_worker(args: &[OsString]) -> Result<Invocation, Error> {
    let [request] = args else {
        return Err(Error::Usage {
            message: "restricted-user runner requires one request path".to_owned(),
        });
    };
    Ok(Invocation {
        debug: false,
        command: Command::Worker {
            request: PathBuf::from(request),
        },
    })
}

fn parse_policy_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("policy path cannot be empty".to_owned());
    }
    Ok(PathBuf::from(path))
}

#[cfg(unix)]
fn parse_fd(value: &str) -> Result<i32, String> {
    let fd = value
        .parse::<i32>()
        .map_err(|_| "fd must be an integer greater than or equal to 3".to_owned())?;
    if fd < 3 {
        return Err("fd must be an integer greater than or equal to 3".to_owned());
    }

    // SAFETY: F_GETFD only inspects the scalar descriptor number.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!(
            "fd {fd} is not open: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(fd)
}

#[cfg(target_os = "windows")]
fn parse_count(value: &str, minimum: u16, name: &str) -> Result<u16, String> {
    let count = value
        .parse::<u16>()
        .map_err(|_| format!("{name} must be an integer between {minimum} and 64"))?;
    if !(minimum..=64).contains(&count) {
        return Err(format!("{name} must be between {minimum} and 64"));
    }
    Ok(count)
}

#[cfg(target_os = "windows")]
fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| "proxy ports must be integers between 1 and 65535".to_owned())?;
    NonZeroU16::new(port)
        .map(NonZeroU16::get)
        .ok_or_else(|| "proxy ports must be between 1 and 65535".to_owned())
}

impl TryFrom<&PolicyInput> for PolicyFormat {
    type Error = Error;

    fn try_from(input: &PolicyInput) -> Result<Self, Self::Error> {
        let stdin_count = input
            .paths
            .iter()
            .filter(|path| path.as_path() == Path::new("-"))
            .count();
        if stdin_count > 1 {
            return Err(Error::Usage {
                message: "standard input may be specified as a policy only once".to_owned(),
            });
        }
        if stdin_count == 1 && input.format.is_none() {
            return Err(Error::Usage {
                message: "--policy-format is required when --policy - is used".to_owned(),
            });
        }
        Ok(input.format.unwrap_or_default())
    }
}
