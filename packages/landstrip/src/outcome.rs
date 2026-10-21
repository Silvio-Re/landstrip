// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::policy::AccessPolicy;
use serde::Serialize;
use std::io::{self, Write};
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum SandboxImplementation {
    #[cfg(target_os = "linux")]
    #[serde(rename = "landlock+seccomp")]
    LandlockSeccomp,
    #[cfg(target_os = "macos")]
    #[serde(rename = "seatbelt")]
    Seatbelt,
    #[cfg(target_os = "windows")]
    #[serde(rename = "appContainer")]
    AppContainer,
    #[cfg(target_os = "windows")]
    #[serde(rename = "restrictedUser")]
    RestrictedUser,
}

impl SandboxImplementation {
    fn capabilities(self) -> FeatureCapabilities {
        let (unix_socket_filtering, process_isolation) = match self {
            #[cfg(target_os = "linux")]
            Self::LandlockSeccomp => (true, true),
            #[cfg(target_os = "macos")]
            Self::Seatbelt => (true, false),
            #[cfg(target_os = "windows")]
            Self::AppContainer | Self::RestrictedUser => (false, false),
        };
        FeatureCapabilities {
            filesystem_tiers: &[
                "allowWrite",
                "denyWrite",
                "allowRead",
                "denyRead",
                "denyReadAlways",
                "denyWriteAlways",
            ],
            network_mediation: true,
            unix_socket_filtering,
            process_isolation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PolicyValidationError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PolicyValidationReport {
    pub(crate) valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<PolicyValidationError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) ok: bool,
    pub(crate) platform: &'static str,
    pub(crate) implementation: SandboxImplementation,
    pub(crate) supported: FeatureCapabilities,
    pub(crate) available: FeatureCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

impl DoctorReport {
    pub(crate) fn new(implementation: SandboxImplementation, error: Option<String>) -> Self {
        let ok = error.is_none();
        let supported = implementation.capabilities();
        let available = if ok {
            supported
        } else {
            FeatureCapabilities::default()
        };
        Self {
            ok,
            platform: std::env::consts::OS,
            implementation,
            supported,
            available,
            error,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct FeatureCapabilities {
    pub(crate) filesystem_tiers: &'static [&'static str],
    pub(crate) network_mediation: bool,
    pub(crate) unix_socket_filtering: bool,
    pub(crate) process_isolation: bool,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WindowsStatusReport {
    pub(crate) active: SandboxImplementation,
    pub(crate) installed: bool,
    pub(crate) healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) restricted_accounts: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unrestricted_accounts: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proxy_port_low: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proxy_port_high: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) runner: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) runner_healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) accounts_healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[cfg(target_os = "windows")]
impl WindowsStatusReport {
    pub(crate) fn app_container(error: Option<String>) -> Self {
        Self {
            active: SandboxImplementation::AppContainer,
            installed: false,
            healthy: error.is_none(),
            version: None,
            complete: None,
            restricted_accounts: None,
            unrestricted_accounts: None,
            proxy_port_low: None,
            proxy_port_high: None,
            runner: None,
            runner_healthy: None,
            accounts_healthy: None,
            error,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CommandOutcome {
    Exit(i32),
    PolicyValidated(PolicyValidationReport),
    PolicyResolved(Box<AccessPolicy>),
    Doctor(DoctorReport),
    #[cfg(target_os = "windows")]
    Windows(WindowsStatusReport),
}

impl CommandOutcome {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Exit(code) => *code,
            Self::PolicyValidated(report) => i32::from(!report.valid),
            Self::Doctor(report) => i32::from(!report.ok),
            #[cfg(target_os = "windows")]
            Self::Windows(report) => i32::from(!report.healthy),
            Self::PolicyResolved(_) => 0,
        }
    }

    pub(crate) fn write_to(&self, mut output: impl Write) -> io::Result<()> {
        match self {
            Self::Exit(_) => return Ok(()),
            Self::PolicyValidated(report) => serde_json::to_writer(&mut output, report)?,
            Self::PolicyResolved(policy) => serde_json::to_writer(&mut output, policy)?,
            Self::Doctor(report) => serde_json::to_writer(&mut output, report)?,
            #[cfg(target_os = "windows")]
            Self::Windows(report) => serde_json::to_writer(&mut output, report)?,
        }
        writeln!(output)
    }
}

impl From<i32> for CommandOutcome {
    fn from(code: i32) -> Self {
        Self::Exit(code)
    }
}

impl From<PolicyValidationReport> for CommandOutcome {
    fn from(report: PolicyValidationReport) -> Self {
        Self::PolicyValidated(report)
    }
}

impl From<AccessPolicy> for CommandOutcome {
    fn from(policy: AccessPolicy) -> Self {
        Self::PolicyResolved(Box::new(policy))
    }
}

impl From<DoctorReport> for CommandOutcome {
    fn from(report: DoctorReport) -> Self {
        Self::Doctor(report)
    }
}

#[cfg(target_os = "windows")]
impl From<WindowsStatusReport> for CommandOutcome {
    fn from(report: WindowsStatusReport) -> Self {
        Self::Windows(report)
    }
}
