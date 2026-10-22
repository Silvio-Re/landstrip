// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! macOS Seatbelt (SBPL) sandbox platform.

use super::unix::close_inherited_fds;
use crate::config::SandboxDarwin;
use crate::error::Error;
use crate::paths::PathCoverage;
use crate::policy::{AccessPolicy, GlobPattern, NetworkAccess, ReadAccess, UnixSocketAccess};
use crate::trap_fd::TrapFd;
use anyhow::Result;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::{self, Write};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const SBPL_PROFILE_FLAGS: u64 = 0;
const SANDBOX_FILTER_NONE: libc::c_int = 0;

pub(crate) fn execute(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: Option<&TrapFd>,
    inherited_fds: &[std::os::fd::RawFd],
) -> Result<i32> {
    let profile = render_profile(policy).map_err(Error::seatbelt)?;
    apply_profile(&profile)?;
    close_inherited_fds(trap_fd.map(AsRawFd::as_raw_fd).as_slice(), inherited_fds)
        .map_err(Error::seatbelt)?;
    let mut command = Command::new(tool);
    command.args(args).current_dir(cwd);
    let error = command.exec();
    Err(Error::launch(tool, error).into())
}

pub(crate) fn doctor() -> Result<()> {
    let operation = CString::new("file-read-data").map_err(Error::seatbelt)?;
    let result =
        unsafe { ffi::sandbox_check(libc::getpid(), operation.as_ptr(), SANDBOX_FILTER_NONE) };
    if result < 0 {
        return Err(Error::seatbelt(io::Error::last_os_error()).into());
    }
    Ok(())
}

fn apply_profile(profile: &str) -> Result<()> {
    let profile = CString::new(profile).map_err(|source| {
        Error::seatbelt(format!(
            "profile: interior nul at offset {}",
            source.nul_position()
        ))
    })?;
    let mut errorbuf = ptr::null_mut();

    // SAFETY: profile is a live NULL-terminated C string and errorbuf points to writable
    // storage through a raw out pointer.
    let rc = unsafe { ffi::sandbox_init(profile.as_ptr(), SBPL_PROFILE_FLAGS, &raw mut errorbuf) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::seatbelt(take_sandbox_error(errorbuf)).into())
    }
}

fn render_profile(policy: &AccessPolicy) -> std::result::Result<String, fmt::Error> {
    let mut sb = String::new();
    let message = policy
        .macos
        .log_tag
        .as_ref()
        .map_or_else(String::new, |tag| format!(" (with message \"{tag}\")"));
    writeln!(sb, "(version 1)")?;
    writeln!(sb, "(deny default{message})")?;

    render_process_rules(&mut sb)?;
    render_mach_rules(&mut sb, &policy.macos)?;
    render_write_rules(&mut sb, policy, &message)?;
    render_read_rules(&mut sb, policy, &message)?;
    render_network_rules(&mut sb, &policy.network_access, &message)?;
    Ok(sb)
}

fn render_process_rules(sb: &mut String) -> fmt::Result {
    writeln!(sb, "(allow process-exec)")?;
    // Seatbelt blocks the setuid system ps binary unless it executes outside the sandbox.
    writeln!(
        sb,
        "(allow process-exec (path \"/bin/ps\") (with no-sandbox))",
    )?;
    writeln!(sb, "(allow process-fork)")?;
    writeln!(sb, "(allow process-info* (target same-sandbox))")?;
    writeln!(sb, "(allow signal (target same-sandbox))")?;
    writeln!(sb, "(allow sysctl-read)")
}

/// Default Mach services, matching the Anthropic sandbox-runtime (srt) base
/// profile plus `SecurityServer` for Keychain access.
fn render_mach_rules(sb: &mut String, macos: &SandboxDarwin) -> fmt::Result {
    writeln!(sb, "(allow mach-lookup")?;
    writeln!(sb, "  (global-name \"com.apple.SecurityServer\")")?;
    if macos.allow_trustd {
        writeln!(sb, "  (global-name \"com.apple.trustd.agent\")")?;
    }
    if macos.allow_apple_events {
        writeln!(sb, "  (global-name \"com.apple.coreservices.appleevents\")")?;
        writeln!(
            sb,
            "  (global-name \"com.apple.CoreServices.coreservicesd\")"
        )?;
        writeln!(
            sb,
            "  (global-name \"com.apple.coreservices.quarantine-resolver\")"
        )?;
    }
    for service in &macos.allow_mach_lookup {
        if let Some(prefix) = service.strip_suffix('*') {
            let escaped = escape_sbpl_literal(prefix);
            writeln!(sb, "  (global-name-prefix \"{escaped}\")")?;
        } else {
            let escaped = escape_sbpl_literal(service);
            writeln!(sb, "  (global-name \"{escaped}\")")?;
        }
    }
    writeln!(sb, "  (global-name \"com.apple.audio.systemsoundserver\")")?;
    writeln!(sb, "  (global-name \"com.apple.bsd.dirhelper\")")?;
    writeln!(
        sb,
        "  (global-name \"com.apple.coreservices.launchservicesd\")"
    )?;
    writeln!(
        sb,
        "  (global-name \"com.apple.distributed_notifications@Uv3\")"
    )?;
    writeln!(sb, "  (global-name \"com.apple.FontObjectsServer\")")?;
    writeln!(sb, "  (global-name \"com.apple.fonts\")")?;
    writeln!(sb, "  (global-name \"com.apple.logd\")")?;
    writeln!(sb, "  (global-name \"com.apple.lsd.mapdb\")")?;
    writeln!(sb, "  (global-name \"com.apple.PowerManagement.control\")")?;
    writeln!(sb, "  (global-name \"com.apple.securityd.xpc\")")?;
    // apple/container CLI talks to its daemons over XPC.
    writeln!(sb, "  (global-name-prefix \"com.apple.container.\")")?;
    writeln!(sb, "  (global-name \"com.apple.system.logger\")")?;
    writeln!(
        sb,
        "  (global-name \"com.apple.system.notification_center\")"
    )?;
    writeln!(
        sb,
        "  (global-name \"com.apple.system.opendirectoryd.libinfo\")"
    )?;
    writeln!(
        sb,
        "  (global-name \"com.apple.system.opendirectoryd.membership\")"
    )?;
    writeln!(sb, ")")?;
    if macos.allow_apple_events {
        writeln!(sb, "(allow appleevent-send)")?;
        writeln!(sb, "(allow lsopen)")?;
    }
    writeln!(
        sb,
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))"
    )?;
    writeln!(sb, "(allow system-socket (socket-domain AF_ROUTE))")
}

fn glob_to_sbpl_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let mut rest = pattern;

    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix("**/") {
            regex.push_str("(.*/)?");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("**") {
            regex.push_str(".*");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('*') {
            regex.push_str("[^/]*");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('?') {
            regex.push_str("[^/]");
            rest = tail;
        } else if rest.starts_with('[') {
            if let Some(offset) = rest[1..].find(']') {
                let end = 1 + offset;
                regex.push_str(&rest[..=end]);
                rest = &rest[end + 1..];
            } else {
                regex.push_str("\\[");
                rest = &rest[1..];
            }
        } else {
            let mut chars = rest.chars();
            let Some(ch) = chars.next() else {
                break;
            };
            match ch {
                '.' | '(' | ')' | '{' | '}' | '+' | '|' | '^' | '$' | '\\' => {
                    regex.push('\\');
                    regex.push(ch);
                }
                _ => regex.push(ch),
            }
            rest = chars.as_str();
        }
    }

    if !pattern.ends_with('/') {
        regex.push_str("(/.*)?");
    }
    regex.push('$');
    regex
}

fn render_pattern_filter(pattern: &str, carveouts: &[PathBuf]) -> String {
    let regex = glob_to_sbpl_regex(pattern);
    let escaped = escape_sbpl_regex_literal(&regex);
    let glob = GlobPattern::new(pattern);
    let filter = format!("(regex #\"{escaped}\")");
    let matching_carveouts: Vec<&Path> = carveouts
        .iter()
        .map(PathBuf::as_path)
        .filter(|carveout| glob.matches_tree(carveout))
        .collect();
    if matching_carveouts.is_empty() {
        return filter;
    }

    let mut wrapped = format!("(require-all {filter}");
    for carveout in matching_carveouts {
        let escaped_carveout = escape_sbpl_literal(&carveout.to_string_lossy());
        let _ = write!(wrapped, " (require-not (subpath \"{escaped_carveout}\"))");
    }
    wrapped.push(')');
    wrapped
}

fn render_write_rules(sb: &mut String, policy: &AccessPolicy, message: &str) -> fmt::Result {
    for root in &policy.write_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(allow file-write* (subpath \"{escaped}\"))")?;
    }
    if policy.macos.allow_pty {
        writeln!(sb, "(allow pseudo-tty)")?;
        writeln!(
            sb,
            "(allow file-ioctl file-write* (literal \"/dev/ptmx\") (regex #\"^/dev/ttys\"))"
        )?;
    }
    // Deny rules follow the allow rules so SBPL's last-match-wins precedence
    // subtracts the denied subtrees from the granted write roots.
    for root in &policy.write_denied_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(deny file-write* (subpath \"{escaped}\"){message})")?;
    }

    // Regex rules are evaluated at syscall time, so unlike expand_glob_path
    // they also cover paths created after sandbox_init.
    for pattern in &policy.write_denied_patterns {
        let regex = glob_to_sbpl_regex(pattern);
        let escaped = escape_sbpl_regex_literal(&regex);
        writeln!(sb, "(deny file-write* (regex #\"{escaped}\"){message})")?;
    }

    if !policy.write_roots.is_empty() {
        for root in &policy.read_denied_roots {
            let escaped = escape_sbpl_literal(&root.to_string_lossy());
            writeln!(
                sb,
                "(deny file-write-unlink (subpath \"{escaped}\"){message})"
            )?;
        }
        for pattern in &policy.read_denied_patterns {
            let filter = render_pattern_filter(pattern, &policy.read_carveouts);
            writeln!(sb, "(deny file-write-unlink {filter}{message})")?;
        }

        let mut ancestors: Vec<PathBuf> = Vec::new();
        for root in policy
            .write_denied_roots
            .iter()
            .chain(policy.read_denied_roots.iter())
        {
            for ancestor in root.ancestors().skip(1) {
                if ancestor != Path::new("/") && ancestor.is_under_any(&policy.write_roots) {
                    ancestors.push(ancestor.to_path_buf());
                }
            }
        }
        for pattern in policy
            .write_denied_patterns
            .iter()
            .chain(policy.read_denied_patterns.iter())
        {
            let base = GlobPattern::new(pattern).base();
            for ancestor in base.ancestors() {
                if ancestor != Path::new("/") && ancestor.is_under_any(&policy.write_roots) {
                    ancestors.push(ancestor.to_path_buf());
                }
            }
        }
        ancestors.sort_unstable();
        ancestors.dedup();
        for ancestor in &ancestors {
            let escaped = escape_sbpl_literal(&ancestor.to_string_lossy());
            writeln!(
                sb,
                "(deny file-write-unlink (literal \"{escaped}\"){message})"
            )?;
        }
    }

    Ok(())
}

fn render_read_rules(sb: &mut String, policy: &AccessPolicy, message: &str) -> fmt::Result {
    match &policy.read_access {
        ReadAccess::Unrestricted => sb.push_str("(allow file-read*)\n"),
        ReadAccess::AllowRoots(roots) => {
            writeln!(sb, "(deny file-read*{message})")?;
            writeln!(sb, "(allow file-read* (literal \"/\"))")?;
            for root in roots {
                let escaped = escape_sbpl_literal(&root.to_string_lossy());
                writeln!(sb, "(allow file-read* (subpath \"{escaped}\"))")?;
            }
            if policy.macos.allow_pty {
                writeln!(
                    sb,
                    "(allow file-read* (literal \"/dev/ptmx\") (regex #\"^/dev/ttys\"))"
                )?;
            }
            render_parent_dir_rules(sb, roots)?;

            render_symlink_metadata_rules(sb, &policy.read_symlinks)?;
        }
    }
    // Deny rules follow the allow rules so SBPL's last-match-wins
    // precedence subtracts the denied subtrees from the read grants.
    for root in &policy.read_denied_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(deny file-read* (subpath \"{escaped}\"){message})")?;
    }
    for pattern in &policy.read_denied_patterns {
        let filter = render_pattern_filter(pattern, &policy.read_carveouts);
        writeln!(sb, "(deny file-read* {filter}{message})")?;
    }

    Ok(())
}

fn render_parent_dir_rules(sb: &mut String, roots: &[PathBuf]) -> fmt::Result {
    let mut ancestors: Vec<PathBuf> = Vec::new();
    for root in roots {
        let mut current = root.as_path();
        while let Some(parent) = current.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            ancestors.push(parent.to_path_buf());
            current = parent;
        }
    }
    ancestors.sort_unstable();
    ancestors.dedup();
    for ancestor in &ancestors {
        let escaped = escape_sbpl_literal(&ancestor.to_string_lossy());
        writeln!(sb, "(allow file-read* (literal \"{escaped}\"))")?;
    }
    Ok(())
}

/// Allow `readlink` on the lexical symlink inodes the read scan skipped.
///
/// Mirrors Apple's system.sb: `readlink` only permits resolution; the target
/// is still gated by the existing allow/deny rules, so this grants no new read
/// access.
fn render_symlink_metadata_rules(sb: &mut String, symlinks: &[PathBuf]) -> fmt::Result {
    if symlinks.is_empty() {
        return Ok(());
    }
    sb.push_str("(allow file-read-metadata");
    for sym in symlinks {
        let escaped = escape_sbpl_literal(&sym.to_string_lossy());
        write!(sb, "\n  (literal \"{escaped}\")")?;
    }
    sb.push_str(")\n");
    Ok(())
}

fn render_network_rules(sb: &mut String, network: &NetworkAccess, message: &str) -> fmt::Result {
    if network.is_unrestricted() {
        sb.push_str("(allow network*)\n");
        if !matches!(network.unix_socket_access(), UnixSocketAccess::Unrestricted) {
            writeln!(sb, "(deny network-outbound (remote unix-socket){message})")?;
            writeln!(sb, "(deny network-bind (local unix-socket){message})")?;
        }
        if let UnixSocketAccess::AllowPaths(paths) = network.unix_socket_access() {
            for path in paths {
                let escaped = escape_sbpl_literal(&path.to_string_lossy());
                writeln!(
                    sb,
                    "(allow network-outbound (remote unix-socket (subpath \"{escaped}\")))"
                )?;
                writeln!(
                    sb,
                    "(allow network-bind (local unix-socket (subpath \"{escaped}\")))"
                )?;
            }
        }
        return Ok(());
    }

    // AF_UNIX socket creation stays allowed regardless of the socket policy.
    sb.push_str("(allow system-socket (socket-domain AF_UNIX))\n");

    // Seatbelt accepts only `*` or `localhost` as the host token in an IP
    // endpoint filter. `localhost` permits IPv4 and IPv6 loopback connections,
    // matching the macOS Anthropic Sandbox Runtime behavior. On some hosts it
    // also matches addresses assigned to other local interfaces; Seatbelt
    // cannot express a stricter loopback-only rule.
    writeln!(sb, "(deny network-outbound{message})")?;
    for port in network.connect_tcp_ports() {
        writeln!(
            sb,
            "(allow network-outbound (remote tcp \"localhost:{port}\"))"
        )?;
    }

    if network.allows_local_binding() {
        // allowLocalBinding also grants host-local UDP on Seatbelt. Match the
        // destination for outbound traffic: a local/source filter would allow
        // remote egress from a locally bound socket.
        for protocol in ["tcp", "udp"] {
            writeln!(
                sb,
                "(allow network-outbound (remote {protocol} \"localhost:*\"))"
            )?;
            writeln!(
                sb,
                "(allow network-bind (local {protocol} \"localhost:*\"))"
            )?;
            writeln!(
                sb,
                "(allow network-inbound (local {protocol} \"localhost:*\"))"
            )?;
        }
    }

    match network.unix_socket_access() {
        UnixSocketAccess::Unrestricted => {
            sb.push_str("(allow network-outbound (remote unix-socket))\n");
            sb.push_str("(allow network-bind (local unix-socket))\n");
        }
        UnixSocketAccess::AllowPaths(paths) => {
            for path in paths {
                let escaped = escape_sbpl_literal(&path.to_string_lossy());
                writeln!(
                    sb,
                    "(allow network-outbound (remote unix-socket (subpath \"{escaped}\")))"
                )?;
                writeln!(
                    sb,
                    "(allow network-bind (local unix-socket (subpath \"{escaped}\")))"
                )?;
            }
        }
        UnixSocketAccess::Denied => {}
    }

    Ok(())
}

fn escape_sbpl_literal(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn escape_sbpl_regex_literal(regex: &str) -> String {
    let mut escaped = String::with_capacity(regex.len());
    for ch in regex.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn take_sandbox_error(errorbuf: *mut libc::c_char) -> String {
    if errorbuf.is_null() {
        return "sandbox_init failed without an error message".to_string();
    }

    let message = unsafe { CStr::from_ptr(errorbuf) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::sandbox_free_error(errorbuf) };
    message
}

mod ffi {
    use libc::{c_char, c_int};

    #[link(name = "sandbox")]
    unsafe extern "C" {
        pub(super) fn sandbox_init(
            profile: *const c_char,
            flags: u64,
            errorbuf: *mut *mut c_char,
        ) -> c_int;
        pub(super) fn sandbox_free_error(errorbuf: *mut c_char);
        pub(super) fn sandbox_check(
            pid: libc::pid_t,
            operation: *const c_char,
            filter_type: c_int,
            ...
        ) -> c_int;
    }
}
