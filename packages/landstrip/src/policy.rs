// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Policy lowering from JSON settings to platform access rules.
//!
//! Filesystem policy follows the Seatbelt-compatible shape. Writes start
//! denied; `allowWrite` grants roots and `denyWrite` subtracts from them. Reads
//! stay unrestricted unless `denyRead` or `denyReadAlways` is set. `allowRead`
//! adds paths back from ordinary denials, with the most specific rule winning;
//! `denyReadAlways` roots and descendants cannot be restored by any allow.
//! Hard links and renames that would give a `denyRead` inode a readable name
//! stay denied even when the destination is under `allowWrite`.
//!
//! Paths accept absolute names, names relative to the policy base, `~`, and the
//! macOS-style `*`, `**`, `?`, and character-class globs. Globs are expanded
//! while lowering the policy.

use crate::config::{AppContainerMode, PathSelector, SandboxMacos, SandboxNetwork, Settings};
use crate::error::{Error, PathIo};
use crate::paths::{
    NormalizeRoots, PathCoverage, canonicalize_existing_prefix, normalize_path,
    normalize_path_lexically,
};
use anyhow::Result;
use serde::Serialize;
use std::env;
use std::fs;
use std::io;
#[cfg(target_os = "macos")]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessPolicy {
    pub(crate) write_roots: Vec<PathBuf>,
    pub(crate) write_denied_roots: Vec<PathBuf>,
    pub(crate) write_denied_always_roots: Box<[PathBuf]>,
    pub(crate) write_denied_always_patterns: Box<[String]>,
    pub(crate) write_denied_patterns: Vec<String>,
    pub(crate) write_denied_links: Vec<PathBuf>,
    pub(crate) read_access: ReadAccess,
    pub(crate) read_denied_roots: Vec<PathBuf>,
    pub(crate) read_denied_patterns: Vec<String>,
    pub(crate) read_carveouts: Vec<PathBuf>,
    pub(crate) read_denied_always_roots: Box<[PathBuf]>,
    pub(crate) read_denied_always_patterns: Box<[String]>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) read_symlinks: Vec<PathBuf>,
    pub(crate) network_access: NetworkAccess,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) macos: SandboxMacos,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) app_container_mode: AppContainerMode,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) allow_windows_loopback: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DenialReason {
    DenyMatch,
    AllowMiss,
}

// The write broker that consults these lives only in the Linux seccomp path.
#[cfg(target_os = "linux")]
impl AccessPolicy {
    /// Whether a write to `canonical` (with lexical form `lexical`, used for the
    /// symlink-ancestor deny-list) lands in the `denyWrite` deny-list. Glob
    /// patterns in `write_denied_patterns` are evaluated dynamically against the
    /// lexical path so files created after sandbox startup are also blocked.
    pub(crate) fn is_write_denied(&self, canonical: &Path, lexical: &Path) -> bool {
        matches_denied(
            &self.write_denied_roots,
            &self.write_denied_patterns,
            canonical,
        ) || matches_denied(
            &self.write_denied_links,
            &self.write_denied_patterns,
            lexical,
        )
    }

    pub(crate) fn is_write_denied_always(&self, canonical: &Path, lexical: &Path) -> bool {
        matches_denied(
            &self.write_denied_always_roots,
            &self.write_denied_always_patterns,
            canonical,
        ) || matches_denied(
            &self.write_denied_always_roots,
            &self.write_denied_always_patterns,
            lexical,
        )
    }

    pub(crate) fn is_read_denied(&self, path: &Path) -> bool {
        path.is_under_any(&self.read_denied_roots)
            || self.is_read_denied_always(path)
            || self.read_denied_patterns.iter().any(|pattern| {
                let glob = GlobPattern::new(pattern);
                path.ancestors().any(|ancestor| glob.matches_path(ancestor))
                    && !self.read_carveouts.iter().any(|carveout| {
                        path.is_under(carveout)
                            && carveout
                                .ancestors()
                                .any(|ancestor| glob.matches_path(ancestor))
                    })
            })
    }

    pub(crate) fn is_read_denied_always(&self, path: &Path) -> bool {
        matches_denied(
            &self.read_denied_always_roots,
            &self.read_denied_always_patterns,
            path,
        )
    }

    pub(crate) fn has_read_denied_under(&self, dir: &Path) -> bool {
        has_denied_under(&self.read_denied_roots, &self.read_denied_patterns, dir)
    }

    pub(crate) fn has_write_denied_under(&self, dir: &Path) -> bool {
        has_denied_under(&self.write_denied_roots, &self.write_denied_patterns, dir)
    }

    pub(crate) fn has_read_denied_always_under(&self, dir: &Path) -> bool {
        has_denied_under(
            &self.read_denied_always_roots,
            &self.read_denied_always_patterns,
            dir,
        )
    }

    pub(crate) fn has_write_denied_always_under(&self, dir: &Path) -> bool {
        has_denied_under(
            &self.write_denied_always_roots,
            &self.write_denied_always_patterns,
            dir,
        )
    }

    /// Why a write to `canonical` is mediated, or `None` when the policy permits
    /// it. `allow_miss` (outside every `allowWrite` root) is reported only when
    /// `surface_allow_miss` is set: content syscalls leave it to Landlock unless
    /// a query can resolve it, but metadata syscalls Landlock does not cover must
    /// always surface it so the broker can gate them.
    pub(crate) fn write_reason(
        &self,
        canonical: &Path,
        lexical: &Path,
        surface_allow_miss: bool,
    ) -> Option<DenialReason> {
        if self.is_write_denied(canonical, lexical) {
            Some(DenialReason::DenyMatch)
        } else if surface_allow_miss && !canonical.is_under_any(&self.write_roots) {
            Some(DenialReason::AllowMiss)
        } else {
            None
        }
    }

    pub(crate) fn read_reason(&self, path: &Path) -> Option<DenialReason> {
        match &self.read_access {
            ReadAccess::Unrestricted => None,
            ReadAccess::AllowRoots(roots) => {
                if self.is_read_denied(path) {
                    Some(DenialReason::DenyMatch)
                } else if path.is_under_any(roots) {
                    None
                } else {
                    Some(DenialReason::AllowMiss)
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl AccessPolicy {
    /// Reject policies macOS Seatbelt cannot enforce: an existing non-socket
    /// `allowUnixSockets` path or a `denyWrite` symlink ancestor.
    pub(crate) fn validate(&self) -> std::result::Result<(), Error> {
        if let UnixSocketAccess::AllowPaths(paths) = self.network_access.unix_socket_access() {
            for path in paths {
                match fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.file_type().is_socket() => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        log::debug!(
                            "macos: allowUnixSockets path absent, skipping {}",
                            path.display()
                        );
                    }
                    _ => return Err(Error::PolicyUnixSocketPath),
                }
            }
        }

        let has_writable_symlink_ancestor = self
            .write_denied_links
            .iter()
            .any(|link| link.is_under_any(&self.write_roots));
        if has_writable_symlink_ancestor {
            return Err(Error::PolicyDenyWriteSymlinkAncestor);
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl AccessPolicy {
    /// Reject policies the Windows `AppContainer` cannot enforce: unrestricted
    /// read, a local TCP bind, or a non-empty Unix socket allowlist. Connect
    /// proxy ports are accepted but unenforceable, so the container then runs
    /// with no network access.
    pub(crate) fn validate(&self) -> std::result::Result<(), Error> {
        if matches!(self.read_access, ReadAccess::Unrestricted) {
            return Err(Error::PolicyUnrestrictedRead);
        }

        let network = &self.network_access;
        if !network.unix_socket_access().is_denied() {
            return Err(Error::PolicyUnixSocketUnsupported);
        }

        if network.is_unrestricted() {
            return Ok(());
        }

        if network.allows_local_binding() {
            return Err(Error::PolicyLocalBindingUnsupported);
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", tag = "mode", content = "roots")]
pub(crate) enum ReadAccess {
    Unrestricted,
    AllowRoots(Vec<PathBuf>),
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", tag = "mode")]
pub(crate) enum NetworkAccess {
    Unrestricted {
        unix_socket_access: UnixSocketAccess,
    },
    Restricted {
        connect_tcp_ports: Vec<u16>,
        bind: IpBindAccess,
        unix_socket_access: UnixSocketAccess,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum IpBindAccess {
    Deny,
    Localhost,
}

impl NetworkAccess {
    pub(crate) fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted { .. })
    }

    pub(crate) fn connect_tcp_ports(&self) -> &[u16] {
        match self {
            Self::Unrestricted { .. } => &[],
            Self::Restricted {
                connect_tcp_ports, ..
            } => connect_tcp_ports,
        }
    }

    pub(crate) fn unix_socket_access(&self) -> &UnixSocketAccess {
        match self {
            Self::Unrestricted { unix_socket_access }
            | Self::Restricted {
                unix_socket_access, ..
            } => unix_socket_access,
        }
    }

    pub(crate) fn allows_local_binding(&self) -> bool {
        matches!(
            self,
            Self::Restricted {
                bind: IpBindAccess::Localhost,
                ..
            }
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn restricts_bind_ip(&self) -> bool {
        matches!(
            self,
            Self::Restricted {
                bind: IpBindAccess::Deny,
                ..
            }
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn restricts_connect_tcp(&self) -> bool {
        matches!(self, Self::Restricted { .. })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn needs_bind_broker(&self) -> bool {
        match self {
            Self::Unrestricted { unix_socket_access } => unix_socket_access.needs_broker(),
            Self::Restricted {
                bind,
                unix_socket_access,
                ..
            } => matches!(bind, IpBindAccess::Localhost) || unix_socket_access.needs_broker(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn needs_network_broker(&self) -> bool {
        match self {
            Self::Unrestricted { unix_socket_access } => unix_socket_access.needs_broker(),
            Self::Restricted {
                connect_tcp_ports, ..
            } => self.needs_bind_broker() || !connect_tcp_ports.is_empty(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", tag = "mode", content = "paths")]
pub(crate) enum UnixSocketAccess {
    Unrestricted,
    AllowPaths(Vec<PathBuf>),
    Denied,
}

impl UnixSocketAccess {
    #[cfg(target_os = "linux")]
    pub(crate) fn needs_broker(&self) -> bool {
        !matches!(self, Self::Unrestricted)
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn is_denied(&self) -> bool {
        matches!(self, Self::Denied)
    }
}

impl Settings {
    pub(crate) fn resolve(&self, policy_base: &Path) -> Result<AccessPolicy> {
        let filesystem = &self.filesystem;
        let network = &self.network;
        let windows = &self.windows;
        #[cfg(target_os = "windows")]
        if !filesystem.deny_read_always.is_empty() {
            return Err(Error::PolicyDenyReadAlwaysUnsupported.into());
        }
        #[cfg(target_os = "windows")]
        if !filesystem.deny_write_always.is_empty() {
            return Err(Error::PolicyDenyWriteAlwaysUnsupported.into());
        }
        let home_dir = dirs::home_dir();
        let home = home_dir.as_deref();
        let policy_base = if policy_base.is_absolute() {
            policy_base.to_path_buf()
        } else {
            env::current_dir()?.join(policy_base)
        };
        let policy_base = normalize_path_lexically(&policy_base);

        let mut write_allow = resolve_paths(&filesystem.allow_write, &policy_base, home)?;
        // Missing Windows allow roots cannot receive ACL entries. Dropping them is
        // fail-closed because sandbox SIDs receive no access to those paths.
        #[cfg(target_os = "windows")]
        retain_windows_allow_roots(&mut write_allow);
        let mut resolved_write_deny =
            resolve_deny_paths(&filesystem.deny_write, &policy_base, home)?;
        let mut write_denied_links =
            collect_symlink_ancestors(&filesystem.deny_write, &policy_base, home)?;
        let resolved_write_always =
            resolve_deny_paths(&filesystem.deny_write_always, &policy_base, home)?;
        resolved_write_deny.merge_always(&resolved_write_always, &mut write_allow);
        let write_deny = resolved_write_deny.concrete;
        let write_denied_patterns = resolved_write_deny.patterns;
        let write_denied_always_roots = resolved_write_always.concrete;
        let write_denied_always_patterns = resolved_write_always.patterns;
        write_denied_links.extend(collect_symlink_ancestors(
            &filesystem.deny_write_always,
            &policy_base,
            home,
        )?);
        write_denied_links.sort_unstable();
        write_denied_links.dedup();

        let mut read_allow = resolve_paths(&filesystem.allow_read, &policy_base, home)?;
        #[cfg(target_os = "windows")]
        retain_windows_allow_roots(&mut read_allow);
        let mut resolved_read_deny = resolve_deny_paths(&filesystem.deny_read, &policy_base, home)?;
        let mut read_denied_roots =
            effective_denied_roots(&resolved_read_deny.concrete, &read_allow);
        let resolved_read_always =
            resolve_deny_paths(&filesystem.deny_read_always, &policy_base, home)?;
        let read_carveouts = resolved_read_deny.carveouts(&resolved_read_always, &read_allow);
        resolved_read_deny.merge_always(&resolved_read_always, &mut read_allow);
        let read_deny = resolved_read_deny.concrete;
        let read_denied_patterns = resolved_read_deny.patterns;
        let read_denied_always_roots = resolved_read_always.concrete;
        let read_denied_always_patterns = resolved_read_always.patterns;
        // Windows cannot attach deny entries to missing paths or volume roots.
        #[cfg(target_os = "windows")]
        retain_windows_deny_roots(&mut read_denied_roots);

        #[cfg(target_os = "windows")]
        let (write_allow, write_deny) = {
            let write_roots =
                lower_windows_write_access(&write_allow, write_deny, &read_denied_roots);
            (write_roots.allow, write_roots.deny)
        };

        let lowered_read = lower_read_access(
            &read_allow,
            &read_deny,
            &read_denied_patterns,
            &read_denied_roots,
        )?;
        let (read_access, read_symlinks) = (lowered_read.access, lowered_read.symlinks);
        read_denied_roots.extend(read_denied_always_roots.iter().cloned());
        read_denied_roots.normalize_roots();
        let policy = AccessPolicy {
            write_roots: write_allow,
            write_denied_roots: write_deny,
            write_denied_always_roots: write_denied_always_roots.into_boxed_slice(),
            write_denied_always_patterns: write_denied_always_patterns.into_boxed_slice(),
            write_denied_patterns,
            write_denied_links,
            read_access,
            read_denied_roots,
            read_denied_patterns,
            read_carveouts,
            read_denied_always_roots: read_denied_always_roots.into_boxed_slice(),
            read_denied_always_patterns: read_denied_always_patterns.into_boxed_slice(),
            read_symlinks,
            network_access: lower_network_policy(network, &policy_base, home)?,
            macos: lower_macos_policy(&self.macos)?,
            app_container_mode: windows.app_container_mode,
            allow_windows_loopback: windows.allow_loopback,
        };
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        policy.validate()?;
        Ok(policy)
    }
}

struct LoweredReadAccess {
    access: ReadAccess,
    symlinks: Vec<PathBuf>,
}

struct ResolvedDenyPaths {
    concrete: Vec<PathBuf>,
    patterns: Vec<String>,
}

impl ResolvedDenyPaths {
    fn matches(&self, path: &Path) -> bool {
        matches_denied(&self.concrete, &self.patterns, path)
    }

    fn carveouts(&self, always: &Self, allow: &[PathBuf]) -> Vec<PathBuf> {
        allow
            .iter()
            .filter(|path| !always.matches(path) && matches_any_pattern(path, &self.patterns))
            .cloned()
            .collect()
    }

    fn merge_always(&mut self, always: &Self, allow: &mut Vec<PathBuf>) {
        allow.retain(|path| !always.matches(path));
        self.concrete.extend(always.concrete.iter().cloned());
        self.concrete.normalize_roots();
        self.patterns.extend(always.patterns.iter().cloned());
        self.patterns.sort_unstable();
        self.patterns.dedup();
    }
}

#[cfg(target_os = "windows")]
struct WindowsWriteRoots {
    allow: Vec<PathBuf>,
    deny: Vec<PathBuf>,
}

#[cfg(target_os = "windows")]
fn retain_windows_allow_roots(paths: &mut Vec<PathBuf>) {
    paths.retain(|path| path.try_exists().unwrap_or(false));
}

#[cfg(target_os = "windows")]
fn retain_windows_deny_roots(paths: &mut Vec<PathBuf>) {
    paths.retain(|path| path.parent().is_some() && path.try_exists().unwrap_or(true));
}

#[cfg(target_os = "windows")]
fn lower_windows_write_access(
    write_allow: &[PathBuf],
    mut write_deny: Vec<PathBuf>,
    read_denied_roots: &[PathBuf],
) -> WindowsWriteRoots {
    // Windows ACLs cannot attach deny entries to paths that do not exist or to
    // volume roots. Nested denials under `allowWrite` are enforced by explicit
    // DENY ACEs applied after the write grants so parent directories keep their
    // write permission for sibling creation.
    retain_windows_deny_roots(&mut write_deny);

    let mut carved_writes: Vec<PathBuf> = write_allow
        .iter()
        .filter(|allow| !allow.is_under_any(&write_deny) && !allow.is_under_any(read_denied_roots))
        .cloned()
        .collect();
    carved_writes.normalize_roots();

    WindowsWriteRoots {
        allow: carved_writes,
        deny: write_deny,
    }
}

fn lower_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    read_denied_patterns: &[String],
    read_denied_roots: &[PathBuf],
) -> Result<LoweredReadAccess> {
    let fs_root = normalize_path(Path::new("/"));
    // Reject a full-volume Windows grant because propagating it over `C:\`
    // can hang while walking the volume.
    #[cfg(target_os = "windows")]
    if read_allow.contains(&fs_root) {
        return Err(Error::PolicyUnrestrictedRead.into());
    }

    let has_dynamic_patterns = cfg!(not(target_os = "windows")) && !read_denied_patterns.is_empty();
    let has_windows_allow_roots = cfg!(target_os = "windows") && !read_allow.is_empty();
    if read_deny.is_empty() && !has_dynamic_patterns && !has_windows_allow_roots {
        Ok(LoweredReadAccess {
            access: ReadAccess::Unrestricted,
            symlinks: Vec::new(),
        })
    } else if (has_dynamic_patterns && read_deny.is_empty())
        || (read_allow.contains(&fs_root)
            && !read_deny
                .iter()
                .any(|deny| read_allow.iter().any(|allow| allow.is_strictly_under(deny))))
    {
        // Layer surviving denyRead roots over a full-tree allowRead grant.
        // Windows rejects the full-volume grant above.
        Ok(LoweredReadAccess {
            access: ReadAccess::AllowRoots(vec![fs_root]),
            symlinks: Vec::new(),
        })
    } else {
        lower_restricted_read_access(read_allow, read_deny, read_denied_roots)
    }
}

#[cfg(target_os = "windows")]
fn lower_restricted_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    read_denied_roots: &[PathBuf],
) -> Result<LoweredReadAccess> {
    // Denials that survive in `read_denied_roots` receive explicit DENY ACEs.
    // Only non-root denials overridden by a more specific `allowRead` (and
    // therefore omitted from `read_denied_roots`) need directory carving.
    let mut carve_denials: Vec<PathBuf> = read_deny
        .iter()
        .filter(|deny| {
            deny.parent().is_some()
                && !read_denied_roots.contains(deny)
                && read_allow.iter().any(|allow| allow.is_strictly_under(deny))
        })
        .cloned()
        .collect();
    carve_denials.normalize_roots();

    let mut roots = Vec::new();
    let mut symlinks = Vec::new();
    for allow in read_allow {
        let nested_denials: Vec<PathBuf> = carve_denials
            .iter()
            .filter(|deny| deny.is_strictly_under(allow))
            .cloned()
            .collect();
        if nested_denials.is_empty() {
            roots.push(allow.clone());
        } else {
            let scan = scan_allowed_root(allow, &nested_denials, true, 0)?;
            roots.extend(scan.roots);
            symlinks.extend(scan.symlinks);
        }
    }
    roots.normalize_roots();
    symlinks.normalize_roots();
    Ok(LoweredReadAccess {
        access: ReadAccess::AllowRoots(roots),
        symlinks,
    })
}

#[cfg(not(target_os = "windows"))]
fn lower_restricted_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    _read_denied_roots: &[PathBuf],
) -> Result<LoweredReadAccess> {
    let mut denied = read_deny.to_vec();
    denied.normalize_roots();
    let scan = scan_allowed_root(Path::new("/"), &denied, true, 0)?;
    let mut roots = scan.roots;
    let mut symlinks = scan.symlinks;

    // The seccomp broker enforces nested denials under explicit allow roots.
    for allow in read_allow {
        if allow.as_path() != Path::new("/") {
            roots.push(allow.clone());
        }
    }
    roots.normalize_roots();
    symlinks.normalize_roots();
    Ok(LoweredReadAccess {
        access: ReadAccess::AllowRoots(roots),
        symlinks,
    })
}

fn lower_network_policy(
    network: &SandboxNetwork,
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<NetworkAccess> {
    let unix_socket_paths = resolve_paths(&network.allow_unix_sockets, policy_base, home)?;
    let unix_socket_access = if network.allow_all_unix_sockets {
        UnixSocketAccess::Unrestricted
    } else if unix_socket_paths.is_empty() {
        UnixSocketAccess::Denied
    } else {
        UnixSocketAccess::AllowPaths(unix_socket_paths)
    };

    if network.allow_network {
        return Ok(NetworkAccess::Unrestricted { unix_socket_access });
    }

    let mut connect_tcp_ports = Vec::new();
    for port in [network.http_proxy_port, network.socks_proxy_port]
        .into_iter()
        .flatten()
    {
        if port == 0 {
            return Err(Error::PolicyInvalidPort.into());
        }
        connect_tcp_ports.push(port);
    }
    connect_tcp_ports.sort_unstable();
    connect_tcp_ports.dedup();

    let bind = if network.allow_local_binding {
        IpBindAccess::Localhost
    } else {
        IpBindAccess::Deny
    };
    Ok(NetworkAccess::Restricted {
        connect_tcp_ports,
        bind,
        unix_socket_access,
    })
}

fn lower_macos_policy(macos: &SandboxMacos) -> Result<SandboxMacos> {
    let mut allow_mach_lookup = Vec::with_capacity(macos.allow_mach_lookup.len());
    for service in &macos.allow_mach_lookup {
        if service.strip_suffix('*').unwrap_or(service).is_empty() {
            return Err(Error::PolicyInvalidMachLookup.into());
        }
        allow_mach_lookup.push(service.clone());
    }
    allow_mach_lookup.sort_unstable();
    allow_mach_lookup.dedup();

    Ok(SandboxMacos {
        allow_trustd: macos.allow_trustd,
        allow_mach_lookup,
        allow_apple_events: macos.allow_apple_events,
        allow_pty: macos.allow_pty,
    })
}

fn resolve_paths(
    paths: &[PathSelector],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::new();
    for selector in paths {
        let path = resolve_sandbox_path(selector.as_str(), policy_base, home)?;
        let path_str = path.to_string_lossy();
        if !selector.is_literal() && GlobPattern::is_glob_str(&path_str) {
            let matches = GlobPattern::new(&path_str).expand()?;
            if matches!(selector, PathSelector::Bare(_))
                && matches.is_empty()
                && fs::symlink_metadata(&path).is_ok()
            {
                push_path_variants(&mut resolved, &path);
            } else {
                for candidate in &matches {
                    push_path_variants(&mut resolved, candidate);
                }
            }
        } else {
            push_path_variants(&mut resolved, &path);
        }
    }

    resolved.normalize_roots();

    Ok(resolved)
}

fn resolve_deny_paths(
    paths: &[PathSelector],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<ResolvedDenyPaths> {
    let mut concrete: Vec<PathBuf> = Vec::new();
    let mut patterns: Vec<String> = Vec::new();

    for selector in paths {
        let resolved = resolve_sandbox_path(selector.as_str(), policy_base, home)?;
        let resolved_str = resolved.to_string_lossy();
        if !selector.is_literal() && GlobPattern::is_glob_str(&resolved_str) {
            for candidate in GlobPattern::new(&resolved_str).expand()? {
                push_path_variants(&mut concrete, &candidate);
            }
            patterns.push(resolved_str.clone().into_owned());
            let base = GlobPattern::new(&resolved_str).base();
            let canonical = normalize_path_lexically(&canonicalize_existing_prefix(&base));
            let base_str = base.to_string_lossy();
            let canonical_str = canonical.to_string_lossy();
            if canonical_str != base_str
                && let Some(suffix) = resolved_str.strip_prefix(base_str.as_ref())
            {
                let mut canonical_pattern = canonical_str.into_owned();
                canonical_pattern.push_str(suffix);
                patterns.push(canonical_pattern);
            }
        } else {
            push_path_variants(&mut concrete, &resolved);
        }
    }

    concrete.normalize_roots();
    patterns.sort_unstable();
    patterns.dedup();

    Ok(ResolvedDenyPaths { concrete, patterns })
}

fn matches_denied(roots: &[PathBuf], patterns: &[String], path: &Path) -> bool {
    path.is_under_any(roots) || matches_any_pattern(path, patterns)
}

#[cfg(target_os = "linux")]
fn has_denied_under(roots: &[PathBuf], patterns: &[String], dir: &Path) -> bool {
    roots.iter().any(|root| root.is_under(dir))
        || patterns
            .iter()
            .any(|pattern| GlobPattern::new(pattern).matches_under(dir))
}

fn matches_any_pattern(path: &Path, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let glob = GlobPattern::new(pattern);
        path.ancestors().any(|ancestor| glob.matches_path(ancestor))
    })
}

const MAX_TRAVERSAL_DEPTH: u32 = 40;

/// Roots and skipped symlinks collected from a single `scan_allowed_root` traversal.
struct RootScan {
    roots: Vec<PathBuf>,
    symlinks: Vec<PathBuf>,
}

fn scan_allowed_root(
    root: &Path,
    denied: &[PathBuf],
    is_explicit_root: bool,
    depth: u32,
) -> Result<RootScan> {
    let mut results = Vec::new();
    let mut symlinks = Vec::new();
    let mut stack = vec![(root.to_path_buf(), is_explicit_root, depth)];

    while let Some((current, is_explicit, depth)) = stack.pop() {
        if depth >= MAX_TRAVERSAL_DEPTH {
            return Err(Error::PolicyTraversalDepth.into());
        }

        if current.is_under_any(denied) {
            continue;
        }

        let has_denied_descendant = denied
            .iter()
            .any(|denied_root| denied_root.is_strictly_under(&current));

        // A transient EIO (e.g. an autofs automount such as macOS `/home`) is
        // treated as an opaque boundary alongside a missing or denied path: keep
        // the path and stop descending rather than abort. A path landstrip cannot
        // stat is also unreadable to the sandboxed child.
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.is_opaque() => {
                results.push(current);
                continue;
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        let file_type = metadata.file_type();

        if file_type.is_symlink() && !is_explicit {
            symlinks.push(normalize_path_lexically(&current));
            continue;
        }
        if !has_denied_descendant || !file_type.is_dir() {
            results.push(current);
            continue;
        }

        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.is_transport_failed() =>
            {
                results.push(current);
                continue;
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.is_transport_failed() => {
                    continue;
                }
                Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
            };
            let child = entry.path();
            stack.push((child, false, depth + 1));
        }
    }

    Ok(RootScan {
        roots: results,
        symlinks,
    })
}

/// The `denyRead` roots that survive `allowRead` overrides.
///
/// An `allowRead` root that equals a `denyRead` root, or is nested under it,
/// re-grants that subtree and overrides the broader-or-equal deny per the
/// most-specific-rule-wins precedence. Such denies are dropped so they neither
/// emit a macOS deny rule nor gate the Linux broker.
fn effective_denied_roots(read_deny: &[PathBuf], read_allow: &[PathBuf]) -> Vec<PathBuf> {
    read_deny
        .iter()
        .filter(|deny| !read_allow.iter().any(|allow| allow.is_under(deny)))
        .cloned()
        .collect()
}

fn collect_symlink_ancestors(
    paths: &[PathSelector],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut links = Vec::new();
    for selector in paths {
        let resolved = resolve_sandbox_path(selector.as_str(), policy_base, home)?;
        let resolved_str = resolved.to_string_lossy();
        let check_path = if !selector.is_literal() && GlobPattern::is_glob_str(&resolved_str) {
            GlobPattern::new(&resolved_str).base()
        } else {
            resolved
        };
        let mut current = PathBuf::new();
        for component in check_path.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    links.push(normalize_path_lexically(&current));
                }
                _ => {}
            }
        }
    }
    links.sort_unstable();
    links.dedup();
    Ok(links)
}

#[cfg(target_os = "macos")]
fn push_path_variants(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.push(normalize_path_lexically(path));
    paths.push(normalize_path_lexically(&canonicalize_existing_prefix(
        path,
    )));
}

#[cfg(not(target_os = "macos"))]
fn push_path_variants(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.push(normalize_path(path));
}

fn resolve_sandbox_path(path: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(Error::PolicyEmptyPath.into());
    }

    let raw = Path::new(path);
    let resolved = if raw.has_root() {
        raw.to_path_buf()
    } else if path == "~" {
        home.map(Path::to_path_buf)
            .ok_or(Error::PolicyHomeUnavailable)?
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.map(|home| home.join(rest))
            .ok_or(Error::PolicyHomeUnavailable)?
    } else {
        base.join(raw)
    };

    Ok(normalize_path_lexically(&resolved))
}

pub(crate) struct GlobPattern<'a> {
    pattern: &'a str,
}

impl<'a> GlobPattern<'a> {
    pub(crate) fn new(pattern: &'a str) -> Self {
        Self { pattern }
    }

    pub(crate) fn is_glob_byte(byte: u8) -> bool {
        matches!(byte, b'*' | b'?' | b'[' | b']')
    }

    pub(crate) fn is_glob_str(s: &str) -> bool {
        s.bytes().any(Self::is_glob_byte)
    }

    pub(crate) fn base(&self) -> PathBuf {
        let Some(glob_at) = self.pattern.bytes().position(Self::is_glob_byte) else {
            return PathBuf::from(self.pattern);
        };
        let prefix = &self.pattern[..glob_at];
        let base = if prefix.ends_with('/') {
            Path::new(prefix.trim_end_matches('/'))
        } else {
            Path::new(prefix).parent().unwrap_or(Path::new("/"))
        };

        if base.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            base.to_path_buf()
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_path(&self, path: &Path) -> bool {
        let path_bytes = path.to_string_lossy();
        let pattern_bytes = self.pattern.as_bytes();
        let path_len = path_bytes.len();
        let pattern_len = pattern_bytes.len();
        let mut memo = vec![None; (pattern_len + 1) * (path_len + 1)];
        self.matches_at(pattern_bytes, path_bytes.as_bytes(), 0, 0, &mut memo)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_under(&self, root: &Path) -> bool {
        let base = self.base();
        if base.is_under(root) {
            return true;
        }
        if !root.is_under(&base) {
            return false;
        }
        let mut matches = Vec::new();
        self.collect_matches(root, &mut matches, 0).is_err() || !matches.is_empty()
    }

    pub(crate) fn expand(&self) -> Result<Vec<PathBuf>> {
        let base = self.base();
        let mut matches = Vec::new();

        match fs::symlink_metadata(&base) {
            Ok(_) => self.collect_matches(&base, &mut matches, 0)?,
            Err(error) if error.is_opaque() => {}
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        }

        Ok(matches)
    }

    fn collect_matches(&self, path: &Path, matches: &mut Vec<PathBuf>, depth: u32) -> Result<()> {
        const LIMIT: u32 = 40;

        if depth >= LIMIT {
            return Err(Error::PolicyTraversalDepth.into());
        }

        let candidate = normalize_path_lexically(path);
        let candidate_text = candidate.to_string_lossy();
        let pattern_bytes = self.pattern.as_bytes();
        let candidate_bytes = candidate_text.as_bytes();
        let mut memo = vec![None; (pattern_bytes.len() + 1) * (candidate_bytes.len() + 1)];

        if self.matches_at(pattern_bytes, candidate_bytes, 0, 0, &mut memo) {
            matches.push(candidate.clone());
        }

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.is_opaque() => return Ok(()),
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(());
        }

        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.is_transport_failed() =>
            {
                return Ok(());
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.is_transport_failed() => continue,
                Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
            };
            self.collect_matches(&entry.path(), matches, depth + 1)?;
        }

        Ok(())
    }

    fn matches_at(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        let memo_at = pattern_at * (text.len() + 1) + text_at;
        if let Some(result) = memo[memo_at] {
            return result;
        }

        let result = if pattern_at == pattern.len() {
            text_at == text.len()
        } else if pattern[pattern_at..].starts_with(b"**/") {
            self.globstar_slash_matches(pattern, text, pattern_at, text_at, memo)
        } else if pattern[pattern_at..].starts_with(b"**") {
            self.globstar_matches(pattern, text, pattern_at, text_at, memo)
        } else {
            match pattern[pattern_at] {
                b'*' => self.star_matches(pattern, text, pattern_at, text_at, memo),
                b'?' => {
                    text_at < text.len()
                        && text[text_at] != b'/'
                        && self.matches_at(pattern, text, pattern_at + 1, text_at + 1, memo)
                }
                b'[' => self.class_matches(pattern, text, pattern_at, text_at, memo),
                byte => {
                    text_at < text.len()
                        && text[text_at] == byte
                        && self.matches_at(pattern, text, pattern_at + 1, text_at + 1, memo)
                }
            }
        };

        memo[memo_at] = Some(result);
        result
    }

    fn globstar_slash_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        if self.matches_at(pattern, text, pattern_at + 3, text_at, memo) {
            return true;
        }

        for next in text_at..text.len() {
            if text[next] == b'/' && self.matches_at(pattern, text, pattern_at + 3, next + 1, memo)
            {
                return true;
            }
        }

        false
    }

    fn globstar_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        for next in text_at..=text.len() {
            if self.matches_at(pattern, text, pattern_at + 2, next, memo) {
                return true;
            }
        }

        false
    }

    fn star_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        let mut next = text_at;
        while next <= text.len() {
            if self.matches_at(pattern, text, pattern_at + 1, next, memo) {
                return true;
            }
            if next == text.len() || text[next] == b'/' {
                break;
            }
            next += 1;
        }

        false
    }

    fn class_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        let Some(class_end) = pattern[pattern_at + 1..]
            .iter()
            .position(|byte| *byte == b']')
            .map(|offset| pattern_at + 1 + offset)
        else {
            return text_at < text.len()
                && text[text_at] == b'['
                && self.matches_at(pattern, text, pattern_at + 1, text_at + 1, memo);
        };

        text_at < text.len()
            && text[text_at] != b'/'
            && Self::byte_in_class(text[text_at], &pattern[pattern_at + 1..class_end])
            && self.matches_at(pattern, text, class_end + 1, text_at + 1, memo)
    }

    fn byte_in_class(byte: u8, class: &[u8]) -> bool {
        let mut at = 0;

        while at < class.len() {
            if at + 2 < class.len() && class[at + 1] == b'-' {
                if byte >= class[at] && byte <= class[at + 2] {
                    return true;
                }
                at += 3;
            } else {
                if byte == class[at] {
                    return true;
                }
                at += 1;
            }
        }

        false
    }
}
