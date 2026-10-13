// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use super::grant::{
    Anchor, FdMutation, Grant, MutationGrant, MutationOp, OPEN_HOW_SIZE, OpenGrant, OpenHow,
    OpenKind, open_fd_path, open_path,
};
use super::notify::NotificationResult;
use super::process::TargetProcess;
use super::supervise::{Denial, Denials};
use crate::paths::{
    PathCoverage, normalize_path, normalize_path_lexically, normalize_path_nofollow,
};
use crate::policy::{AccessPolicy, DenialReason, ReadAccess};
use crate::trap::{FilesystemDenial, Trap, TrapOperation};
use std::fs;
use std::io::IoSliceMut;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const SYS_FCHMODAT2: i64 = 452;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) mod legacy_syscall {
    pub const OPEN: Option<i64> = Some(libc::SYS_open);
    pub const RENAME: Option<i64> = Some(libc::SYS_rename);
    pub const LINK: Option<i64> = Some(libc::SYS_link);
    pub const SYMLINK: Option<i64> = Some(libc::SYS_symlink);
    pub const UNLINK: Option<i64> = Some(libc::SYS_unlink);
    pub const RMDIR: Option<i64> = Some(libc::SYS_rmdir);
    pub const MKDIR: Option<i64> = Some(libc::SYS_mkdir);
    pub const MKNOD: Option<i64> = Some(libc::SYS_mknod);
    pub const CREAT: Option<i64> = Some(libc::SYS_creat);
    pub const CHMOD: Option<i64> = Some(libc::SYS_chmod);
    pub const CHOWN: Option<i64> = Some(libc::SYS_chown);
    pub const LCHOWN: Option<i64> = Some(libc::SYS_lchown);
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) mod legacy_syscall {
    pub const OPEN: Option<i64> = None;
    pub const RENAME: Option<i64> = None;
    pub const LINK: Option<i64> = None;
    pub const SYMLINK: Option<i64> = None;
    pub const UNLINK: Option<i64> = None;
    pub const RMDIR: Option<i64> = None;
    pub const MKDIR: Option<i64> = None;
    pub const MKNOD: Option<i64> = None;
    pub const CREAT: Option<i64> = None;
    pub const CHMOD: Option<i64> = None;
    pub const CHOWN: Option<i64> = None;
    pub const LCHOWN: Option<i64> = None;
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "syscall argument registers are zero- or sign-extended u64 in seccomp_notif"
)]
fn syscall_u32(value: u64) -> u32 {
    value as u32
}

fn syscall_i32(value: u64) -> i32 {
    syscall_u32(value).cast_signed()
}

fn open_flag_names(flags: i32) -> Vec<&'static str> {
    let mut names = Vec::new();
    match flags & libc::O_ACCMODE {
        libc::O_WRONLY => names.push("O_WRONLY"),
        libc::O_RDWR => names.push("O_RDWR"),
        _ => names.push("O_RDONLY"),
    }
    if flags & libc::O_CREAT != 0 {
        names.push("O_CREAT");
    }
    if flags & libc::O_TRUNC != 0 {
        names.push("O_TRUNC");
    }
    if flags & libc::O_APPEND != 0 {
        names.push("O_APPEND");
    }
    names
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(super) enum MutationSyscall {
    Renameat2,
    Renameat,
    Linkat,
    Symlinkat,
    Unlinkat,
    Mkdirat,
    Mknodat,
    Truncate,
    Fchmod,
    Fchmodat,
    Fchmodat2,
    Fchown,
    Fchownat,
    Utimensat,
    Fsetxattr,
    Setxattr,
    Lsetxattr,
    Fremovexattr,
    Removexattr,
    Lremovexattr,
    Rename,
    Link,
    Symlink,
    Unlink,
    Rmdir,
    Mkdir,
    Mknod,
    Creat,
    Chmod,
    Chown,
    Lchown,
}

impl MutationSyscall {
    pub(super) fn no_follow(self, args: &[u64; 6]) -> bool {
        let flag = |index: usize| syscall_i32(args[index]) & libc::AT_SYMLINK_NOFOLLOW != 0;
        let follow = |index: usize| syscall_i32(args[index]) & libc::AT_SYMLINK_FOLLOW != 0;
        match self {
            Self::Unlink
            | Self::Unlinkat
            | Self::Rmdir
            | Self::Lchown
            | Self::Lsetxattr
            | Self::Lremovexattr
            | Self::Link => true,
            Self::Fchownat => flag(4),
            Self::Fchmodat2 | Self::Utimensat => flag(3),
            Self::Linkat => !follow(4),
            Self::Renameat2
            | Self::Renameat
            | Self::Symlinkat
            | Self::Mkdirat
            | Self::Mknodat
            | Self::Truncate
            | Self::Fchmodat
            | Self::Fchmod
            | Self::Fchown
            | Self::Fsetxattr
            | Self::Fremovexattr
            | Self::Setxattr
            | Self::Removexattr
            | Self::Rename
            | Self::Symlink
            | Self::Mkdir
            | Self::Mknod
            | Self::Creat
            | Self::Chmod
            | Self::Chown => false,
        }
    }

    pub(super) fn is_mkdir(self) -> bool {
        matches!(self, Self::Mkdir | Self::Mkdirat)
    }

    pub(super) fn is_reparent(self) -> bool {
        matches!(
            self,
            Self::Link | Self::Linkat | Self::Rename | Self::Renameat | Self::Renameat2
        )
    }
}

pub(super) struct Syscall {
    pub(super) nr: Option<i64>,
    pub(super) kind: MutationSyscall,
    pub(super) paths: &'static [(Option<usize>, usize)],
    pub(super) landlock_backed: bool,
}

pub(super) const MUTATION_SYSCALLS: &[Syscall] = &[
    Syscall {
        nr: Some(libc::SYS_renameat2),
        kind: MutationSyscall::Renameat2,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_renameat),
        kind: MutationSyscall::Renameat,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_linkat),
        kind: MutationSyscall::Linkat,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_symlinkat),
        kind: MutationSyscall::Symlinkat,
        paths: &[(Some(1), 2)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_unlinkat),
        kind: MutationSyscall::Unlinkat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mkdirat),
        kind: MutationSyscall::Mkdirat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mknodat),
        kind: MutationSyscall::Mknodat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_truncate),
        kind: MutationSyscall::Truncate,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_fchmod),
        kind: MutationSyscall::Fchmod,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchown),
        kind: MutationSyscall::Fchown,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchmodat),
        kind: MutationSyscall::Fchmodat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(SYS_FCHMODAT2),
        kind: MutationSyscall::Fchmodat2,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchownat),
        kind: MutationSyscall::Fchownat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_utimensat),
        kind: MutationSyscall::Utimensat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fsetxattr),
        kind: MutationSyscall::Fsetxattr,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fremovexattr),
        kind: MutationSyscall::Fremovexattr,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_setxattr),
        kind: MutationSyscall::Setxattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lsetxattr),
        kind: MutationSyscall::Lsetxattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_removexattr),
        kind: MutationSyscall::Removexattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lremovexattr),
        kind: MutationSyscall::Lremovexattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::RENAME,
        kind: MutationSyscall::Rename,
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::LINK,
        kind: MutationSyscall::Link,
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::SYMLINK,
        kind: MutationSyscall::Symlink,
        paths: &[(None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::UNLINK,
        kind: MutationSyscall::Unlink,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::RMDIR,
        kind: MutationSyscall::Rmdir,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKDIR,
        kind: MutationSyscall::Mkdir,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKNOD,
        kind: MutationSyscall::Mknod,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CREAT,
        kind: MutationSyscall::Creat,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CHMOD,
        kind: MutationSyscall::Chmod,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::CHOWN,
        kind: MutationSyscall::Chown,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::LCHOWN,
        kind: MutationSyscall::Lchown,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
];

struct Open {
    flags: i32,
    mode: u32,
    resolve: u64,
}

impl Open {
    fn from_args(request: &libc::seccomp_notif, legacy_open: bool) -> SysResult<Self> {
        let args = &request.data.args;
        let flags_arg = if legacy_open { 1 } else { 2 };
        let mode_arg = if legacy_open { 2 } else { 3 };
        let flags = i32::try_from(args[flags_arg]).map_err(|_| BrokerError::InvalidAddress)?;
        Ok(Self {
            flags,
            mode: syscall_u32(args[mode_arg]),
            resolve: 0,
        })
    }

    fn from_how(request: &libc::seccomp_notif, process: &TargetProcess) -> SysResult<Self> {
        let args = &request.data.args;
        let addr = usize::try_from(args[2]).map_err(|_| BrokerError::BadAddress)?;
        let size = usize::try_from(args[3]).map_err(|_| BrokerError::InvalidAddress)?;
        if size < OPEN_HOW_SIZE {
            return Err(BrokerError::InvalidAddress);
        }
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| BrokerError::SystemCall { errno: libc::EIO })?;
        if size > page_size {
            return Err(BrokerError::SystemCall { errno: libc::E2BIG });
        }
        if addr == 0 {
            return Err(BrokerError::BadAddress);
        }

        let mut buf = vec![0_u8; size];
        let mut local = [IoSliceMut::new(&mut buf)];
        let target = [nix::sys::uio::RemoteIoVec {
            base: addr,
            len: size,
        }];
        let copied = nix::sys::uio::process_vm_readv(process.pid, &mut local, &target)?;
        if copied != size {
            return Err(BrokerError::BadAddress);
        }
        if buf[OPEN_HOW_SIZE..].iter().any(|byte| *byte != 0) {
            return Err(BrokerError::SystemCall { errno: libc::E2BIG });
        }

        let how = OpenHow {
            flags: u64::from_ne_bytes(buf[0..8].try_into().map_err(|_| BrokerError::BadAddress)?),
            mode: u64::from_ne_bytes(buf[8..16].try_into().map_err(|_| BrokerError::BadAddress)?),
            resolve: u64::from_ne_bytes(
                buf[16..24]
                    .try_into()
                    .map_err(|_| BrokerError::BadAddress)?,
            ),
        };
        validate_open_how(&how)?;
        Ok(Self {
            flags: i32::try_from(how.flags).map_err(|_| BrokerError::InvalidAddress)?,
            mode: u32::try_from(how.mode).map_err(|_| BrokerError::InvalidAddress)?,
            resolve: how.resolve,
        })
    }
}

fn validate_open_how(how: &OpenHow) -> SysResult<()> {
    match how.openat2(libc::AT_FDCWD, &c"".to_owned()) {
        Err(libc::ENOENT) => Ok(()),
        Err(errno) => Err(BrokerError::SystemCall { errno }),
        Ok(_) => Err(BrokerError::SystemCall { errno: libc::EIO }),
    }
}

struct OpenDenial {
    operation: TrapOperation,
    path: PathBuf,
    requested_path: PathBuf,
    syscall: &'static str,
    flags: i32,
    mode: u32,
    grant: Option<OpenGrant>,
    reason: DenialReason,
    pid: u32,
    report: bool,
}

fn deny_open(
    details: OpenDenial,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    if !details.report {
        return Err(BrokerError::PolicyDenied);
    }

    let OpenDenial {
        operation,
        path,
        requested_path,
        syscall,
        flags,
        mode,
        grant,
        reason,
        pid,
        ..
    } = details;
    if query_enabled {
        let query_id = *next_query_id;
        *next_query_id += 1;
        let grant = if flags & libc::O_PATH != 0 {
            None
        } else {
            Some(Grant::Open(match grant {
                Some(grant) => grant,
                None => OpenGrant::new(&path, flags, mode)
                    .map_err(|errno| BrokerError::SystemCall { errno })?,
            }))
        };
        return Ok(NotificationResult::query(
            query_id,
            Trap::filesystem(
                FilesystemDenial {
                    operation,
                    path,
                    requested_path,
                    syscall,
                    flags: open_flag_names(flags),
                    reason,
                    process: TargetProcess::from_raw(pid).context(),
                },
                Some(query_id),
            ),
            grant,
        ));
    }

    denials.record(Denial::Filesystem(FilesystemDenial {
        operation,
        path,
        requested_path,
        syscall,
        flags: open_flag_names(flags),
        reason,
        process: TargetProcess::from_raw(pid).context(),
    }));
    Err(BrokerError::PolicyDenied)
}

struct OpenRequest {
    process: TargetProcess,
    dirfd: RawFd,
    path: PathBuf,
    flags: i32,
    mode: u32,
    resolve: u64,
    syscall: &'static str,
}

fn read_open_request(request: &libc::seccomp_notif) -> SysResult<OpenRequest> {
    let nr = i64::from(request.data.nr);
    let openat2 = nr == libc::SYS_openat2;
    let legacy_open = matches!(legacy_syscall::OPEN, Some(open) if open == nr);
    let dirfd = if legacy_open {
        libc::AT_FDCWD
    } else {
        syscall_i32(request.data.args[0])
    };
    let path_arg = usize::from(!legacy_open);
    let path_ptr =
        usize::try_from(request.data.args[path_arg]).map_err(|_| BrokerError::BadAddress)?;
    let process = TargetProcess::from_raw(request.pid);
    let open = if openat2 {
        Open::from_how(request, &process)?
    } else {
        Open::from_args(request, legacy_open)?
    };
    let syscall = if openat2 {
        "openat2"
    } else if legacy_open {
        "open"
    } else {
        "openat"
    };
    Ok(OpenRequest {
        dirfd,
        path: process.read_nonempty_path(path_ptr)?,
        flags: open.flags,
        mode: open.mode,
        resolve: open.resolve,
        syscall,
        process,
    })
}

fn resolve_open_target(
    process: &TargetProcess,
    dirfd: i32,
    path: &Path,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> SysResult<(PathBuf, PathBuf, Option<OpenGrant>)> {
    if resolve != 0 {
        let (raw, resolved, grant) =
            OpenGrant::new_openat2(process, dirfd, path, flags, mode, resolve)
                .map_err(|errno| BrokerError::SystemCall { errno })?;
        Ok((raw, resolved, Some(grant)))
    } else {
        let raw = process.resolve_path(dirfd, path)?;
        let trailing_slash = raw.as_os_str().as_bytes().ends_with(b"/");
        if trailing_slash || flags & libc::O_NOFOLLOW != 0 {
            let target = if trailing_slash {
                raw.clone()
            } else {
                normalize_path_nofollow(&raw)
            };
            let grant = OpenGrant::new(&target, flags, mode)
                .map_err(|errno| BrokerError::SystemCall { errno })?;
            let resolved = match &grant.kind {
                OpenKind::Reopen(handle) => open_fd_path(handle.as_fd())
                    .map_err(|errno| BrokerError::SystemCall { errno })?,
                OpenKind::Create { .. } => target,
            };
            Ok((raw, resolved, Some(grant)))
        } else {
            let resolved = normalize_path(&raw);
            Ok((raw, resolved, None))
        }
    }
}

pub(super) fn handle_openat(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let OpenRequest {
        process,
        dirfd,
        path,
        flags,
        mode,
        resolve,
        syscall,
    } = read_open_request(request)?;

    let (raw, resolved, open_grant) =
        resolve_open_target(&process, dirfd, &path, flags, mode, resolve)?;
    let wants_write = flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0;
    let reports_write = flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0;
    let wants_read = flags & libc::O_WRONLY == 0;
    let hard_read_denied = wants_read && resolved.is_under_any(&policy.read_denied_always_roots);
    let hard_write_denied = wants_write && resolved.is_under_any(&policy.write_denied_always_roots);
    let query_enabled = query_enabled && !hard_read_denied && !hard_write_denied;

    if wants_write
        && !hard_read_denied
        && let Some(reason) = policy.write_reason(&resolved, &normalize_path_lexically(&raw), true)
    {
        if flags & libc::O_CREAT == 0 && !resolved.try_exists()? {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        return deny_open(
            OpenDenial {
                operation: TrapOperation::Write,
                path: resolved,
                requested_path: path,
                syscall,
                flags,
                mode,
                grant: open_grant,
                reason,
                pid: request.pid,
                report: reports_write,
            },
            denials,
            query_enabled,
            next_query_id,
        );
    }
    if wants_read && let Some(reason) = policy.read_reason(&resolved) {
        if !resolved.try_exists()? {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        return deny_open(
            OpenDenial {
                operation: TrapOperation::Read,
                path: resolved,
                requested_path: path,
                syscall,
                flags,
                mode,
                grant: open_grant,
                reason,
                pid: request.pid,
                report: true,
            },
            denials,
            query_enabled,
            next_query_id,
        );
    }

    if flags & libc::O_PATH != 0 {
        return Ok(NotificationResult::Continue);
    }

    let grant = open_grant
        .map_or_else(|| OpenGrant::new(&resolved, flags, mode), Ok)
        .map_err(|errno| BrokerError::SystemCall { errno })?;
    Ok(NotificationResult::Open(grant))
}

fn reparent_read_denial(
    policy: &AccessPolicy,
    spec: &Syscall,
    slots: &[Option<(PathBuf, PathBuf)>],
) -> Option<(usize, DenialReason, TrapOperation)> {
    if !spec.kind.is_reparent() {
        return None;
    }
    let (source, _) = slots.first().and_then(Option::as_ref)?;
    let reason = policy.read_reason(source)?;
    let dest_readable = slots
        .get(1)
        .and_then(Option::as_ref)
        .is_none_or(|(dest, _)| policy.read_reason(dest).is_none());
    dest_readable.then_some((0, reason, TrapOperation::Read))
}

fn validate_mutation_flags(kind: MutationSyscall, args: &[u64; 6]) -> SysResult<()> {
    let flags = match kind {
        MutationSyscall::Fchmodat2 | MutationSyscall::Utimensat => syscall_i32(args[3]),
        MutationSyscall::Fchownat => syscall_i32(args[4]),
        _ => return Ok(()),
    };
    if flags & !(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW) != 0 {
        return Err(BrokerError::SystemCall {
            errno: libc::EINVAL,
        });
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "mutation path checks and grant construction share one policy decision"
)]
pub(super) fn handle_mutation(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let syscall = i64::from(request.data.nr);
    let Some(spec) = MUTATION_SYSCALLS.iter().find(|s| s.nr == Some(syscall)) else {
        return Ok(NotificationResult::Continue);
    };
    validate_mutation_flags(spec.kind, &request.data.args)?;
    if spec.paths.is_empty()
        || (spec.kind == MutationSyscall::Utimensat && request.data.args[1] == 0)
    {
        return handle_fd_mutation(policy, spec, request, denials, query_enabled, next_query_id);
    }

    let process = TargetProcess::from_raw(request.pid);
    let mut slots: Vec<Option<(PathBuf, PathBuf)>> = Vec::with_capacity(spec.paths.len());
    let mut denial: Option<(usize, DenialReason, TrapOperation)> = None;
    let no_follow = spec.kind.no_follow(&request.data.args);
    for (index, (dirfd_arg, path_arg)) in spec.paths.iter().enumerate() {
        let dirfd = match dirfd_arg {
            Some(arg) => syscall_i32(request.data.args[*arg]),
            None => libc::AT_FDCWD,
        };
        let path_ptr =
            usize::try_from(request.data.args[*path_arg]).map_err(|_| BrokerError::BadAddress)?;
        let path = process.read_path(path_ptr)?;
        if empty_path_uses_fd(spec.kind, &request.data.args, &path)? {
            return handle_fd_mutation(
                policy,
                spec,
                request,
                denials,
                query_enabled,
                next_query_id,
            );
        }
        let raw = process.resolve_path(dirfd, &path)?;
        if spec.kind.is_mkdir() && mkdir_target_exists(&raw) {
            return Err(BrokerError::SystemCall {
                errno: libc::EEXIST,
            });
        }
        let resolved = if no_follow {
            normalize_path_nofollow(&raw)
        } else {
            normalize_path(&raw)
        };
        if denial.is_none() {
            let lexical = normalize_path_lexically(&raw);
            let surface_allow_miss = query_enabled || !spec.landlock_backed;
            if let Some(reason) = policy.write_reason(&resolved, &lexical, surface_allow_miss) {
                denial = Some((index, reason, TrapOperation::Write));
            }
        }
        slots.push(Some((resolved, path)));
    }

    let hard_read_denial = spec
        .kind
        .is_reparent()
        .then(|| {
            slots.iter().position(|slot| {
                slot.as_ref().is_some_and(|(path, _)| {
                    path.is_under_any(&policy.read_denied_always_roots)
                        || policy
                            .read_denied_always_roots
                            .iter()
                            .any(|root| root.is_under(path))
                })
            })
        })
        .flatten();
    let hard_write_denial = slots.iter().position(|slot| {
        slot.as_ref().is_some_and(|(path, _)| {
            path.is_under_any(&policy.write_denied_always_roots)
                || (spec.kind.is_reparent()
                    && policy
                        .write_denied_always_roots
                        .iter()
                        .any(|root| root.is_under(path)))
        })
    });
    let query_enabled = query_enabled && hard_read_denial.is_none() && hard_write_denial.is_none();
    denial = hard_read_denial
        .map(|index| (index, DenialReason::DenyMatch, TrapOperation::Read))
        .or_else(|| {
            hard_write_denial.map(|index| (index, DenialReason::DenyMatch, TrapOperation::Write))
        })
        .or(denial)
        .or_else(|| reparent_read_denial(policy, spec, &slots));

    let Some((index, reason, operation)) = denial else {
        let must_pin = !policy.write_denied_roots.is_empty()
            || !policy.write_denied_patterns.is_empty()
            || !policy.write_denied_links.is_empty()
            || !spec.landlock_backed
            || (spec.kind.is_reparent() && !matches!(policy.read_access, ReadAccess::Unrestricted));
        if must_pin {
            match mutation_grant(spec, request, &process, &slots)? {
                Some(Grant::Mutation(grant)) => {
                    return Ok(NotificationResult::Mutation(grant));
                }
                Some(Grant::Open(grant)) => {
                    return Ok(NotificationResult::Open(grant));
                }
                Some(Grant::Socket(_)) | None => {
                    return Err(BrokerError::SystemCall { errno: libc::EIO });
                }
            }
        }
        return Ok(NotificationResult::Continue);
    };
    let (resolved, path) = slots[index].clone().ok_or(BrokerError::InvalidAddress)?;

    if !query_enabled {
        denials.record(Denial::Filesystem(FilesystemDenial {
            operation,
            path: resolved,
            requested_path: path,
            syscall: spec.kind.into(),
            flags: Vec::new(),
            reason,
            process: process.context(),
        }));
        return Err(BrokerError::PolicyDenied);
    }

    let qid = *next_query_id;
    *next_query_id += 1;
    let grant = mutation_grant(spec, request, &process, &slots)?;
    Ok(NotificationResult::query(
        qid,
        Trap::filesystem(
            FilesystemDenial {
                operation,
                path: resolved,
                requested_path: path,
                syscall: spec.kind.into(),
                flags: Vec::new(),
                reason,
                process: process.context(),
            },
            Some(qid),
        ),
        grant,
    ))
}

fn mutation_target_fd(
    process: &TargetProcess,
    child_fd: RawFd,
    kind: MutationSyscall,
) -> SysResult<OwnedFd> {
    let at_cwd = child_fd == libc::AT_FDCWD
        && matches!(kind, MutationSyscall::Fchmodat2 | MutationSyscall::Fchownat);
    if child_fd < 0 && !at_cwd {
        return Err(BrokerError::BadFileDescriptor);
    }
    if !at_cwd {
        return process.duplicate_fd(child_fd);
    }

    let cwd = Path::new("/proc")
        .join(process.pid.as_raw().to_string())
        .join("cwd");
    open_path(&cwd, libc::O_PATH | libc::O_CLOEXEC)
        .map_err(|errno| BrokerError::SystemCall { errno })
}

fn handle_fd_mutation(
    policy: &AccessPolicy,
    spec: &Syscall,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let args = &request.data.args;
    let process = TargetProcess::from_raw(request.pid);
    if spec.kind == MutationSyscall::Utimensat && syscall_i32(args[3]) != 0 {
        return Err(BrokerError::SystemCall {
            errno: libc::EINVAL,
        });
    }

    let target = mutation_target_fd(&process, syscall_i32(args[0]), spec.kind)?;
    let requested_path =
        fs::read_link(Path::new("/proc/self/fd").join(target.as_raw_fd().to_string()))?;
    let mutation = match spec.kind {
        MutationSyscall::Fchmod => FdMutation::Chmod {
            mode: syscall_u32(args[1]),
        },
        MutationSyscall::Fchmodat2 => FdMutation::ChmodAt {
            mode: syscall_u32(args[2]),
            flags: syscall_i32(args[3]),
        },
        MutationSyscall::Fchown => FdMutation::Chown {
            uid: syscall_u32(args[1]),
            gid: syscall_u32(args[2]),
        },
        MutationSyscall::Fchownat => FdMutation::ChownAt {
            uid: syscall_u32(args[2]),
            gid: syscall_u32(args[3]),
            flags: syscall_i32(args[4]),
        },
        MutationSyscall::Utimensat => FdMutation::Utimes {
            times: process.read_times(args[2])?,
        },
        MutationSyscall::Fsetxattr => FdMutation::SetXattr {
            name: process.read_xattr_name(args[1])?,
            value: process.read_bytes(args[2], args[3])?,
            flags: syscall_i32(args[4]),
        },
        MutationSyscall::Fremovexattr => FdMutation::RemoveXattr {
            name: process.read_xattr_name(args[1])?,
        },
        _ => {
            return Err(BrokerError::SystemCall {
                errno: libc::EINVAL,
            });
        }
    };
    let no_follow = match spec.kind {
        MutationSyscall::Fchmodat2 => syscall_i32(args[3]) & libc::AT_SYMLINK_NOFOLLOW != 0,
        MutationSyscall::Fchownat => syscall_i32(args[4]) & libc::AT_SYMLINK_NOFOLLOW != 0,
        _ => false,
    };
    let resolved = if no_follow {
        normalize_path_nofollow(&requested_path)
    } else {
        normalize_path(&requested_path)
    };
    let lexical = normalize_path_lexically(&requested_path);
    let hard_write_denied = resolved.is_under_any(&policy.write_denied_always_roots);
    let query_enabled = query_enabled && !hard_write_denied;
    let reason = policy.write_reason(&resolved, &lexical, true);
    let operation = MutationGrant {
        op: MutationOp::Fd { target, mutation },
        anchors: Vec::new(),
        no_follow: false,
    };

    let Some(reason) = reason else {
        return Ok(NotificationResult::Mutation(operation));
    };

    let denial = FilesystemDenial {
        operation: TrapOperation::Write,
        path: resolved,
        requested_path,
        syscall: spec.kind.into(),
        flags: Vec::new(),
        reason,
        process: process.context(),
    };
    if !query_enabled {
        denials.record(Denial::Filesystem(denial));
        return Err(BrokerError::PolicyDenied);
    }

    let qid = *next_query_id;
    *next_query_id += 1;
    Ok(NotificationResult::query(
        qid,
        Trap::filesystem(denial, Some(qid)),
        Some(Grant::Mutation(operation)),
    ))
}

fn mutation_grant(
    spec: &Syscall,
    request: &libc::seccomp_notif,
    process: &TargetProcess,
    slots: &[Option<(PathBuf, PathBuf)>],
) -> SysResult<Option<Grant>> {
    let args = &request.data.args;
    let op = match spec.kind {
        MutationSyscall::Creat => {
            return creat_grant(slots, syscall_u32(args[1]));
        }
        MutationSyscall::Fchmod
        | MutationSyscall::Fchown
        | MutationSyscall::Fsetxattr
        | MutationSyscall::Fremovexattr => return Ok(None),
        MutationSyscall::Mkdirat => MutationOp::Mkdir {
            mode: syscall_u32(args[2]),
        },
        MutationSyscall::Mkdir => MutationOp::Mkdir {
            mode: syscall_u32(args[1]),
        },
        MutationSyscall::Mknodat => MutationOp::Mknod {
            mode: syscall_u32(args[2]),
            dev: args[3],
        },
        MutationSyscall::Mknod => MutationOp::Mknod {
            mode: syscall_u32(args[1]),
            dev: args[2],
        },
        MutationSyscall::Unlinkat => MutationOp::Unlink {
            flags: syscall_i32(args[2]),
        },
        MutationSyscall::Unlink => MutationOp::Unlink { flags: 0 },
        MutationSyscall::Rmdir => MutationOp::Unlink {
            flags: libc::AT_REMOVEDIR,
        },
        MutationSyscall::Renameat2 => MutationOp::Rename {
            flags: syscall_u32(args[4]),
        },
        MutationSyscall::Renameat | MutationSyscall::Rename => MutationOp::Rename { flags: 0 },
        MutationSyscall::Linkat => MutationOp::Link {
            flags: syscall_i32(args[4]),
        },
        MutationSyscall::Link => MutationOp::Link { flags: 0 },
        MutationSyscall::Symlinkat | MutationSyscall::Symlink => {
            let Some(target) = process.read_target(args[0])? else {
                return Ok(None);
            };
            MutationOp::Symlink { target }
        }
        MutationSyscall::Truncate => MutationOp::Truncate {
            length: args[1].cast_signed(),
        },
        MutationSyscall::Fchmodat => MutationOp::Chmod {
            mode: syscall_u32(args[2]),
        },
        MutationSyscall::Fchmodat2 => MutationOp::ChmodAt {
            mode: syscall_u32(args[2]),
            flags: syscall_i32(args[3]),
        },
        MutationSyscall::Chmod => MutationOp::Chmod {
            mode: syscall_u32(args[1]),
        },
        MutationSyscall::Fchownat => MutationOp::ChownAt {
            uid: syscall_u32(args[2]),
            gid: syscall_u32(args[3]),
            flags: syscall_i32(args[4]),
        },
        MutationSyscall::Chown | MutationSyscall::Lchown => MutationOp::Chown {
            uid: syscall_u32(args[1]),
            gid: syscall_u32(args[2]),
        },
        MutationSyscall::Utimensat => MutationOp::Utimes {
            times: process.read_times(args[2])?,
            flags: syscall_i32(args[3]),
        },
        MutationSyscall::Setxattr | MutationSyscall::Lsetxattr => MutationOp::SetXattr {
            name: process.read_xattr_name(args[1])?,
            value: process.read_bytes(args[2], args[3])?,
            flags: syscall_i32(args[4]),
        },
        MutationSyscall::Removexattr | MutationSyscall::Lremovexattr => MutationOp::RemoveXattr {
            name: process.read_xattr_name(args[1])?,
        },
    };

    let mut anchors = Vec::with_capacity(slots.len());
    for slot in slots {
        let Some((resolved, _)) = slot else {
            return Ok(None);
        };
        anchors.push(Anchor::new(resolved).map_err(|errno| BrokerError::SystemCall { errno })?);
    }

    Ok(Some(Grant::Mutation(MutationGrant {
        op,
        anchors,
        no_follow: spec.kind.no_follow(args),
    })))
}

fn creat_grant(slots: &[Option<(PathBuf, PathBuf)>], mode: u32) -> SysResult<Option<Grant>> {
    let Some((resolved, _)) = slots.first().and_then(Option::as_ref) else {
        return Ok(None);
    };
    OpenGrant::new(
        resolved,
        libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
        mode,
    )
    .map(|grant| Some(Grant::Open(grant)))
    .map_err(|errno| BrokerError::SystemCall { errno })
}

fn empty_path_uses_fd(kind: MutationSyscall, args: &[u64; 6], path: &Path) -> SysResult<bool> {
    if !path.as_os_str().is_empty() {
        return Ok(false);
    }
    let flags = match kind {
        MutationSyscall::Fchmodat2 => syscall_i32(args[3]),
        MutationSyscall::Fchownat => syscall_i32(args[4]),
        _ => 0,
    };
    if flags & libc::AT_EMPTY_PATH != 0 {
        Ok(true)
    } else {
        Err(BrokerError::SystemCall {
            errno: libc::ENOENT,
        })
    }
}

fn mkdir_target_exists(path: &Path) -> bool {
    let Ok(anchor) = Anchor::new(&normalize_path_nofollow(path)) else {
        return false;
    };
    let flags = if path.as_os_str().as_bytes().ends_with(b"/") {
        0
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    let mut stat = unsafe { mem::zeroed::<libc::stat>() };
    unsafe {
        libc::fstatat(
            anchor.dir.as_raw_fd(),
            anchor.name.as_ptr(),
            std::ptr::addr_of_mut!(stat),
            flags,
        ) == 0
    }
}
