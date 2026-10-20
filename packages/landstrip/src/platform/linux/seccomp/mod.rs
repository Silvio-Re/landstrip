// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Seccomp filters and user-notification broker for network policy.
//!
//! Direct TCP is denied by default. Configured proxy ports and, when
//! `allowLocalBinding` is enabled, arbitrary loopback ports are allowed. Local
//! TCP bind also requires `allowLocalBinding`. Non-TCP INET, packet, and netlink
//! sockets are blocked.
//!
//! Unix sockets are denied by default. `allowUnixSockets` mediates pathname
//! `connect` and `bind`; unnamed sockets and `socketpair` are not path-mediated.
//! `allowAllUnixSockets` permits new Unix sockets without path checks. systemd
//! and D-Bus control sockets stay denied either way: they start processes that
//! would inherit neither Landlock nor seccomp. Host-created abstract Unix sockets
//! are denied by Landlock scope on ABI 6+ (Linux 6.12+); the broker cannot tell
//! those apart from sockets the child created itself.

mod error;
mod fs;
mod grant;
mod network;
mod notify;
mod process;
mod supervise;

pub(crate) use notify::ensure_notification_supported;
pub(crate) use supervise::NotificationSyscalls;

use super::filter::{build_errno_filter, build_io_uring_deny, build_notify_filter, load_filters};
use super::landlock::enforce_access_policy;
use super::namespace::Launch;
use super::signals::ForwardSignals;
use crate::error::{Error as LandstripError, Mechanism};
use crate::platform::unix::close_inherited_fds;
use crate::policy::{AccessPolicy, UnixSocketAccess};
use crate::trap::Trap;
use crate::trap_fd::TrapFd;
use anyhow::Result;
use fs::MUTATION_SYSCALLS;
use nix::errno::Errno;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg, setsockopt, sockopt,
};
use nix::unistd::Pid;
use process::{Subreaper, TargetProcess};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use supervise::{NamespaceId, Supervisor};

fn send_fd(socket: &mut File, fd: BorrowedFd<'_>) -> Result<()> {
    let byte = [0_u8];
    let iov = [IoSlice::new(&byte)];
    let fds = [fd.as_raw_fd()];
    loop {
        match sendmsg::<()>(
            socket.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        ) {
            Ok(_) => break,
            Err(Errno::EINTR) => {}
            Err(error) => return Err(LandstripError::from(error).into()),
        }
    }
    read_ack(socket)
}

fn send_listener(socket: &mut File, fd: BorrowedFd<'_>) -> Result<()> {
    socket
        .write_all(&[0_u8])
        .map_err(LandstripError::supervise)?;
    socket
        .write_all(&fd.as_raw_fd().to_ne_bytes())
        .map_err(LandstripError::supervise)?;
    read_ack(socket)
}

fn read_ack(socket: &mut File) -> Result<()> {
    let mut ack = [0_u8];
    socket
        .read_exact(&mut ack)
        .map_err(LandstripError::supervise)?;
    if ack != [0] {
        return Err(LandstripError::supervise("notify: invalid acknowledgment").into());
    }
    Ok(())
}

fn send_trap(socket: &mut File, trap: &Trap) -> Result<()> {
    let payload = trap.to_string();
    let length = u32::try_from(payload.len())
        .map_err(|_| LandstripError::supervise("notify: trap is too large"))?;

    socket
        .write_all(&[1_u8])
        .map_err(LandstripError::supervise)?;
    socket
        .write_all(&length.to_be_bytes())
        .map_err(LandstripError::supervise)?;
    socket
        .write_all(payload.as_bytes())
        .map_err(LandstripError::supervise)?;
    Ok(())
}

enum NotifyStartup<'a> {
    Ready(BorrowedFd<'a>, NamespaceId),
    Trap(String),
}

fn get_notify_fd<'a>(
    socket: &File,
    handoff_by_pidfd: bool,
    subreaper: &'a mut Subreaper,
) -> Result<NotifyStartup<'a>> {
    let mut marker = [0_u8];
    let mut iov = [IoSliceMut::new(&mut marker)];
    let mut control = nix::cmsg_space!([RawFd; 1], libc::ucred);
    let (fd, sender) = loop {
        let message = match recvmsg::<()>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::empty(),
        ) {
            Ok(message) => message,
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(LandstripError::from(error).into()),
        };
        let mut fd = None;
        let mut sender = None;
        for control in message.cmsgs().map_err(LandstripError::from)? {
            match control {
                ControlMessageOwned::ScmRights(fds) => fd = fds.first().copied(),
                ControlMessageOwned::ScmCredentials(credentials) => {
                    sender = Some(credentials.pid());
                }
                _ => {}
            }
        }
        if message.bytes == 0 {
            return Err(LandstripError::supervise("notify: unexpected eof").into());
        }
        break (fd, sender);
    };

    let mut socket = socket;
    match marker[0] {
        0 => {
            let sender = sender
                .ok_or_else(|| LandstripError::supervise("notify: missing sender credentials"))?;
            let notify = if handoff_by_pidfd {
                let mut number = [0_u8; mem::size_of::<RawFd>()];
                socket
                    .read_exact(&mut number)
                    .map_err(LandstripError::supervise)?;
                let target = TargetProcess::new(Pid::from_raw(sender));
                target
                    .duplicate_fd(RawFd::from_ne_bytes(number))
                    .map_err(|error| {
                        LandstripError::supervise(io::Error::from_raw_os_error(error.errno()))
                    })?
            } else {
                let fd =
                    fd.ok_or_else(|| LandstripError::supervise("notify: missing descriptor"))?;
                // SAFETY: SCM_RIGHTS transfers ownership of the received descriptor.
                unsafe { OwnedFd::from_raw_fd(fd) }
            };
            let notify = subreaper.retain_listener(notify);
            // Pin namespace identity before acknowledging: the tool may exit immediately.
            let path = Path::new("/proc").join(sender.to_string()).join("ns/mnt");
            let namespace =
                NamespaceId::try_from(path.as_path()).map_err(LandstripError::supervise)?;
            socket
                .write_all(&[0_u8])
                .map_err(LandstripError::supervise)?;
            Ok(NotifyStartup::Ready(notify, namespace))
        }
        1 => {
            let mut length = [0_u8; 4];
            let mut socket = socket;
            socket
                .read_exact(&mut length)
                .map_err(LandstripError::supervise)?;
            let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
            if length > 1_048_576 {
                return Err(LandstripError::supervise("notify: trap is too large").into());
            }
            let mut payload = vec![0_u8; length];
            socket
                .read_exact(&mut payload)
                .map_err(LandstripError::supervise)?;
            let trap = String::from_utf8(payload).map_err(|error| {
                LandstripError::supervise(format!("notify: invalid trap: {error}"))
            })?;
            if serde_json::from_str::<serde_json::Value>(&trap).is_err() {
                return Err(LandstripError::supervise("notify: invalid trap").into());
            }
            Ok(NotifyStartup::Trap(trap))
        }
        _ => Err(LandstripError::supervise("notify: invalid marker").into()),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "broker setup and fork branches share one lifecycle"
)]
pub(super) fn run_broker(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
    needs_filesystem: bool,
    trap_fd: Option<&TrapFd>,
    inherited_fds: &[RawFd],
) -> Result<i32> {
    let needs_network = policy.network_access.needs_network_broker();
    let notify_bind = needs_network && policy.network_access.needs_bind_broker();
    let notify_connect = (needs_network && policy.network_access.needs_network_broker())
        || needs_filesystem
        || matches!(
            policy.network_access.unix_socket_access(),
            UnixSocketAccess::Unrestricted
        );
    let notify_filesystem = needs_filesystem;
    let unix_sockets = policy.network_access.unix_socket_access().into();
    ensure_notification_supported()?;

    let syscalls = NotificationSyscalls::new();
    let restricted = !policy.network_access.is_unrestricted();
    let allow_local_binding = policy.network_access.allows_local_binding();
    let handoff_by_pidfd = restricted && allow_local_binding;
    let errno = build_errno_filter(&syscalls, restricted, allow_local_binding, unix_sockets)?;
    let io_uring = Some(build_io_uring_deny(&syscalls)?);

    let mut notify_syscalls: Vec<i64> = Vec::new();
    if notify_bind {
        notify_syscalls.push(syscalls.bind);
    }
    if notify_connect {
        notify_syscalls.push(syscalls.connect);
    }
    if restricted && allow_local_binding {
        notify_syscalls.push(syscalls.sendto);
        notify_syscalls.push(syscalls.sendmsg);
        notify_syscalls.push(syscalls.sendmmsg);
    }
    if notify_filesystem {
        notify_syscalls.extend(syscalls.filesystem_syscalls());
    }
    notify_syscalls.extend(
        MUTATION_SYSCALLS
            .iter()
            .filter(|spec| notify_filesystem || !spec.landlock_backed)
            .filter_map(|spec| spec.nr),
    );
    let notify = if notify_syscalls.is_empty() {
        None
    } else {
        Some(build_notify_filter(&notify_syscalls)?)
    };

    let (parent, child_sock) = UnixStream::pair().map_err(LandstripError::supervise)?;
    setsockopt(&parent, sockopt::PassCred, &true).map_err(LandstripError::from)?;
    // File uses read/write; UnixStream's sendto would block on our own notify filter.
    let parent = File::from(OwnedFd::from(parent));
    let child_sock = File::from(OwnedFd::from(child_sock));
    let launch = Launch::new().map_err(|error| {
        LandstripError::sandbox_setup(Mechanism::Namespace, error.into_boxed_dyn_error())
    })?;
    let mut subreaper = Subreaper::acquire()?;

    // SAFETY: policy lowering is single-threaded; the child either execs the tool or exits.
    let fork_result = unsafe { launch.fork() }.map_err(|error| {
        LandstripError::sandbox_setup(Mechanism::Namespace, error.into_boxed_dyn_error())
    })?;
    match fork_result {
        super::namespace::ForkResult::Child(child) => {
            drop(parent);
            let mut child_sock = child_sock;
            let mut handed_off = false;

            let result = (|| -> Result<()> {
                child.spawn_tool(&[]).map_err(|error| {
                    LandstripError::sandbox_setup(
                        Mechanism::Namespace,
                        error.into_boxed_dyn_error(),
                    )
                })?;
                enforce_access_policy(policy, false)?;

                {
                    let notify = load_filters(errno.as_ref(), io_uring.as_ref(), notify.as_ref())?;
                    if handoff_by_pidfd {
                        send_listener(&mut child_sock, notify.as_fd())?;
                    } else {
                        send_fd(&mut child_sock, notify.as_fd())?;
                    }
                    handed_off = true;
                }

                let mut excluded = vec![child_sock.as_raw_fd()];
                if let Some(trap_fd) = trap_fd {
                    excluded.push(trap_fd.as_raw_fd());
                }
                close_inherited_fds(&excluded, inherited_fds).map_err(LandstripError::supervise)?;

                let mut child_tool = Command::new(tool);
                child_tool.args(args).current_dir(cwd);

                let error = child_tool.exec();
                Err(LandstripError::launch(tool, error).into())
            })();

            if let Err(error) = result {
                let trap = error
                    .chain()
                    .find_map(|e| e.downcast_ref::<LandstripError>())
                    .map_or_else(|| Trap::internal(format!("{error:#}")), Trap::from);
                if handed_off || send_trap(&mut child_sock, &trap).is_err() {
                    trap.emit_with_fd(trap_fd);
                }
            }

            // SAFETY: _exit terminates the child without running duplicated parent cleanup.
            unsafe { libc::_exit(127) }
        }
        super::namespace::ForkResult::Parent { child } => {
            subreaper.track_descendants();
            drop(child_sock);
            let mut signals = ForwardSignals::new(child)
                .map_err(|error| LandstripError::supervise(error.into_boxed_dyn_error()))?;
            let result = (|| match get_notify_fd(&parent, handoff_by_pidfd, &mut subreaper)? {
                NotifyStartup::Ready(notify, namespace) => {
                    signals.process_pending()?;
                    Supervisor {
                        policy,
                        child,
                        notify_fd: notify,
                        syscalls: &syscalls,
                        notify_filesystem,
                        trap_fd,
                        mount_namespace: namespace,
                        signals: Some(&mut signals),
                    }
                    .run()
                }
                NotifyStartup::Trap(trap) => {
                    if let Some(trap_fd) = trap_fd
                        && let Err(error) = trap_fd.write_line(&trap)
                    {
                        log::debug!("trap fd write failed: {error}");
                    }
                    let _ = writeln!(io::stderr().lock(), "{trap}");
                    Ok(1)
                }
            })();
            drop(parent);
            subreaper.finish()?;
            result
        }
    }
}
