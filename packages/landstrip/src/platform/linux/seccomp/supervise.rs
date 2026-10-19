// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use super::fs::{MUTATION_SYSCALLS, handle_mutation, handle_openat, legacy_syscall};
use super::grant::{Grant, MutationGrant, OpenGrant, SocketGrant};
use super::network::{handle_bind, handle_connect, handle_sendmmsg, handle_sendmsg, handle_sendto};
use super::notify::{NotificationChannel, NotificationResponse, NotificationResult, QueryDecision};
use crate::error::Error as LandstripError;
use crate::policy::AccessPolicy;
use crate::trap::{FilesystemDenial, NetworkOperation, ProcessContext, Trap, TrapOperation};
use crate::trap_fd::TrapFd;
use anyhow::Result;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const POLL_MS: u16 = 100;
const CONTROL_BUFFER_MAX: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum Denial {
    Filesystem(FilesystemDenial),
    Network(NetworkOperation, String, ProcessContext),
}

impl Denial {
    fn report_on_success(&self) -> bool {
        match self {
            Self::Filesystem(denial) => denial.operation == TrapOperation::Write,
            Self::Network(_, _, _) => true,
        }
    }
}

impl From<Denial> for Trap {
    fn from(denial: Denial) -> Self {
        match denial {
            Denial::Filesystem(denial) => Self::filesystem(denial, None),
            Denial::Network(operation, target, process) => {
                Self::network(operation, target, process, None)
            }
        }
    }
}

#[derive(Default)]
pub(super) struct Denials<'a> {
    pub(super) trap_fd: Option<&'a TrapFd>,
    seen: HashSet<Denial>,
    pending: Vec<Denial>,
}

impl<'a> Denials<'a> {
    pub(super) fn new(trap_fd: Option<&'a TrapFd>) -> Self {
        Self {
            trap_fd,
            ..Self::default()
        }
    }

    pub(super) fn write(&self, trap: &Trap) -> io::Result<()> {
        self.trap_fd.map_or(Ok(()), |trap_fd| trap_fd.write(trap))
    }

    pub(super) fn record(&mut self, denial: Denial) {
        if self.seen.insert(denial.clone()) {
            self.pending.push(denial);
        }
    }

    pub(super) fn emit(self, status: WaitStatus) -> i32 {
        let code = match status {
            WaitStatus::Exited(_, code) => code,
            WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
            _ => 1,
        };
        let Self {
            trap_fd, pending, ..
        } = self;
        for denial in pending
            .into_iter()
            .filter(|denial| code != 0 || denial.report_on_success())
        {
            let trap = Trap::from(denial);
            if let Some(trap_fd) = trap_fd
                && let Err(error) = trap_fd.write(&trap)
            {
                log::debug!("trap fd write failed: {error}");
            }
            trap.emit();
        }
        code
    }
}

pub(super) enum HandleResult {
    Respond(libc::seccomp_notif_resp),
    AddFd(OpenGrant),
    RunMutation(MutationGrant),
    RunSocket(SocketGrant),
    Pending(QueryDecision),
}

pub(super) struct NotificationContext<'a> {
    pub(super) policy: &'a AccessPolicy,
    pub(super) syscalls: &'a NotificationSyscalls,
    pub(super) notify_filesystem: bool,
    pub(super) query_enabled: bool,
    pub(super) mount_namespace: NamespaceId,
}

impl NotificationContext<'_> {
    fn handle(
        &self,
        request: &libc::seccomp_notif,
        denials: &mut Denials<'_>,
        next_query_id: &mut u64,
    ) -> HandleResult {
        let syscall = i64::from(request.data.nr);
        let result = if syscall == self.syscalls.bind {
            handle_bind(
                self.policy,
                request,
                denials,
                self.query_enabled,
                next_query_id,
            )
        } else if syscall == self.syscalls.connect {
            handle_connect(
                self.policy,
                request,
                denials,
                self.query_enabled,
                next_query_id,
            )
        } else if syscall == self.syscalls.sendto {
            handle_sendto(request, denials)
        } else if syscall == self.syscalls.sendmsg {
            handle_sendmsg(request, denials)
        } else if syscall == self.syscalls.sendmmsg {
            handle_sendmmsg(request, denials)
        } else if self.notify_filesystem && self.syscalls.is_open(syscall) {
            handle_openat(
                self.policy,
                request,
                denials,
                self.query_enabled,
                next_query_id,
            )
        } else if self.notify_filesystem && self.syscalls.is_handle_syscall(syscall) {
            Err(BrokerError::PolicyDenied)
        } else if self.notify_filesystem
            || MUTATION_SYSCALLS
                .iter()
                .any(|spec| !spec.landlock_backed && spec.nr == Some(syscall))
        {
            handle_mutation(
                self.policy,
                request,
                denials,
                self.query_enabled,
                next_query_id,
            )
        } else {
            Ok(NotificationResult::Continue)
        };

        match result {
            Ok(NotificationResult::Socket(grant)) => HandleResult::RunSocket(grant),
            Ok(NotificationResult::Continue) => {
                HandleResult::Respond(NotificationResponse::continue_syscall(request.id))
            }
            Ok(NotificationResult::Open(grant)) => HandleResult::AddFd(grant),
            Ok(NotificationResult::Mutation(grant)) => HandleResult::RunMutation(grant),
            Ok(NotificationResult::Query(decision)) => HandleResult::Pending(decision),
            Err(error) => {
                let errno = error.errno();
                HandleResult::Respond(NotificationResponse::error(request.id, -errno.abs()))
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct NamespaceId {
    device: u64,
    inode: u64,
}

impl TryFrom<&Path> for NamespaceId {
    type Error = io::Error;

    fn try_from(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl NamespaceId {
    pub(super) fn verify(self, pid: u32) -> SysResult<()> {
        let path = Path::new("/proc").join(pid.to_string()).join("ns/mnt");
        let actual = Self::try_from(path.as_path())?;
        if actual != self {
            return Err(BrokerError::PolicyDenied);
        }
        Ok(())
    }
}

pub(crate) struct NotificationSyscalls {
    pub(crate) bind: i64,
    pub(crate) connect: i64,
    pub(crate) socket: i64,
    pub(crate) sendto: i64,
    pub(crate) sendmsg: i64,
    pub(crate) sendmmsg: i64,
    pub(crate) io_uring_setup: i64,
    pub(crate) io_uring_enter: i64,
    pub(crate) io_uring_register: i64,
    openat: i64,
    openat2: i64,
    open: Option<i64>,
    name_to_handle_at: i64,
    open_by_handle_at: i64,
}

impl NotificationSyscalls {
    pub(crate) fn new() -> Self {
        Self {
            bind: libc::SYS_bind,
            connect: libc::SYS_connect,
            socket: libc::SYS_socket,
            sendto: libc::SYS_sendto,
            sendmsg: libc::SYS_sendmsg,
            sendmmsg: libc::SYS_sendmmsg,
            io_uring_setup: libc::SYS_io_uring_setup,
            io_uring_enter: libc::SYS_io_uring_enter,
            io_uring_register: libc::SYS_io_uring_register,
            openat: libc::SYS_openat,
            openat2: libc::SYS_openat2,
            open: legacy_syscall::OPEN,
            name_to_handle_at: libc::SYS_name_to_handle_at,
            open_by_handle_at: libc::SYS_open_by_handle_at,
        }
    }

    fn is_open(&self, syscall: i64) -> bool {
        syscall == self.openat
            || syscall == self.openat2
            || self.open.is_some_and(|open| open == syscall)
    }

    fn is_handle_syscall(&self, syscall: i64) -> bool {
        syscall == self.name_to_handle_at || syscall == self.open_by_handle_at
    }

    pub(crate) fn filesystem_syscalls(&self) -> Vec<i64> {
        let mut nrs = vec![
            self.openat,
            self.openat2,
            self.name_to_handle_at,
            self.open_by_handle_at,
        ];
        if let Some(open) = self.open {
            nrs.push(open);
        }
        nrs
    }
}

struct PendingQuery {
    request: libc::seccomp_notif,
    grant: Option<Grant>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ControlAction {
    Allow,
    #[serde(other)]
    Deny,
}

#[derive(Deserialize)]
struct ControlResponse {
    query_id: String,
    action: ControlAction,
}

#[allow(
    clippy::too_many_lines,
    reason = "query delivery failure handling must update supervisor state atomically"
)]
pub(super) fn supervise_child(
    policy: &AccessPolicy,
    child: Pid,
    notify_fd: BorrowedFd<'_>,
    syscalls: &NotificationSyscalls,
    notify_filesystem: bool,
    trap_fd: Option<&TrapFd>,
) -> Result<i32> {
    let notify = NotificationChannel::new(notify_fd);
    let mut denials = Denials::new(trap_fd);
    let mut trap_fd = trap_fd
        .filter(|trap_fd| trap_fd.is_stream_socket())
        .map(AsFd::as_fd);
    let query_enabled = trap_fd.is_some();
    let mount_namespace =
        NamespaceId::try_from(Path::new("/proc/self/ns/mnt")).map_err(LandstripError::supervise)?;
    let mut ctx = NotificationContext {
        policy,
        syscalls,
        notify_filesystem,
        query_enabled,
        mount_namespace,
    };
    let mut pending_queries: HashMap<u64, PendingQuery> = HashMap::new();
    let mut control_buffer: Vec<u8> = Vec::new();
    let mut next_query_id: u64 = 1;

    loop {
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => break,
                Ok(status) => return Ok(denials.emit(status)),
                Err(Errno::EINTR) => {}
                Err(error) => return Err(LandstripError::from(error).into()),
            }
        }

        let revents = poll_broker_fds(notify_fd, trap_fd)?;
        if revents.iter().all(PollFlags::is_empty) {
            continue;
        }

        if revents[0].intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            loop {
                match waitpid(child, None) {
                    Ok(status) => return Ok(denials.emit(status)),
                    Err(Errno::EINTR) => {}
                    Err(error) => return Err(LandstripError::from(error).into()),
                }
            }
        }

        if let Some(cfd) = trap_fd {
            let dead = revents[1]
                .intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                || (revents[1].intersects(PollFlags::POLLIN)
                    && process_control_responses(
                        policy,
                        cfd,
                        &mut control_buffer,
                        &mut pending_queries,
                        notify,
                    ));
            if dead {
                deny_all_pending(&mut pending_queries, notify);
                denials.trap_fd = None;
                trap_fd = None;
                ctx.query_enabled = false;
            }
        }

        if !revents[0].intersects(PollFlags::POLLIN) {
            continue;
        }

        let Some((request, handle_result)) =
            receive_handled_notification(notify, &ctx, &mut denials, &mut next_query_id)?
        else {
            continue;
        };
        match handle_result {
            HandleResult::Respond(response) => {
                if let Err(source) = notify.respond(response) {
                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => break,
                            Ok(status) => return Ok(denials.emit(status)),
                            Err(Errno::EINTR) => {}
                            Err(error) => return Err(LandstripError::from(error).into()),
                        }
                    }
                    return Err(source);
                }
            }
            HandleResult::Pending(decision) => {
                if let Err(error) = denials.write(&decision.trap) {
                    log::debug!("trap query write failed: {error}");
                    deny_all_pending(&mut pending_queries, notify);
                    denials.trap_fd = None;
                    trap_fd = None;
                    ctx.query_enabled = false;
                    notify.respond(NotificationResponse::error(
                        request.id,
                        -LandstripError::DENIAL_ERRNO,
                    ))?;
                } else {
                    pending_queries.insert(
                        decision.query_id,
                        PendingQuery {
                            request,
                            grant: decision.grant,
                        },
                    );
                }
            }
            HandleResult::AddFd(grant) => {
                grant.apply(policy, notify, request.id);
            }
            HandleResult::RunMutation(grant) => {
                grant.apply(notify, request.id);
            }
            HandleResult::RunSocket(grant) => {
                grant.apply(notify, request.id);
            }
        }
    }
}

fn receive_handled_notification(
    notify: NotificationChannel<'_>,
    ctx: &NotificationContext,
    denials: &mut Denials<'_>,
    next_query_id: &mut u64,
) -> Result<Option<(libc::seccomp_notif, HandleResult)>> {
    let request = notify.receive()?;
    if !notify.is_id_valid(request.id)? {
        return Ok(None);
    }
    let handle_result = match ctx.mount_namespace.verify(request.pid) {
        Ok(()) => ctx.handle(&request, denials, next_query_id),
        Err(error) => HandleResult::Respond(NotificationResponse::error(
            request.id,
            -error.errno().abs(),
        )),
    };
    if !notify.is_id_valid(request.id)? {
        return Ok(None);
    }
    Ok(Some((request, handle_result)))
}

fn poll_broker_fds(
    notify: BorrowedFd<'_>,
    control: Option<BorrowedFd<'_>>,
) -> Result<[PollFlags; 2]> {
    let len = if control.is_some() { 2 } else { 1 };
    let mut poll_fds = [
        PollFd::new(notify, PollFlags::POLLIN),
        PollFd::new(control.unwrap_or(notify), PollFlags::POLLIN),
    ];
    loop {
        match poll(&mut poll_fds[..len], POLL_MS) {
            Ok(0) => return Ok([PollFlags::empty(); 2]),
            Ok(_) => {
                return Ok([
                    poll_fds[0].revents().unwrap_or_else(PollFlags::empty),
                    poll_fds[1].revents().unwrap_or_else(PollFlags::empty),
                ]);
            }
            Err(Errno::EINTR) => {}
            Err(error) => return Err(LandstripError::from(error).into()),
        }
    }
}

fn process_control_responses(
    policy: &AccessPolicy,
    control_fd: BorrowedFd<'_>,
    buffer: &mut Vec<u8>,
    pending_queries: &mut HashMap<u64, PendingQuery>,
    notify: NotificationChannel<'_>,
) -> bool {
    let mut chunk = [0u8; 4096];
    let n = loop {
        let n = unsafe {
            libc::read(
                control_fd.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                chunk.len(),
            )
        };
        if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break n;
    };
    if n == 0 {
        return true;
    }
    if n < 0 {
        return io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock;
    }
    let Ok(n) = usize::try_from(n) else {
        return true;
    };
    buffer.extend_from_slice(&chunk[..n]);

    if buffer.len() > CONTROL_BUFFER_MAX {
        log::warn!(
            "linux: control buffer exceeded {CONTROL_BUFFER_MAX} bytes with no newline; dropping"
        );
        buffer.clear();
        return true;
    }

    let Some(last_newline) = buffer.iter().rposition(|b| *b == b'\n') else {
        return false;
    };
    let complete: Vec<u8> = buffer.drain(..=last_newline).collect();

    for line in complete.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(response): std::result::Result<ControlResponse, _> = serde_json::from_slice(line)
        else {
            return true;
        };
        let Ok(query_id) = response.query_id.parse::<u64>() else {
            return true;
        };
        if let Some(pending) = pending_queries.remove(&query_id) {
            let id = pending.request.id;
            if !notify.is_id_valid(id).unwrap_or(false) {
                continue;
            }
            match response.action {
                ControlAction::Allow => match pending.grant {
                    Some(grant) => grant.apply(policy, notify, id),
                    None => {
                        let _ = notify.respond(NotificationResponse::continue_syscall(id));
                    }
                },
                ControlAction::Deny => {
                    let _ = notify.respond(NotificationResponse::error(
                        id,
                        -LandstripError::DENIAL_ERRNO,
                    ));
                }
            }
        }
    }
    false
}

fn deny_all_pending(
    pending_queries: &mut HashMap<u64, PendingQuery>,
    notify: NotificationChannel<'_>,
) {
    for (_id, pending) in pending_queries.drain() {
        let id = pending.request.id;
        if notify.is_id_valid(id).unwrap_or(false) {
            let _ = notify.respond(NotificationResponse::error(
                id,
                -LandstripError::DENIAL_ERRNO,
            ));
        }
    }
}
