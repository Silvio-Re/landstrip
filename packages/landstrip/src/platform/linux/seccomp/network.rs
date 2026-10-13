// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use super::grant::{Grant, SocketGrant};
use super::notify::NotificationResult;
use super::process::TargetProcess;
use super::supervise::{Denial, Denials};
use crate::paths::{PathCoverage, normalize_path_nofollow};
use crate::policy::{AccessPolicy, UnixSocketAccess};
use crate::trap::{NetworkOperation, Trap};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::unistd::Pid;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::IoSliceMut;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(super) type SocketAddrCall =
    unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;

#[derive(Debug)]
pub(super) struct TargetSocket {
    pub(super) sock: OwnedFd,
    pub(super) addr: Vec<u8>,
    pub(super) info: SocketInfo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SocketInfo {
    pub(super) domain: i32,
    pub(super) ty: i32,
    pub(super) proto: i32,
}

impl SocketInfo {
    pub(super) fn read(fd: RawFd) -> SysResult<Self> {
        let get_opt = |name: i32| -> std::io::Result<i32> {
            let mut value: i32 = 0;
            let mut len =
                libc::socklen_t::try_from(std::mem::size_of_val(&value)).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "socket option size exceeds socklen_t",
                    )
                })?;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    name,
                    (&raw mut value).cast::<libc::c_void>(),
                    &raw mut len,
                )
            };
            if rc < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(value)
            }
        };

        Ok(Self {
            domain: get_opt(libc::SO_DOMAIN)?,
            ty: get_opt(libc::SO_TYPE)?,
            proto: get_opt(libc::SO_PROTOCOL)?,
        })
    }

    pub(super) fn kind(&self) -> SocketKind {
        if matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            && self.ty == libc::SOCK_STREAM
            && (self.proto == libc::IPPROTO_TCP || self.proto == 0)
        {
            SocketKind::Tcp
        } else if matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            && self.ty == libc::SOCK_DGRAM
            && (self.proto == libc::IPPROTO_UDP || self.proto == 0)
        {
            SocketKind::Udp
        } else if self.domain == libc::AF_UNIX {
            SocketKind::Unix
        } else if matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            || matches!(self.domain, libc::AF_PACKET | libc::AF_NETLINK)
        {
            SocketKind::NotSupported
        } else {
            SocketKind::Other
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SocketKind {
    Tcp,
    Udp,
    Unix,
    NotSupported,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IpEndpoint {
    pub(super) addr: SocketAddr,
    pub(super) port: u16,
    pub(super) loopback: bool,
}

fn network_query(
    operation: NetworkOperation,
    target: String,
    pid: u32,
    socket: TargetSocket,
    call: SocketAddrCall,
    next_query_id: &mut u64,
) -> NotificationResult {
    let qid = *next_query_id;
    *next_query_id += 1;
    let trap = Trap::network(
        operation,
        target,
        TargetProcess::from_raw(pid).context(),
        Some(qid),
    );
    let grant = Grant::Socket(SocketGrant {
        sock: socket.sock,
        addr: socket.addr,
        call,
    });
    NotificationResult::query(qid, trap, Some(grant))
}

pub(super) fn handle_bind(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp | SocketKind::Udp => {
            if !policy.network_access.allows_local_binding() {
                if let Ok(endpoint) = ip_endpoint(&socket.addr, socket.info.domain) {
                    if query_enabled {
                        return Ok(network_query(
                            NetworkOperation::Bind,
                            endpoint.addr.to_string(),
                            request.pid,
                            socket,
                            libc::bind,
                            next_query_id,
                        ));
                    }
                    denials.record(Denial::Network(
                        NetworkOperation::Bind,
                        endpoint.addr.to_string(),
                        TargetProcess::from_raw(request.pid).context(),
                    ));
                }
                return Err(BrokerError::PolicyDenied);
            }
            let endpoint = ip_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback {
                if query_enabled {
                    return Ok(network_query(
                        NetworkOperation::Bind,
                        endpoint.addr.to_string(),
                        request.pid,
                        socket,
                        libc::bind,
                        next_query_id,
                    ));
                }
                denials.record(Denial::Network(
                    NetworkOperation::Bind,
                    endpoint.addr.to_string(),
                    TargetProcess::from_raw(request.pid).context(),
                ));
                return Err(BrokerError::PolicyDenied);
            }

            Ok(NotificationResult::Socket(SocketGrant::new(
                socket,
                libc::bind,
            )))
        }
        SocketKind::Unix => handle_unix_bind(policy, request.pid, socket),
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
        SocketKind::Other => Ok(NotificationResult::Continue),
    }
}

pub(super) fn handle_connect(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            if policy.network_access.is_unrestricted() {
                return Ok(NotificationResult::Continue);
            }
            let endpoint = ip_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback
                || (!policy.network_access.allows_local_binding()
                    && !policy
                        .network_access
                        .connect_tcp_ports()
                        .contains(&endpoint.port))
            {
                if query_enabled {
                    return Ok(network_query(
                        NetworkOperation::Connect,
                        endpoint.addr.to_string(),
                        request.pid,
                        socket,
                        libc::connect,
                        next_query_id,
                    ));
                }
                denials.record(Denial::Network(
                    NetworkOperation::Connect,
                    endpoint.addr.to_string(),
                    TargetProcess::from_raw(request.pid).context(),
                ));
                return Err(BrokerError::PolicyDenied);
            }

            Ok(NotificationResult::Socket(SocketGrant::new(
                socket,
                libc::connect,
            )))
        }
        SocketKind::Udp => {
            if policy.network_access.is_unrestricted() {
                return Ok(NotificationResult::Continue);
            }
            if sockaddr_family(&socket.addr)? == libc::AF_UNSPEC {
                return Ok(NotificationResult::Socket(SocketGrant::new(
                    socket,
                    libc::connect,
                )));
            }
            let endpoint = ip_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback || !policy.network_access.allows_local_binding() {
                if query_enabled {
                    return Ok(network_query(
                        NetworkOperation::Connect,
                        endpoint.addr.to_string(),
                        request.pid,
                        socket,
                        libc::connect,
                        next_query_id,
                    ));
                }
                denials.record(Denial::Network(
                    NetworkOperation::Connect,
                    endpoint.addr.to_string(),
                    TargetProcess::from_raw(request.pid).context(),
                ));
                return Err(BrokerError::PolicyDenied);
            }

            Ok(NotificationResult::Socket(SocketGrant::new(
                socket,
                libc::connect,
            )))
        }
        SocketKind::Unix => handle_unix_connect(policy, request.pid, socket),
        SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported if policy.network_access.is_unrestricted() => {
            Ok(NotificationResult::Continue)
        }
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
    }
}

fn check_target_datagram_addr(
    pid: Pid,
    fd: RawFd,
    target_addr: usize,
    addr_len: usize,
    request_pid: u32,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    if target_addr == 0 || addr_len == 0 {
        return Ok(NotificationResult::Continue);
    }
    if addr_len > mem::size_of::<libc::sockaddr_storage>() {
        return Err(BrokerError::InvalidAddress);
    }
    let target = TargetProcess::new(pid);
    let addr = target.read_sockaddr(target_addr, addr_len)?;
    let sock = target.duplicate_fd(fd)?;
    let info = SocketInfo::read(sock.as_raw_fd())?;
    match info.kind() {
        SocketKind::Tcp | SocketKind::Udp => {
            let endpoint = ip_endpoint(&addr, info.domain)?;
            if endpoint.loopback {
                Ok(NotificationResult::Continue)
            } else {
                denials.record(Denial::Network(
                    NetworkOperation::Connect,
                    endpoint.addr.to_string(),
                    TargetProcess::from_raw(request_pid).context(),
                ));
                Err(BrokerError::PolicyDenied)
            }
        }
        SocketKind::Unix | SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
    }
}

pub(super) fn handle_sendto(
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let target_addr = usize::try_from(request.data.args[4]).map_err(|_| BrokerError::BadAddress)?;
    let addr_len =
        usize::try_from(request.data.args[5]).map_err(|_| BrokerError::InvalidAddress)?;
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);
    check_target_datagram_addr(pid, fd, target_addr, addr_len, request.pid, denials)
}

pub(super) fn handle_sendmsg(
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let target_msg = usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    if target_msg == 0 {
        return Err(BrokerError::BadAddress);
    }
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);
    let mut msghdr = mem::MaybeUninit::<libc::msghdr>::uninit();
    let len = mem::size_of::<libc::msghdr>();
    let mut local = [IoSliceMut::new(unsafe {
        std::slice::from_raw_parts_mut(msghdr.as_mut_ptr().cast::<u8>(), len)
    })];
    let target = [RemoteIoVec {
        base: target_msg,
        len,
    }];
    if process_vm_readv(pid, &mut local, &target)? != len {
        return Err(BrokerError::BadAddress);
    }
    let msghdr = unsafe { msghdr.assume_init() };
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    check_target_datagram_addr(
        pid,
        fd,
        msghdr.msg_name as usize,
        usize::try_from(msghdr.msg_namelen).unwrap_or(0),
        request.pid,
        denials,
    )
}

pub(super) fn handle_sendmmsg(
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let target_msgvec =
        usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let vlen = usize::try_from(request.data.args[2]).map_err(|_| BrokerError::InvalidAddress)?;
    if target_msgvec == 0 || vlen == 0 {
        return Ok(NotificationResult::Continue);
    }
    let vlen = vlen.min(1024);
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);
    let mut mmsgvec = vec![mem::MaybeUninit::<libc::mmsghdr>::uninit(); vlen];
    let total_len = vlen * mem::size_of::<libc::mmsghdr>();
    let mut local = [IoSliceMut::new(unsafe {
        std::slice::from_raw_parts_mut(mmsgvec.as_mut_ptr().cast::<u8>(), total_len)
    })];
    let target = [RemoteIoVec {
        base: target_msgvec,
        len: total_len,
    }];
    if process_vm_readv(pid, &mut local, &target)? != total_len {
        return Err(BrokerError::BadAddress);
    }
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    for mmsg in mmsgvec {
        let mmsg = unsafe { mmsg.assume_init() };
        let result = check_target_datagram_addr(
            pid,
            fd,
            mmsg.msg_hdr.msg_name as usize,
            usize::try_from(mmsg.msg_hdr.msg_namelen).unwrap_or(0),
            request.pid,
            denials,
        )?;
        if !matches!(result, NotificationResult::Continue) {
            return Ok(result);
        }
    }
    Ok(NotificationResult::Continue)
}

fn handle_unix_connect(
    policy: &AccessPolicy,
    pid: u32,
    socket: TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        return if matches!(
            policy.network_access.unix_socket_access(),
            UnixSocketAccess::Unrestricted
        ) {
            Ok(NotificationResult::Continue)
        } else {
            Err(BrokerError::PolicyDenied)
        };
    };
    authorize_unix_path(policy, &target)?;

    let mut addr = socket.addr.clone();
    if relative {
        rewrite_unix_path(&mut addr, &target)?;
    }

    Ok(NotificationResult::Socket(SocketGrant {
        sock: socket.sock,
        addr,
        call: libc::connect,
    }))
}

fn handle_unix_bind(
    policy: &AccessPolicy,
    pid: u32,
    mut socket: TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        return Err(BrokerError::PolicyDenied);
    };
    authorize_unix_path(policy, &target)?;

    if !target.is_under_any(&policy.write_roots) {
        return Err(BrokerError::PolicyDenied);
    }

    if relative {
        rewrite_unix_path(&mut socket.addr, &target)?;
    }

    Ok(NotificationResult::Socket(SocketGrant::new(
        socket,
        libc::bind,
    )))
}

fn unix_path_target(pid: u32, addr: &[u8]) -> SysResult<Option<(PathBuf, bool)>> {
    let sun_path = mem::size_of::<libc::sa_family_t>();
    if addr.len() <= sun_path || addr[sun_path] == 0 {
        return Ok(None);
    }

    let path = &addr[sun_path..];
    let end = path
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path.len());
    if end == 0 {
        return Ok(None);
    }

    let path = Path::new(OsStr::from_bytes(&path[..end]));
    if path.is_absolute() {
        Ok(Some((normalize_path_nofollow(path), false)))
    } else {
        let pid = i32::try_from(pid).map_err(|_| BrokerError::InvalidAddress)?;
        let cwd = fs::read_link(format!("/proc/{pid}/cwd"))?;
        Ok(Some((normalize_path_nofollow(&cwd.join(path)), true)))
    }
}

fn authorize_unix_path(policy: &AccessPolicy, target: &Path) -> SysResult<()> {
    if is_supervisor_socket(target) {
        return Err(BrokerError::PolicyDenied);
    }
    match policy.network_access.unix_socket_access() {
        UnixSocketAccess::Unrestricted => Ok(()),
        UnixSocketAccess::AllowPaths(paths) => target
            .is_under_any(paths)
            .then_some(())
            .ok_or(BrokerError::PolicyDenied),
        UnixSocketAccess::Denied => Err(BrokerError::PolicyDenied),
    }
}

fn is_supervisor_socket(target: &Path) -> bool {
    let target = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    // SAFETY: getuid(2) is always defined and has no preconditions.
    let uid = unsafe { libc::getuid() };
    let uid_runtime = Path::new("/run/user").join(uid.to_string());
    let runtime = env::var_os("XDG_RUNTIME_DIR").map_or_else(|| uid_runtime.clone(), PathBuf::from);
    let candidates = [
        runtime.join("bus"),
        uid_runtime.join("bus"),
        PathBuf::from("/run/dbus/system_bus_socket"),
    ];
    candidates
        .iter()
        .any(|socket| target == *socket || same_socket_inode(&target, socket))
        || target.is_under("/run/systemd")
        || target.is_under(runtime.join("systemd"))
        || target.is_under(uid_runtime.join("systemd"))
}

fn same_socket_inode(left: &Path, right: &Path) -> bool {
    let Ok(left) = fs::metadata(left) else {
        return false;
    };
    let Ok(right) = fs::metadata(right) else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn rewrite_unix_path(addr: &mut Vec<u8>, target: &Path) -> SysResult<()> {
    let sun_path = mem::size_of::<libc::sa_family_t>();
    let path = target.as_os_str().as_bytes();
    let max_path = mem::size_of::<libc::sockaddr_un>() - sun_path;
    if path.len() + 1 > max_path {
        return Err(BrokerError::NameTooLong);
    }

    let mut rewritten = vec![0_u8; sun_path + path.len() + 1];
    rewritten[..sun_path].copy_from_slice(&addr[..sun_path]);
    rewritten[sun_path..sun_path + path.len()].copy_from_slice(path);
    *addr = rewritten;

    Ok(())
}

fn sockaddr_family(addr: &[u8]) -> SysResult<i32> {
    let family = addr
        .get(..mem::size_of::<libc::sa_family_t>())
        .ok_or(BrokerError::InvalidAddress)?;
    let family = <[u8; 2]>::try_from(family).map_err(|_| BrokerError::InvalidAddress)?;
    Ok(i32::from(libc::sa_family_t::from_ne_bytes(family)))
}

fn ip_endpoint(addr: &[u8], domain: i32) -> SysResult<IpEndpoint> {
    match (domain, sockaddr_family(addr)?) {
        (libc::AF_INET, libc::AF_INET) => {
            if addr.len() < mem::size_of::<libc::sockaddr_in>() {
                return Err(BrokerError::InvalidAddress);
            }

            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
            Ok(IpEndpoint {
                addr: SocketAddr::from((ip, port)),
                port,
                loopback: ip.is_loopback(),
            })
        }
        (libc::AF_INET6, libc::AF_INET6) => {
            if addr.len() < mem::size_of::<libc::sockaddr_in6>() {
                return Err(BrokerError::InvalidAddress);
            }

            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&addr[8..24]).map_err(|_| BrokerError::InvalidAddress)?,
            );
            Ok(IpEndpoint {
                addr: SocketAddr::from((ip, port)),
                port,
                loopback: ip.is_loopback()
                    || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
            })
        }
        _ => Err(BrokerError::AddressFamilyNotSupported),
    }
}

fn target_socket(request: &libc::seccomp_notif) -> SysResult<TargetSocket> {
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    let target_addr = usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let addr_len =
        usize::try_from(request.data.args[2]).map_err(|_| BrokerError::InvalidAddress)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);

    if addr_len > mem::size_of::<libc::sockaddr_storage>() {
        return Err(BrokerError::InvalidAddress);
    }

    let target = TargetProcess::new(pid);
    let addr = target.read_sockaddr(target_addr, addr_len)?;
    let sock = target.duplicate_fd(fd)?;
    let info = SocketInfo::read(sock.as_raw_fd())?;

    Ok(TargetSocket { sock, addr, info })
}
