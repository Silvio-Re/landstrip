// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::BrokerError;
use super::network::{SocketAddrCall, TargetSocket};
use super::notify::{NotificationChannel, NotificationResponse};
use super::process::TargetProcess;
use crate::error::Error as LandstripError;
use crate::paths::PathCoverage;
use crate::policy::AccessPolicy;
use nix::errno::Errno;
use std::ffi::{CString, OsStr};
use std::fs;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

pub(super) const OPEN_HOW_SIZE: usize = 24;
pub(super) const RESOLVE_IN_ROOT: u64 = 0x10;
const SYS_FCHMODAT2: i64 = 452;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct OpenHow {
    pub(super) flags: u64,
    pub(super) mode: u64,
    pub(super) resolve: u64,
}

impl OpenHow {
    pub(super) fn openat2(
        &self,
        dirfd: RawFd,
        path: &CString,
    ) -> std::result::Result<OwnedFd, i32> {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                ptr::addr_of!(*self),
                OPEN_HOW_SIZE,
            )
        };
        if rc < 0 {
            return Err(Errno::last() as i32);
        }
        RawFd::try_from(rc)
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
            .map_err(|_| libc::EMFILE)
    }
}

pub(super) enum Grant {
    Open(OpenGrant),
    Mutation(MutationGrant),
    Socket(SocketGrant),
}

impl Grant {
    pub(super) fn apply(&self, policy: &AccessPolicy, notify: NotificationChannel<'_>, id: u64) {
        match self {
            Self::Open(grant) => grant.apply(policy, notify, id),
            Self::Mutation(grant) => grant.apply(notify, id),
            Self::Socket(grant) => grant.apply(notify, id),
        }
    }
}

pub(super) struct SocketGrant {
    pub(super) sock: OwnedFd,
    pub(super) addr: Vec<u8>,
    pub(super) call: SocketAddrCall,
}

impl SocketGrant {
    pub(super) fn new(socket: TargetSocket, call: SocketAddrCall) -> Self {
        Self {
            sock: socket.sock,
            addr: socket.addr,
            call,
        }
    }

    pub(super) fn apply(&self, notify: NotificationChannel<'_>, id: u64) {
        let rc = match broker_addr_call(self.sock.as_raw_fd(), &self.addr, self.call) {
            Ok(value) => NotificationResponse::success(id, value),
            Err(error) => NotificationResponse::error(id, -error.errno().abs()),
        };
        let _ = notify.respond(rc);
    }
}

fn broker_addr_call(sock: RawFd, addr: &[u8], call: SocketAddrCall) -> Result<i64, BrokerError> {
    let len = libc::socklen_t::try_from(addr.len()).map_err(|_| BrokerError::InvalidAddress)?;
    let rc = unsafe { call(sock, addr.as_ptr().cast(), len) };
    if rc < 0 {
        return Err(Errno::last().into());
    }
    Ok(i64::from(rc))
}

pub(super) struct Anchor {
    pub(super) dir: OwnedFd,
    pub(super) name: CString,
}

impl Anchor {
    pub(super) fn new(resolved: &Path) -> std::result::Result<Self, i32> {
        let parent = resolved.parent().ok_or(libc::EINVAL)?;
        let name = CString::new(resolved.file_name().ok_or(libc::EINVAL)?.as_bytes())
            .map_err(|_| libc::EINVAL)?;
        Ok(Self {
            dir: open_path(parent, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)?,
            name,
        })
    }

    pub(super) fn pin(&self) -> std::result::Result<(OwnedFd, CString), i32> {
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Errno::last() as i32);
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let path =
            CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(|_| libc::EINVAL)?;
        Ok((fd, path))
    }

    pub(super) fn path(&self) -> std::result::Result<CString, i32> {
        let mut path = format!("/proc/self/fd/{}/", self.dir.as_raw_fd()).into_bytes();
        path.extend_from_slice(self.name.as_bytes());
        CString::new(path).map_err(|_| libc::EINVAL)
    }
}

pub(super) struct OpenGrant {
    pub(super) flags: i32,
    pub(super) kind: OpenKind,
}

impl OpenGrant {
    pub(super) fn new(resolved: &Path, flags: i32, mode: u32) -> std::result::Result<Self, i32> {
        let kind = match open_path(resolved, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) {
            Ok(handle) => {
                if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
                    return Err(libc::EEXIST);
                }
                validate_nofollow_target(handle.as_fd(), flags)?;
                OpenKind::Reopen(handle)
            }
            Err(libc::ENOENT) if resolved.as_os_str().as_bytes().ends_with(b"/") => {
                return Err(if flags & libc::O_CREAT != 0 {
                    libc::EISDIR
                } else {
                    libc::ENOENT
                });
            }
            Err(libc::ENOENT) => OpenKind::Create {
                anchor: Anchor::new(resolved)?,
                mode,
                resolve: 0,
            },
            Err(errno) => return Err(errno),
        };
        Ok(Self { flags, kind })
    }

    pub(super) fn new_openat2(
        target: &TargetProcess,
        dirfd: RawFd,
        path: &Path,
        flags: i32,
        mode: u32,
        resolve: u64,
    ) -> std::result::Result<(PathBuf, PathBuf, Self), i32> {
        let base = if path.is_absolute() && resolve & RESOLVE_IN_ROOT == 0 {
            None
        } else {
            Some(target.open_dirfd(dirfd)?)
        };
        let base_fd = base.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
        let raw = match &base {
            Some(base) => {
                let base = open_fd_path(base.as_fd())?;
                if path.is_absolute() {
                    base.join(path.strip_prefix("/").map_err(|_| libc::EINVAL)?)
                } else {
                    base.join(path)
                }
            }
            None => path.to_path_buf(),
        };
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let no_follow = flags & (libc::O_NOFOLLOW | libc::O_EXCL) != 0;
        let pin_flags = libc::O_PATH
            | libc::O_CLOEXEC
            | (flags & libc::O_DIRECTORY)
            | if no_follow { libc::O_NOFOLLOW } else { 0 };
        let pin_how = OpenHow {
            flags: u64::try_from(pin_flags).map_err(|_| libc::EINVAL)?,
            mode: 0,
            resolve,
        };

        match pin_how.openat2(base_fd, &c_path) {
            Ok(handle) => {
                if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
                    return Err(libc::EEXIST);
                }
                validate_nofollow_target(handle.as_fd(), flags)?;
                let resolved = open_fd_path(handle.as_fd())?;
                Ok((
                    raw,
                    resolved,
                    Self {
                        flags,
                        kind: OpenKind::Reopen(handle),
                    },
                ))
            }
            Err(libc::ENOENT) if flags & libc::O_CREAT != 0 => {
                let source = Path::new(OsStr::from_bytes(c_path.to_bytes()));
                if source.as_os_str().as_bytes().ends_with(b"/") {
                    return Err(libc::ENOENT);
                }
                let parent = source.parent().ok_or(libc::ENOENT)?;
                let parent = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                let name = CString::new(source.file_name().ok_or(libc::ENOENT)?.as_bytes())
                    .map_err(|_| libc::EINVAL)?;
                let parent =
                    CString::new(parent.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
                let parent_how = OpenHow {
                    flags: u64::try_from(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
                        .map_err(|_| libc::EINVAL)?,
                    mode: 0,
                    resolve,
                };
                let parent_handle = parent_how.openat2(base_fd, &parent)?;
                let resolved =
                    open_fd_path(parent_handle.as_fd())?.join(OsStr::from_bytes(name.to_bytes()));
                Ok((
                    raw,
                    resolved,
                    Self {
                        flags,
                        kind: OpenKind::Create {
                            anchor: Anchor {
                                dir: parent_handle,
                                name,
                            },
                            mode,
                            resolve,
                        },
                    },
                ))
            }
            Err(errno) => Err(errno),
        }
    }

    pub(super) fn open(&self) -> std::result::Result<OwnedFd, i32> {
        match &self.kind {
            OpenKind::Reopen(handle) => {
                let proc_path = CString::new(format!("/proc/self/fd/{}", handle.as_raw_fd()))
                    .map_err(|_| libc::EINVAL)?;
                let flags = (self.flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW))
                    | libc::O_CLOEXEC;
                let fd = unsafe { libc::open(proc_path.as_ptr(), flags) };
                if fd < 0 {
                    return Err(Errno::last() as i32);
                }
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
            OpenKind::Create {
                anchor,
                mode,
                resolve,
            } => {
                let flags = self.flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                if *resolve != 0 {
                    let how = OpenHow {
                        flags: u64::try_from(flags).map_err(|_| libc::EINVAL)?,
                        mode: u64::from(*mode),
                        resolve: *resolve,
                    };
                    return how.openat2(anchor.dir.as_raw_fd(), &anchor.name);
                }
                let fd = unsafe {
                    libc::openat(
                        anchor.dir.as_raw_fd(),
                        anchor.name.as_ptr(),
                        flags,
                        *mode as libc::c_uint,
                    )
                };
                if fd < 0 {
                    return Err(Errno::last() as i32);
                }
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        }
    }

    pub(super) fn apply(&self, policy: &AccessPolicy, notify: NotificationChannel<'_>, id: u64) {
        let opened = self.open().and_then(|fd| {
            if self.flags & libc::O_WRONLY == 0
                && !policy.read_denied_always_roots.is_empty()
                && open_fd_path(fd.as_fd())?.is_under_any(&policy.read_denied_always_roots)
            {
                return Err(libc::EACCES);
            }
            if self.flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0
                && !policy.write_denied_always_roots.is_empty()
                && open_fd_path(fd.as_fd())?.is_under_any(&policy.write_denied_always_roots)
            {
                return Err(libc::EACCES);
            }
            Ok(fd)
        });
        let opened = match opened {
            Ok(fd) => fd,
            Err(errno) => {
                let _ = notify.respond(NotificationResponse::error(id, -errno.abs()));
                return;
            }
        };

        let cloexec = self.flags & libc::O_CLOEXEC != 0;
        let addfd = libc::seccomp_notif_addfd {
            id,
            flags: u32::try_from(libc::SECCOMP_ADDFD_FLAG_SEND).unwrap_or(0),
            srcfd: u32::try_from(opened.as_raw_fd()).unwrap_or(0),
            newfd: 0,
            newfd_flags: if cloexec {
                u32::try_from(libc::O_CLOEXEC).unwrap_or(0)
            } else {
                0
            },
        };

        if notify.add_fd(&addfd).is_err() {
            let _ = notify.respond(NotificationResponse::error(
                id,
                -LandstripError::DENIAL_ERRNO,
            ));
        }
    }
}

pub(super) enum OpenKind {
    Reopen(OwnedFd),
    Create {
        anchor: Anchor,
        mode: u32,
        resolve: u64,
    },
}

pub(super) struct MutationGrant {
    pub(super) op: MutationOp,
    pub(super) anchors: Vec<Anchor>,
    pub(super) no_follow: bool,
}

impl MutationGrant {
    pub(super) fn run(&self) -> std::result::Result<(), i32> {
        if let MutationOp::Fd { target, mutation } = &self.op {
            return mutation.run(target.as_raw_fd());
        }

        let at = self.anchors.first().ok_or(libc::EINVAL)?;
        let dir = at.dir.as_raw_fd();
        let name = at.name.as_ptr();
        let rc = match &self.op {
            MutationOp::Mkdir { mode } => unsafe { libc::mkdirat(dir, name, *mode) },
            MutationOp::Mknod { mode, dev } => unsafe { libc::mknodat(dir, name, *mode, *dev) },
            MutationOp::Unlink { flags } => unsafe { libc::unlinkat(dir, name, *flags) },
            MutationOp::Symlink { target } => unsafe {
                libc::symlinkat(target.as_ptr(), dir, name)
            },
            MutationOp::Truncate { length } => {
                let (_target, path) = at.pin()?;
                let writable =
                    unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
                if writable < 0 {
                    return Err(Errno::last() as i32);
                }
                let writable = unsafe { OwnedFd::from_raw_fd(writable) };
                return check(unsafe { libc::ftruncate(writable.as_raw_fd(), *length) });
            }
            MutationOp::Rename { flags } => {
                let to = self.anchors.get(1).ok_or(libc::EINVAL)?;
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        dir,
                        name,
                        to.dir.as_raw_fd(),
                        to.name.as_ptr(),
                        *flags,
                    )
                };
                return if rc < 0 {
                    Err(Errno::last() as i32)
                } else {
                    Ok(())
                };
            }
            MutationOp::Link { flags } => {
                let to = self.anchors.get(1).ok_or(libc::EINVAL)?;
                unsafe { libc::linkat(dir, name, to.dir.as_raw_fd(), to.name.as_ptr(), *flags) }
            }
            MutationOp::Chmod { mode } => {
                let (_fd, path) = at.pin()?;
                unsafe { libc::chmod(path.as_ptr(), *mode) }
            }
            MutationOp::ChmodAt { mode, flags } => run_fchmodat(self, at, *mode, *flags)?,
            MutationOp::Chown { uid, gid } => {
                if self.no_follow {
                    unsafe { libc::fchownat(dir, name, *uid, *gid, libc::AT_SYMLINK_NOFOLLOW) }
                } else {
                    let (_fd, path) = at.pin()?;
                    unsafe { libc::chown(path.as_ptr(), *uid, *gid) }
                }
            }
            MutationOp::ChownAt { uid, gid, flags } => run_fchownat(self, at, *uid, *gid, *flags)?,
            MutationOp::Utimes { times, flags } => {
                let ptr = times.as_ref().map_or(ptr::null(), |t| t.as_ptr());
                if self.no_follow {
                    unsafe { libc::utimensat(dir, name, ptr, *flags) }
                } else {
                    let (_fd, path) = at.pin()?;
                    unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), ptr, *flags) }
                }
            }
            MutationOp::Fd { .. } => return Err(libc::EINVAL),
            MutationOp::SetXattr { name, value, flags } => {
                run_setxattr(self, at, name, value, *flags)?
            }
            MutationOp::RemoveXattr { name } => run_removexattr(self, at, name)?,
        };
        check(rc)
    }

    pub(super) fn apply(&self, notify: NotificationChannel<'_>, id: u64) {
        let rc = match self.run() {
            Ok(()) => NotificationResponse::success(id, 0),
            Err(errno) => NotificationResponse::error(id, -errno.abs()),
        };
        let _ = notify.respond(rc);
    }
}

pub(super) enum MutationOp {
    Mkdir {
        mode: u32,
    },
    Mknod {
        mode: u32,
        dev: u64,
    },
    Unlink {
        flags: i32,
    },
    Symlink {
        target: CString,
    },
    Truncate {
        length: i64,
    },
    Rename {
        flags: u32,
    },
    Link {
        flags: i32,
    },
    Chmod {
        mode: u32,
    },
    ChmodAt {
        mode: u32,
        flags: i32,
    },
    Chown {
        uid: u32,
        gid: u32,
    },
    ChownAt {
        uid: u32,
        gid: u32,
        flags: i32,
    },
    Utimes {
        times: Option<[libc::timespec; 2]>,
        flags: i32,
    },
    Fd {
        target: OwnedFd,
        mutation: FdMutation,
    },
    SetXattr {
        name: CString,
        value: Vec<u8>,
        flags: i32,
    },
    RemoveXattr {
        name: CString,
    },
}

pub(super) enum FdMutation {
    Chmod {
        mode: u32,
    },
    ChmodAt {
        mode: u32,
        flags: i32,
    },
    Chown {
        uid: u32,
        gid: u32,
    },
    ChownAt {
        uid: u32,
        gid: u32,
        flags: i32,
    },
    Utimes {
        times: Option<[libc::timespec; 2]>,
    },
    SetXattr {
        name: CString,
        value: Vec<u8>,
        flags: i32,
    },
    RemoveXattr {
        name: CString,
    },
}

impl FdMutation {
    pub(super) fn run(&self, target: RawFd) -> std::result::Result<(), i32> {
        let rc = match self {
            Self::Chmod { mode } => unsafe { libc::fchmod(target, *mode) },
            Self::Chown { uid, gid } => unsafe { libc::fchown(target, *uid, *gid) },
            Self::ChmodAt { mode, flags } => unsafe {
                let rc = libc::syscall(SYS_FCHMODAT2, target, c"".as_ptr(), *mode, *flags);
                if rc < 0 { -1 } else { 0 }
            },
            Self::ChownAt { uid, gid, flags } => unsafe {
                libc::fchownat(target, c"".as_ptr(), *uid, *gid, *flags)
            },
            Self::Utimes { times } => {
                let times = times.as_ref().map_or(ptr::null(), |value| value.as_ptr());
                unsafe { libc::futimens(target, times) }
            }
            Self::SetXattr { name, value, flags } => unsafe {
                libc::fsetxattr(
                    target,
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    *flags,
                )
            },
            Self::RemoveXattr { name } => unsafe { libc::fremovexattr(target, name.as_ptr()) },
        };
        check(rc)
    }
}

pub(super) fn open_path(path: &Path, flags: i32) -> std::result::Result<OwnedFd, i32> {
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(Errno::last() as i32);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(super) fn open_fd_path(fd: BorrowedFd<'_>) -> std::result::Result<PathBuf, i32> {
    fs::read_link(Path::new("/proc/self/fd").join(fd.as_raw_fd().to_string()))
        .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
}

pub(super) fn validate_nofollow_target(
    handle: BorrowedFd<'_>,
    flags: i32,
) -> std::result::Result<(), i32> {
    if flags & libc::O_NOFOLLOW == 0 || flags & libc::O_PATH != 0 {
        return Ok(());
    }
    let mut stat = unsafe { mem::zeroed::<libc::stat>() };
    let rc = unsafe { libc::fstat(handle.as_raw_fd(), ptr::addr_of_mut!(stat)) };
    if rc < 0 {
        return Err(Errno::last() as i32);
    }
    if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(libc::ELOOP);
    }
    Ok(())
}

fn run_fchmodat(
    grant: &MutationGrant,
    at: &Anchor,
    mode: u32,
    flags: i32,
) -> std::result::Result<i32, i32> {
    let dir = at.dir.as_raw_fd();
    let name = at.name.as_ptr();
    let (target, target_name, target_flags) = if grant.no_follow {
        (None, name, flags)
    } else {
        let (target, _) = at.pin()?;
        (Some(target), c"".as_ptr(), flags | libc::AT_EMPTY_PATH)
    };
    let target_fd = target.as_ref().map_or(dir, AsRawFd::as_raw_fd);
    let rc = unsafe { libc::syscall(SYS_FCHMODAT2, target_fd, target_name, mode, target_flags) };
    Ok(if rc < 0 { -1 } else { 0 })
}

fn run_fchownat(
    grant: &MutationGrant,
    at: &Anchor,
    uid: u32,
    gid: u32,
    flags: i32,
) -> std::result::Result<i32, i32> {
    if grant.no_follow {
        return Ok(unsafe {
            libc::fchownat(at.dir.as_raw_fd(), at.name.as_ptr(), uid, gid, flags)
        });
    }
    let (target, _) = at.pin()?;
    Ok(unsafe {
        libc::fchownat(
            target.as_raw_fd(),
            c"".as_ptr(),
            uid,
            gid,
            flags | libc::AT_EMPTY_PATH,
        )
    })
}

fn mutation_xattr_path(
    grant: &MutationGrant,
    at: &Anchor,
) -> std::result::Result<(Option<OwnedFd>, CString), i32> {
    if grant.no_follow {
        Ok((None, at.path()?))
    } else {
        let (target, path) = at.pin()?;
        Ok((Some(target), path))
    }
}

fn run_setxattr(
    grant: &MutationGrant,
    at: &Anchor,
    name: &CString,
    value: &[u8],
    flags: i32,
) -> std::result::Result<i32, i32> {
    let (_target, path) = mutation_xattr_path(grant, at)?;
    Ok(unsafe {
        if grant.no_follow {
            libc::lsetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                flags,
            )
        } else {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                flags,
            )
        }
    })
}

fn run_removexattr(
    grant: &MutationGrant,
    at: &Anchor,
    name: &CString,
) -> std::result::Result<i32, i32> {
    let (_target, path) = mutation_xattr_path(grant, at)?;
    Ok(unsafe {
        if grant.no_follow {
            libc::lremovexattr(path.as_ptr(), name.as_ptr())
        } else {
            libc::removexattr(path.as_ptr(), name.as_ptr())
        }
    })
}

fn check(rc: libc::c_int) -> std::result::Result<(), i32> {
    if rc < 0 {
        Err(Errno::last() as i32)
    } else {
        Ok(())
    }
}
