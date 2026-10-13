// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use crate::error::Error as LandstripError;
use crate::trap::ProcessContext;
use anyhow::Result;
use nix::errno::Errno;
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{self, IoSliceMut};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub(super) struct Subreaper {
    was_subreaper: bool,
}

impl Subreaper {
    pub(super) fn acquire() -> Result<Self> {
        let mut enabled = 0;
        // SAFETY: PR_GET_CHILD_SUBREAPER writes an integer to the supplied pointer.
        if unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut enabled) } == -1 {
            return Err(LandstripError::supervise(io::Error::last_os_error()).into());
        }
        let was_subreaper = enabled != 0;
        if !was_subreaper {
            Self::set(true)?;
        }
        Ok(Self { was_subreaper })
    }

    fn set(enabled: bool) -> Result<()> {
        // SAFETY: PR_SET_CHILD_SUBREAPER only changes how orphaned descendants are reparented.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, i32::from(enabled), 0, 0, 0) } == -1 {
            return Err(LandstripError::supervise(io::Error::last_os_error()).into());
        }
        Ok(())
    }

    pub(super) fn restore(self) -> Result<()> {
        if !self.was_subreaper {
            Self::set(false)?;
        }
        Ok(())
    }
}

fn child_pids() -> Result<Vec<Pid>> {
    let children =
        fs::read_to_string("/proc/thread-self/children").map_err(LandstripError::supervise)?;
    children
        .split_whitespace()
        .map(|pid| {
            pid.parse::<i32>().map(Pid::from_raw).map_err(|error| {
                LandstripError::supervise(io::Error::new(io::ErrorKind::InvalidData, error)).into()
            })
        })
        .collect()
}

pub(super) fn cleanup_descendants() -> Result<()> {
    loop {
        let children = child_pids()?;
        if children.is_empty() {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                Err(Errno::ECHILD) => return Ok(()),
                Ok(_) | Err(Errno::EINTR) => continue,
                Err(error) => return Err(LandstripError::from(error).into()),
            }
        }

        let mut kill_error = None;
        for child in children {
            // SAFETY: child came from the kernel's direct-child list.
            if unsafe { libc::kill(child.as_raw(), libc::SIGKILL) } == -1 {
                let error = Errno::last();
                if error != Errno::ESRCH && kill_error.is_none() {
                    kill_error = Some(error);
                }
            }
        }
        if let Some(error) = kill_error {
            return Err(LandstripError::from(error).into());
        }

        loop {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                Ok(_) | Err(Errno::EINTR) => {}
                Err(error) => return Err(LandstripError::from(error).into()),
            }
        }
        std::thread::yield_now();
    }
}

pub(super) struct TargetProcess {
    pub(super) pid: Pid,
}

impl TargetProcess {
    pub(super) fn new(pid: Pid) -> Self {
        Self { pid }
    }

    pub(super) fn from_raw(pid: u32) -> Self {
        Self::new(Pid::from_raw(pid.cast_signed()))
    }

    pub(super) fn context(&self) -> ProcessContext {
        let pid = self.pid.as_raw().cast_unsigned();
        ProcessContext {
            pid,
            exe: fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
            cwd: fs::read_link(format!("/proc/{pid}/cwd"))
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }

    pub(super) fn read_string(&self, addr: usize, max_len: usize) -> SysResult<Vec<u8>> {
        let mut buf = vec![0_u8; max_len];
        let mut local = [IoSliceMut::new(&mut buf)];
        let target = [RemoteIoVec {
            base: addr,
            len: max_len,
        }];
        let n = process_vm_readv(self.pid, &mut local, &target)?;
        if n == 0 {
            return Err(BrokerError::BadAddress);
        }
        let slice = &buf[..n];
        let end = slice
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(BrokerError::NameTooLong)?;
        buf.truncate(end);
        Ok(buf)
    }

    pub(super) fn read_path(&self, path_ptr: usize) -> SysResult<PathBuf> {
        if path_ptr == 0 {
            return Err(BrokerError::BadAddress);
        }
        let buf = self.read_string(path_ptr, libc::PATH_MAX as usize)?;
        Ok(PathBuf::from(OsStr::from_bytes(&buf)))
    }

    pub(super) fn read_nonempty_path(&self, path_ptr: usize) -> SysResult<PathBuf> {
        let path = self.read_path(path_ptr)?;
        if path.as_os_str().is_empty() {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        Ok(path)
    }

    pub(super) fn read_bytes(&self, ptr: u64, size: u64) -> SysResult<Vec<u8>> {
        const XATTR_MAX: usize = 65536;

        let len =
            usize::try_from(size).map_err(|_| BrokerError::SystemCall { errno: libc::E2BIG })?;
        if len > XATTR_MAX {
            return Err(BrokerError::SystemCall { errno: libc::E2BIG });
        }
        if len == 0 {
            return Ok(Vec::new());
        }

        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        if addr == 0 {
            return Err(BrokerError::BadAddress);
        }

        let mut buf = vec![0_u8; len];
        let mut local = [IoSliceMut::new(&mut buf)];
        let target = [RemoteIoVec { base: addr, len }];
        let n = process_vm_readv(self.pid, &mut local, &target)?;
        if n != len {
            return Err(BrokerError::BadAddress);
        }
        Ok(buf)
    }

    pub(super) fn read_times(&self, ptr: u64) -> SysResult<Option<[libc::timespec; 2]>> {
        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        if addr == 0 {
            return Ok(None);
        }
        let mut times = [libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }; 2];
        let len = mem::size_of_val(&times);
        // SAFETY: times is a live, suitably aligned array of two POD timespecs that
        // we expose as its raw byte span for the copy from the child.
        let bytes = unsafe { std::slice::from_raw_parts_mut(times.as_mut_ptr().cast::<u8>(), len) };
        let mut local = [IoSliceMut::new(bytes)];
        let target = [RemoteIoVec { base: addr, len }];
        let n = process_vm_readv(self.pid, &mut local, &target)?;
        if n < len {
            return Err(BrokerError::BadAddress);
        }
        Ok(Some(times))
    }

    pub(super) fn read_xattr_name(&self, ptr: u64) -> SysResult<CString> {
        const XATTR_NAME_MAX: usize = 255;

        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        if addr == 0 {
            return Err(BrokerError::BadAddress);
        }
        let buf = match self.read_string(addr, XATTR_NAME_MAX + 1) {
            Err(BrokerError::NameTooLong) => {
                return Err(BrokerError::SystemCall {
                    errno: libc::ERANGE,
                });
            }
            result => result?,
        };
        CString::new(buf).map_err(|_| BrokerError::BadAddress)
    }

    pub(super) fn read_target(&self, ptr: u64) -> SysResult<Option<CString>> {
        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        if addr == 0 {
            return Ok(None);
        }
        let buf = self.read_string(addr, libc::PATH_MAX as usize)?;
        CString::new(buf)
            .map(Some)
            .map_err(|_| BrokerError::InvalidAddress)
    }

    pub(super) fn read_sockaddr(&self, target_addr: usize, addr_len: usize) -> SysResult<Vec<u8>> {
        if addr_len < mem::size_of::<libc::sa_family_t>() {
            return Err(BrokerError::InvalidAddress);
        }

        let mut addr = vec![0_u8; addr_len];
        let mut local = [IoSliceMut::new(&mut addr)];
        let target = [RemoteIoVec {
            base: target_addr,
            len: addr_len,
        }];
        if process_vm_readv(self.pid, &mut local, &target)? != addr_len {
            return Err(BrokerError::BadAddress);
        }

        Ok(addr)
    }

    pub(super) fn thread_group_leader(&self) -> SysResult<Pid> {
        let status_path = Path::new("/proc")
            .join(self.pid.as_raw().to_string())
            .join("status");
        let status = fs::read_to_string(status_path)?;
        let line = status
            .lines()
            .find(|line| line.starts_with("Tgid:"))
            .ok_or(BrokerError::InvalidAddress)?;
        let value = line
            .strip_prefix("Tgid:")
            .ok_or(BrokerError::InvalidAddress)?;
        let tgid = value
            .trim()
            .parse::<i32>()
            .map_err(|_| BrokerError::InvalidAddress)?;
        if tgid <= 0 {
            return Err(BrokerError::InvalidAddress);
        }

        Ok(Pid::from_raw(tgid))
    }

    pub(super) fn duplicate_fd(&self, fd: RawFd) -> SysResult<OwnedFd> {
        let pidfd = match self.open_pidfd(libc::O_EXCL as libc::c_uint) {
            Ok(pidfd) => pidfd,
            Err(Errno::EINVAL | Errno::ENOSYS) => match self.open_pidfd(0) {
                Ok(pidfd) => pidfd,
                Err(Errno::EINVAL) => {
                    let leader = TargetProcess::new(self.thread_group_leader()?);
                    leader.open_pidfd(0)?
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        };

        // SAFETY: pidfd_getfd copies scalar arguments and returns a duplicated fd.
        let target = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
        if target < 0 {
            return Err(Errno::last().into());
        }

        let target = RawFd::try_from(target).map_err(|_| BrokerError::BadFileDescriptor)?;
        // SAFETY: pidfd_getfd returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(target) })
    }

    pub(super) fn open_pidfd(&self, flags: libc::c_uint) -> std::result::Result<OwnedFd, Errno> {
        // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid.as_raw(), flags) };
        if pidfd < 0 {
            return Err(Errno::last());
        }
        let pidfd = RawFd::try_from(pidfd).map_err(|_| Errno::EMFILE)?;
        // SAFETY: pidfd_open returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
    }

    pub(super) fn resolve_path(&self, dirfd: i32, path: &Path) -> SysResult<PathBuf> {
        if path.is_absolute() {
            if let Ok(suffix) = path.strip_prefix("/proc/self") {
                return Ok(Path::new("/proc").join(self.pid.to_string()).join(suffix));
            }
            return Ok(path.to_path_buf());
        }

        if dirfd == libc::AT_FDCWD {
            let cwd = fs::read_link(format!("/proc/{}/cwd", self.pid))?;
            return Ok(cwd.join(path));
        }

        let dir = self.duplicate_fd(dirfd)?;
        let dir_path = fs::read_link(Path::new("/proc/self/fd").join(dir.as_raw_fd().to_string()))
            .map_err(|error| BrokerError::SystemCall {
                errno: error.raw_os_error().unwrap_or(libc::EBADF),
            })?;
        Ok(dir_path.join(path))
    }

    pub(super) fn open_dirfd(&self, dirfd: RawFd) -> std::result::Result<OwnedFd, i32> {
        if dirfd == libc::AT_FDCWD {
            let cwd = Path::new("/proc").join(self.pid.to_string()).join("cwd");
            return super::grant::open_path(
                &cwd,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            );
        }
        self.duplicate_fd(dirfd).map_err(|error| error.errno())
    }
}
