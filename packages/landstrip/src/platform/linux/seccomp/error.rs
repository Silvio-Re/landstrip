// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::Error as LandstripError;
use nix::errno::Errno;
use std::io;

#[derive(Debug)]
pub(crate) enum BrokerError {
    AddressFamilyNotSupported,
    BadAddress,
    BadFileDescriptor,
    InvalidAddress,
    NameTooLong,
    PolicyDenied,
    SystemCall { errno: i32 },
}

impl BrokerError {
    pub(crate) fn errno(&self) -> i32 {
        match self {
            Self::PolicyDenied => LandstripError::DENIAL_ERRNO,
            Self::AddressFamilyNotSupported => libc::EAFNOSUPPORT,
            Self::InvalidAddress => libc::EINVAL,
            Self::BadFileDescriptor => libc::EBADF,
            Self::BadAddress => libc::EFAULT,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::SystemCall { errno } => *errno,
        }
    }
}

impl From<Errno> for BrokerError {
    fn from(errno: Errno) -> Self {
        Self::SystemCall {
            errno: errno as i32,
        }
    }
}

impl From<io::Error> for BrokerError {
    fn from(error: io::Error) -> Self {
        Self::SystemCall {
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        }
    }
}

pub(crate) type SysResult<T> = std::result::Result<T, BrokerError>;
