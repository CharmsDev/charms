//! Stub of `getrandom` 0.4.x for ICP canisters. Every call returns
//! `Error::UNSUPPORTED`. See Cargo.toml for the rationale.

#![no_std]
#![allow(dead_code)]

use core::fmt;
use core::mem::MaybeUninit;

pub type RawOsError = i32;
type NonZeroRawOsError = core::num::NonZeroI32;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Error(NonZeroRawOsError);

impl Error {
    pub const UNSUPPORTED: Error = Self::new_internal(0);
    pub const ERRNO_NOT_POSITIVE: Error = Self::new_internal(1);
    pub const UNEXPECTED: Error = Self::new_internal(2);

    const INTERNAL_START: RawOsError = 1 << 16;
    const CUSTOM_START: RawOsError = 1 << 17;

    pub const fn new_custom(n: u16) -> Error {
        let code = Error::CUSTOM_START + (n as RawOsError);
        Error(unsafe { NonZeroRawOsError::new_unchecked(code) })
    }

    const fn new_internal(n: u16) -> Error {
        let code = Error::INTERNAL_START + (n as RawOsError);
        Error(unsafe { NonZeroRawOsError::new_unchecked(code) })
    }

    #[inline]
    pub fn raw_os_error(self) -> Option<RawOsError> {
        let code = self.0.get();
        if code >= 0 { None } else { code.checked_neg() }
    }
}

impl core::error::Error for Error {}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("internal_code", &self.0.get())
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "getrandom stub: unsupported on this target")
    }
}

#[inline]
pub fn fill(_dest: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}

#[inline]
pub fn fill_uninit(_dest: &mut [MaybeUninit<u8>]) -> Result<&mut [u8], Error> {
    Err(Error::UNSUPPORTED)
}

#[inline]
pub fn u32() -> Result<u32, Error> {
    Err(Error::UNSUPPORTED)
}

#[inline]
pub fn u64() -> Result<u64, Error> {
    Err(Error::UNSUPPORTED)
}

#[cfg(feature = "sys_rng")]
pub use rand_core;

#[cfg(feature = "sys_rng")]
mod sys_rng {
    use super::Error;
    use rand_core::{TryCryptoRng, TryRng};

    #[derive(Clone, Copy, Debug, Default)]
    pub struct SysRng;

    impl TryRng for SysRng {
        type Error = Error;

        #[inline]
        fn try_next_u32(&mut self) -> Result<u32, Error> {
            super::u32()
        }

        #[inline]
        fn try_next_u64(&mut self) -> Result<u64, Error> {
            super::u64()
        }

        #[inline]
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            super::fill(dest)
        }
    }

    impl TryCryptoRng for SysRng {}
}

#[cfg(feature = "sys_rng")]
pub use sys_rng::SysRng;
