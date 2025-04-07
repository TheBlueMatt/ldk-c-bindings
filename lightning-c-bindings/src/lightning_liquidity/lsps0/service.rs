// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains the main bLIP-50 / LSPS0 server-side object, [`LSPS0ServiceHandler`].
//!
//! Please refer to the [bLIP-50 / LSPS0
//! specifcation](https://github.com/lightning/blips/blob/master/blip-0050.md) for more
//! information.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::lsps0::service::LSPS0ServiceHandler as nativeLSPS0ServiceHandlerImport;
pub(crate) type nativeLSPS0ServiceHandler = nativeLSPS0ServiceHandlerImport;

/// The main server-side object allowing to send and receive bLIP-50 / LSPS0 messages.
#[must_use]
#[repr(C)]
pub struct LSPS0ServiceHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS0ServiceHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS0ServiceHandler {
	type Target = nativeLSPS0ServiceHandler;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS0ServiceHandler { }
unsafe impl core::marker::Sync for LSPS0ServiceHandler { }
impl Drop for LSPS0ServiceHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS0ServiceHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS0ServiceHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS0ServiceHandler_free(this_obj: LSPS0ServiceHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ServiceHandler_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS0ServiceHandler) };
}
#[allow(unused)]
impl LSPS0ServiceHandler {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS0ServiceHandler {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS0ServiceHandler {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS0ServiceHandler {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
