// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains the main bLIP-50 / LSPS0 client-side object, [`LSPS0ClientHandler`].
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


use lightning_liquidity::lsps0::client::LSPS0ClientHandler as nativeLSPS0ClientHandlerImport;
pub(crate) type nativeLSPS0ClientHandler = nativeLSPS0ClientHandlerImport<crate::lightning::sign::EntropySource, >;

/// A message handler capable of sending and handling bLIP-50 / LSPS0 messages.
#[must_use]
#[repr(C)]
pub struct LSPS0ClientHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS0ClientHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS0ClientHandler {
	type Target = nativeLSPS0ClientHandler;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS0ClientHandler { }
unsafe impl core::marker::Sync for LSPS0ClientHandler { }
impl Drop for LSPS0ClientHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS0ClientHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS0ClientHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS0ClientHandler_free(this_obj: LSPS0ClientHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ClientHandler_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS0ClientHandler) };
}
#[allow(unused)]
impl LSPS0ClientHandler {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS0ClientHandler {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS0ClientHandler {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS0ClientHandler {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Calls bLIP-50 / LSPS0's `list_protocols`.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specifcation](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[no_mangle]
pub extern "C" fn LSPS0ClientHandler_list_protocols(this_arg: &crate::lightning_liquidity::lsps0::client::LSPS0ClientHandler, mut counterparty_node_id: crate::c_types::PublicKey) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.list_protocols(&counterparty_node_id.into_rust())
}

