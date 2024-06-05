// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Common error types

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An error that possibly needs to be handled by the user.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum TxSyncError {
	/// A transaction sync failed and needs to be retried eventually.
	Failed,
}
use lightning_transaction_sync::error::TxSyncError as TxSyncErrorImport;
pub(crate) type nativeTxSyncError = TxSyncErrorImport;

impl TxSyncError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeTxSyncError {
		match self {
			TxSyncError::Failed => nativeTxSyncError::Failed,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeTxSyncError {
		match self {
			TxSyncError::Failed => nativeTxSyncError::Failed,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &TxSyncErrorImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeTxSyncError) };
		match native {
			nativeTxSyncError::Failed => TxSyncError::Failed,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeTxSyncError) -> Self {
		match native {
			nativeTxSyncError::Failed => TxSyncError::Failed,
		}
	}
}
/// Creates a copy of the TxSyncError
#[no_mangle]
pub extern "C" fn TxSyncError_clone(orig: &TxSyncError) -> TxSyncError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TxSyncError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const TxSyncError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TxSyncError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut TxSyncError) };
}
#[no_mangle]
/// Utility method to constructs a new Failed-variant TxSyncError
pub extern "C" fn TxSyncError_failed() -> TxSyncError {
	TxSyncError::Failed}
/// Get a string which allows debug introspection of a TxSyncError object
pub extern "C" fn TxSyncError_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_transaction_sync::error::TxSyncError }).into()}
