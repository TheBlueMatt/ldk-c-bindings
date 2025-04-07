// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Message, request, and other primitive types used to implement bLIP-51 / LSPS1.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::lsps1::msgs::LSPS1OrderId as nativeLSPS1OrderIdImport;
pub(crate) type nativeLSPS1OrderId = nativeLSPS1OrderIdImport;

/// The identifier of an order.
#[must_use]
#[repr(C)]
pub struct LSPS1OrderId {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1OrderId,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1OrderId {
	type Target = nativeLSPS1OrderId;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1OrderId { }
unsafe impl core::marker::Sync for LSPS1OrderId { }
impl Drop for LSPS1OrderId {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1OrderId>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1OrderId, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1OrderId_free(this_obj: LSPS1OrderId) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OrderId_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1OrderId) };
}
#[allow(unused)]
impl LSPS1OrderId {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1OrderId {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1OrderId {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1OrderId {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
#[no_mangle]
pub extern "C" fn LSPS1OrderId_get_a(this_ptr: &LSPS1OrderId) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val.as_str().into()
}
#[no_mangle]
pub extern "C" fn LSPS1OrderId_set_a(this_ptr: &mut LSPS1OrderId, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_string();
}
/// Constructs a new LSPS1OrderId given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1OrderId_new(mut a_arg: crate::c_types::Str) -> LSPS1OrderId {
	LSPS1OrderId { inner: ObjOps::heap_alloc(lightning_liquidity::lsps1::msgs::LSPS1OrderId (
		a_arg.into_string(),
	)), is_owned: true }
}
impl Clone for LSPS1OrderId {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1OrderId>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OrderId_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1OrderId)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1OrderId
pub extern "C" fn LSPS1OrderId_clone(orig: &LSPS1OrderId) -> LSPS1OrderId {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1OrderId object
pub extern "C" fn LSPS1OrderId_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId }).into()}
/// Checks if two LSPS1OrderIds contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1OrderId_eq(a: &LSPS1OrderId, b: &LSPS1OrderId) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Generates a non-cryptographic 64-bit hash of the LSPS1OrderId.
#[no_mangle]
pub extern "C" fn LSPS1OrderId_hash(o: &LSPS1OrderId) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning_liquidity::lsps1::msgs::LSPS1GetInfoRequest as nativeLSPS1GetInfoRequestImport;
pub(crate) type nativeLSPS1GetInfoRequest = nativeLSPS1GetInfoRequestImport;

/// A request made to an LSP to retrieve the supported options.
///
/// Please refer to the [bLIP-51 / LSPS1
/// specification](https://github.com/lightning/blips/blob/master/blip-0051.md#1-lsps1get_info) for
/// more information.
#[must_use]
#[repr(C)]
pub struct LSPS1GetInfoRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1GetInfoRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1GetInfoRequest {
	type Target = nativeLSPS1GetInfoRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1GetInfoRequest { }
unsafe impl core::marker::Sync for LSPS1GetInfoRequest { }
impl Drop for LSPS1GetInfoRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1GetInfoRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1GetInfoRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1GetInfoRequest_free(this_obj: LSPS1GetInfoRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1GetInfoRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1GetInfoRequest) };
}
#[allow(unused)]
impl LSPS1GetInfoRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1GetInfoRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1GetInfoRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1GetInfoRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new LSPS1GetInfoRequest given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1GetInfoRequest_new() -> LSPS1GetInfoRequest {
	LSPS1GetInfoRequest { inner: ObjOps::heap_alloc(nativeLSPS1GetInfoRequest {
	}), is_owned: true }
}
impl Clone for LSPS1GetInfoRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1GetInfoRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1GetInfoRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1GetInfoRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1GetInfoRequest
pub extern "C" fn LSPS1GetInfoRequest_clone(orig: &LSPS1GetInfoRequest) -> LSPS1GetInfoRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1GetInfoRequest object
pub extern "C" fn LSPS1GetInfoRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoRequest }).into()}
/// Checks if two LSPS1GetInfoRequests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1GetInfoRequest_eq(a: &LSPS1GetInfoRequest, b: &LSPS1GetInfoRequest) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1Options as nativeLSPS1OptionsImport;
pub(crate) type nativeLSPS1Options = nativeLSPS1OptionsImport;

/// An object representing the supported protocol options.
#[must_use]
#[repr(C)]
pub struct LSPS1Options {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1Options,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1Options {
	type Target = nativeLSPS1Options;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1Options { }
unsafe impl core::marker::Sync for LSPS1Options { }
impl Drop for LSPS1Options {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1Options>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1Options, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1Options_free(this_obj: LSPS1Options) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Options_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1Options) };
}
#[allow(unused)]
impl LSPS1Options {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1Options {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1Options {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1Options {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The smallest number of confirmations needed for the LSP to accept a channel as confirmed.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_min_required_channel_confirmations(this_ptr: &LSPS1Options) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_required_channel_confirmations;
	*inner_val
}
/// The smallest number of confirmations needed for the LSP to accept a channel as confirmed.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_min_required_channel_confirmations(this_ptr: &mut LSPS1Options, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_required_channel_confirmations = val;
}
/// The smallest number of blocks in which the LSP can confirm the funding transaction.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_min_funding_confirms_within_blocks(this_ptr: &LSPS1Options) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_funding_confirms_within_blocks;
	*inner_val
}
/// The smallest number of blocks in which the LSP can confirm the funding transaction.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_min_funding_confirms_within_blocks(this_ptr: &mut LSPS1Options, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_funding_confirms_within_blocks = val;
}
/// Indicates if the LSP supports zero reserve.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_supports_zero_channel_reserve(this_ptr: &LSPS1Options) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().supports_zero_channel_reserve;
	*inner_val
}
/// Indicates if the LSP supports zero reserve.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_supports_zero_channel_reserve(this_ptr: &mut LSPS1Options, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.supports_zero_channel_reserve = val;
}
/// The maximum number of blocks a channel can be leased for.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_max_channel_expiry_blocks(this_ptr: &LSPS1Options) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_channel_expiry_blocks;
	*inner_val
}
/// The maximum number of blocks a channel can be leased for.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_max_channel_expiry_blocks(this_ptr: &mut LSPS1Options, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_channel_expiry_blocks = val;
}
/// The minimum number of satoshi that the client MUST request.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_min_initial_client_balance_sat(this_ptr: &LSPS1Options) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_initial_client_balance_sat;
	*inner_val
}
/// The minimum number of satoshi that the client MUST request.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_min_initial_client_balance_sat(this_ptr: &mut LSPS1Options, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_initial_client_balance_sat = val;
}
/// The maximum number of satoshi that the client MUST request.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_max_initial_client_balance_sat(this_ptr: &LSPS1Options) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_initial_client_balance_sat;
	*inner_val
}
/// The maximum number of satoshi that the client MUST request.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_max_initial_client_balance_sat(this_ptr: &mut LSPS1Options, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_initial_client_balance_sat = val;
}
/// The minimum number of satoshi that the LSP will provide to the channel.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_min_initial_lsp_balance_sat(this_ptr: &LSPS1Options) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_initial_lsp_balance_sat;
	*inner_val
}
/// The minimum number of satoshi that the LSP will provide to the channel.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_min_initial_lsp_balance_sat(this_ptr: &mut LSPS1Options, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_initial_lsp_balance_sat = val;
}
/// The maximum number of satoshi that the LSP will provide to the channel.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_max_initial_lsp_balance_sat(this_ptr: &LSPS1Options) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_initial_lsp_balance_sat;
	*inner_val
}
/// The maximum number of satoshi that the LSP will provide to the channel.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_max_initial_lsp_balance_sat(this_ptr: &mut LSPS1Options, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_initial_lsp_balance_sat = val;
}
/// The minimal channel size.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_min_channel_balance_sat(this_ptr: &LSPS1Options) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_channel_balance_sat;
	*inner_val
}
/// The minimal channel size.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_min_channel_balance_sat(this_ptr: &mut LSPS1Options, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_channel_balance_sat = val;
}
/// The maximal channel size.
#[no_mangle]
pub extern "C" fn LSPS1Options_get_max_channel_balance_sat(this_ptr: &LSPS1Options) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_channel_balance_sat;
	*inner_val
}
/// The maximal channel size.
#[no_mangle]
pub extern "C" fn LSPS1Options_set_max_channel_balance_sat(this_ptr: &mut LSPS1Options, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_channel_balance_sat = val;
}
/// Constructs a new LSPS1Options given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1Options_new(mut min_required_channel_confirmations_arg: u16, mut min_funding_confirms_within_blocks_arg: u16, mut supports_zero_channel_reserve_arg: bool, mut max_channel_expiry_blocks_arg: u32, mut min_initial_client_balance_sat_arg: u64, mut max_initial_client_balance_sat_arg: u64, mut min_initial_lsp_balance_sat_arg: u64, mut max_initial_lsp_balance_sat_arg: u64, mut min_channel_balance_sat_arg: u64, mut max_channel_balance_sat_arg: u64) -> LSPS1Options {
	LSPS1Options { inner: ObjOps::heap_alloc(nativeLSPS1Options {
		min_required_channel_confirmations: min_required_channel_confirmations_arg,
		min_funding_confirms_within_blocks: min_funding_confirms_within_blocks_arg,
		supports_zero_channel_reserve: supports_zero_channel_reserve_arg,
		max_channel_expiry_blocks: max_channel_expiry_blocks_arg,
		min_initial_client_balance_sat: min_initial_client_balance_sat_arg,
		max_initial_client_balance_sat: max_initial_client_balance_sat_arg,
		min_initial_lsp_balance_sat: min_initial_lsp_balance_sat_arg,
		max_initial_lsp_balance_sat: max_initial_lsp_balance_sat_arg,
		min_channel_balance_sat: min_channel_balance_sat_arg,
		max_channel_balance_sat: max_channel_balance_sat_arg,
	}), is_owned: true }
}
impl Clone for LSPS1Options {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1Options>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Options_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1Options)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1Options
pub extern "C" fn LSPS1Options_clone(orig: &LSPS1Options) -> LSPS1Options {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1Options object
pub extern "C" fn LSPS1Options_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1Options }).into()}
/// Checks if two LSPS1Optionss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1Options_eq(a: &LSPS1Options, b: &LSPS1Options) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1GetInfoResponse as nativeLSPS1GetInfoResponseImport;
pub(crate) type nativeLSPS1GetInfoResponse = nativeLSPS1GetInfoResponseImport;

/// A response to a [`LSPS1GetInfoRequest`].
#[must_use]
#[repr(C)]
pub struct LSPS1GetInfoResponse {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1GetInfoResponse,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1GetInfoResponse {
	type Target = nativeLSPS1GetInfoResponse;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1GetInfoResponse { }
unsafe impl core::marker::Sync for LSPS1GetInfoResponse { }
impl Drop for LSPS1GetInfoResponse {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1GetInfoResponse>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1GetInfoResponse, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1GetInfoResponse_free(this_obj: LSPS1GetInfoResponse) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1GetInfoResponse_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1GetInfoResponse) };
}
#[allow(unused)]
impl LSPS1GetInfoResponse {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1GetInfoResponse {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1GetInfoResponse {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1GetInfoResponse {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// All options supported by the LSP.
#[no_mangle]
pub extern "C" fn LSPS1GetInfoResponse_get_options(this_ptr: &LSPS1GetInfoResponse) -> crate::lightning_liquidity::lsps1::msgs::LSPS1Options {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().options;
	crate::lightning_liquidity::lsps1::msgs::LSPS1Options { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps1::msgs::LSPS1Options<>) as *mut _) }, is_owned: false }
}
/// All options supported by the LSP.
#[no_mangle]
pub extern "C" fn LSPS1GetInfoResponse_set_options(this_ptr: &mut LSPS1GetInfoResponse, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1Options) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.options = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new LSPS1GetInfoResponse given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1GetInfoResponse_new(mut options_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1Options) -> LSPS1GetInfoResponse {
	LSPS1GetInfoResponse { inner: ObjOps::heap_alloc(nativeLSPS1GetInfoResponse {
		options: *unsafe { Box::from_raw(options_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for LSPS1GetInfoResponse {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1GetInfoResponse>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1GetInfoResponse_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1GetInfoResponse)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1GetInfoResponse
pub extern "C" fn LSPS1GetInfoResponse_clone(orig: &LSPS1GetInfoResponse) -> LSPS1GetInfoResponse {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1GetInfoResponse object
pub extern "C" fn LSPS1GetInfoResponse_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoResponse }).into()}
/// Checks if two LSPS1GetInfoResponses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1GetInfoResponse_eq(a: &LSPS1GetInfoResponse, b: &LSPS1GetInfoResponse) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1CreateOrderRequest as nativeLSPS1CreateOrderRequestImport;
pub(crate) type nativeLSPS1CreateOrderRequest = nativeLSPS1CreateOrderRequestImport;

/// A request made to an LSP to create an order.
///
/// Please refer to the [bLIP-51 / LSPS1
/// specification](https://github.com/lightning/blips/blob/master/blip-0051.md#2-lsps1create_order)
/// for more information.
#[must_use]
#[repr(C)]
pub struct LSPS1CreateOrderRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1CreateOrderRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1CreateOrderRequest {
	type Target = nativeLSPS1CreateOrderRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1CreateOrderRequest { }
unsafe impl core::marker::Sync for LSPS1CreateOrderRequest { }
impl Drop for LSPS1CreateOrderRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1CreateOrderRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1CreateOrderRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderRequest_free(this_obj: LSPS1CreateOrderRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1CreateOrderRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1CreateOrderRequest) };
}
#[allow(unused)]
impl LSPS1CreateOrderRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1CreateOrderRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1CreateOrderRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1CreateOrderRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The order made.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderRequest_get_order(this_ptr: &LSPS1CreateOrderRequest) -> crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().order;
	crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps1::msgs::LSPS1OrderParams<>) as *mut _) }, is_owned: false }
}
/// The order made.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderRequest_set_order(this_ptr: &mut LSPS1CreateOrderRequest, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.order = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The address where the LSP will send the funds if the order fails.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderRequest_get_refund_onchain_address(this_ptr: &LSPS1CreateOrderRequest) -> crate::c_types::derived::COption_AddressZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().refund_onchain_address;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_AddressZ::None } else { crate::c_types::derived::COption_AddressZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::Address::from_rust(&(*inner_val.as_ref().unwrap()).clone()) }) };
	local_inner_val
}
/// The address where the LSP will send the funds if the order fails.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderRequest_set_refund_onchain_address(this_ptr: &mut LSPS1CreateOrderRequest, mut val: crate::c_types::derived::COption_AddressZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_rust() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.refund_onchain_address = local_val;
}
/// Constructs a new LSPS1CreateOrderRequest given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderRequest_new(mut order_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams, mut refund_onchain_address_arg: crate::c_types::derived::COption_AddressZ) -> LSPS1CreateOrderRequest {
	let mut local_refund_onchain_address_arg = { /*refund_onchain_address_arg*/ let refund_onchain_address_arg_opt = refund_onchain_address_arg; if refund_onchain_address_arg_opt.is_none() { None } else { Some({ { { refund_onchain_address_arg_opt.take() }.into_rust() }})} };
	LSPS1CreateOrderRequest { inner: ObjOps::heap_alloc(nativeLSPS1CreateOrderRequest {
		order: *unsafe { Box::from_raw(order_arg.take_inner()) },
		refund_onchain_address: local_refund_onchain_address_arg,
	}), is_owned: true }
}
impl Clone for LSPS1CreateOrderRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1CreateOrderRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1CreateOrderRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1CreateOrderRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1CreateOrderRequest
pub extern "C" fn LSPS1CreateOrderRequest_clone(orig: &LSPS1CreateOrderRequest) -> LSPS1CreateOrderRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1CreateOrderRequest object
pub extern "C" fn LSPS1CreateOrderRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderRequest }).into()}
/// Checks if two LSPS1CreateOrderRequests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderRequest_eq(a: &LSPS1CreateOrderRequest, b: &LSPS1CreateOrderRequest) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1OrderParams as nativeLSPS1OrderParamsImport;
pub(crate) type nativeLSPS1OrderParams = nativeLSPS1OrderParamsImport;

/// An object representing an bLIP-51 / LSPS1 channel order.
#[must_use]
#[repr(C)]
pub struct LSPS1OrderParams {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1OrderParams,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1OrderParams {
	type Target = nativeLSPS1OrderParams;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1OrderParams { }
unsafe impl core::marker::Sync for LSPS1OrderParams { }
impl Drop for LSPS1OrderParams {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1OrderParams>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1OrderParams, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_free(this_obj: LSPS1OrderParams) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OrderParams_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1OrderParams) };
}
#[allow(unused)]
impl LSPS1OrderParams {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1OrderParams {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1OrderParams {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1OrderParams {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Indicates how many satoshi the LSP will provide on their side.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_get_lsp_balance_sat(this_ptr: &LSPS1OrderParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().lsp_balance_sat;
	*inner_val
}
/// Indicates how many satoshi the LSP will provide on their side.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_set_lsp_balance_sat(this_ptr: &mut LSPS1OrderParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.lsp_balance_sat = val;
}
/// Indicates how many satoshi the client will provide on their side.
///
/// The client sends these funds to the LSP, who will push them back to the client upon opening
/// the channel.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_get_client_balance_sat(this_ptr: &LSPS1OrderParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().client_balance_sat;
	*inner_val
}
/// Indicates how many satoshi the client will provide on their side.
///
/// The client sends these funds to the LSP, who will push them back to the client upon opening
/// the channel.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_set_client_balance_sat(this_ptr: &mut LSPS1OrderParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.client_balance_sat = val;
}
/// The number of confirmations the funding tx must have before the LSP sends `channel_ready`.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_get_required_channel_confirmations(this_ptr: &LSPS1OrderParams) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().required_channel_confirmations;
	*inner_val
}
/// The number of confirmations the funding tx must have before the LSP sends `channel_ready`.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_set_required_channel_confirmations(this_ptr: &mut LSPS1OrderParams, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.required_channel_confirmations = val;
}
/// The maximum number of blocks the client wants to wait until the funding transaction is confirmed.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_get_funding_confirms_within_blocks(this_ptr: &LSPS1OrderParams) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funding_confirms_within_blocks;
	*inner_val
}
/// The maximum number of blocks the client wants to wait until the funding transaction is confirmed.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_set_funding_confirms_within_blocks(this_ptr: &mut LSPS1OrderParams, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funding_confirms_within_blocks = val;
}
/// Indicates how long the channel is leased for in block time.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_get_channel_expiry_blocks(this_ptr: &LSPS1OrderParams) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_expiry_blocks;
	*inner_val
}
/// Indicates how long the channel is leased for in block time.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_set_channel_expiry_blocks(this_ptr: &mut LSPS1OrderParams, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_expiry_blocks = val;
}
/// May contain arbitrary associated data like a coupon code or a authentication token.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_get_token(this_ptr: &LSPS1OrderParams) -> crate::c_types::derived::COption_StrZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().token;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_StrZ::None } else { crate::c_types::derived::COption_StrZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { (*inner_val.as_ref().unwrap()).clone().into() }) };
	local_inner_val
}
/// May contain arbitrary associated data like a coupon code or a authentication token.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_set_token(this_ptr: &mut LSPS1OrderParams, mut val: crate::c_types::derived::COption_StrZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_string() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.token = local_val;
}
/// Indicates if the channel should be announced to the network.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_get_announce_channel(this_ptr: &LSPS1OrderParams) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().announce_channel;
	*inner_val
}
/// Indicates if the channel should be announced to the network.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_set_announce_channel(this_ptr: &mut LSPS1OrderParams, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.announce_channel = val;
}
/// Constructs a new LSPS1OrderParams given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_new(mut lsp_balance_sat_arg: u64, mut client_balance_sat_arg: u64, mut required_channel_confirmations_arg: u16, mut funding_confirms_within_blocks_arg: u16, mut channel_expiry_blocks_arg: u32, mut token_arg: crate::c_types::derived::COption_StrZ, mut announce_channel_arg: bool) -> LSPS1OrderParams {
	let mut local_token_arg = { /*token_arg*/ let token_arg_opt = token_arg; if token_arg_opt.is_none() { None } else { Some({ { { token_arg_opt.take() }.into_string() }})} };
	LSPS1OrderParams { inner: ObjOps::heap_alloc(nativeLSPS1OrderParams {
		lsp_balance_sat: lsp_balance_sat_arg,
		client_balance_sat: client_balance_sat_arg,
		required_channel_confirmations: required_channel_confirmations_arg,
		funding_confirms_within_blocks: funding_confirms_within_blocks_arg,
		channel_expiry_blocks: channel_expiry_blocks_arg,
		token: local_token_arg,
		announce_channel: announce_channel_arg,
	}), is_owned: true }
}
impl Clone for LSPS1OrderParams {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1OrderParams>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OrderParams_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1OrderParams)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1OrderParams
pub extern "C" fn LSPS1OrderParams_clone(orig: &LSPS1OrderParams) -> LSPS1OrderParams {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1OrderParams object
pub extern "C" fn LSPS1OrderParams_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams }).into()}
/// Checks if two LSPS1OrderParamss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1OrderParams_eq(a: &LSPS1OrderParams, b: &LSPS1OrderParams) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse as nativeLSPS1CreateOrderResponseImport;
pub(crate) type nativeLSPS1CreateOrderResponse = nativeLSPS1CreateOrderResponseImport;

/// A response to a [`LSPS1CreateOrderRequest`].
#[must_use]
#[repr(C)]
pub struct LSPS1CreateOrderResponse {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1CreateOrderResponse,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1CreateOrderResponse {
	type Target = nativeLSPS1CreateOrderResponse;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1CreateOrderResponse { }
unsafe impl core::marker::Sync for LSPS1CreateOrderResponse { }
impl Drop for LSPS1CreateOrderResponse {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1CreateOrderResponse>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1CreateOrderResponse, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_free(this_obj: LSPS1CreateOrderResponse) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1CreateOrderResponse_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1CreateOrderResponse) };
}
#[allow(unused)]
impl LSPS1CreateOrderResponse {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1CreateOrderResponse {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1CreateOrderResponse {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1CreateOrderResponse {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The id of the channel order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_get_order_id(this_ptr: &LSPS1CreateOrderResponse) -> crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().order_id;
	crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps1::msgs::LSPS1OrderId<>) as *mut _) }, is_owned: false }
}
/// The id of the channel order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_set_order_id(this_ptr: &mut LSPS1CreateOrderResponse, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.order_id = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The parameters of channel order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_get_order(this_ptr: &LSPS1CreateOrderResponse) -> crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().order;
	crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps1::msgs::LSPS1OrderParams<>) as *mut _) }, is_owned: false }
}
/// The parameters of channel order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_set_order(this_ptr: &mut LSPS1CreateOrderResponse, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.order = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The datetime when the order was created
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_get_created_at(this_ptr: &LSPS1CreateOrderResponse) -> crate::lightning_liquidity::lsps0::ser::LSPSDateTime {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().created_at;
	crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps0::ser::LSPSDateTime<>) as *mut _) }, is_owned: false }
}
/// The datetime when the order was created
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_set_created_at(this_ptr: &mut LSPS1CreateOrderResponse, mut val: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.created_at = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The current state of the order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_get_order_state(this_ptr: &LSPS1CreateOrderResponse) -> crate::lightning_liquidity::lsps1::msgs::LSPS1OrderState {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().order_state;
	crate::lightning_liquidity::lsps1::msgs::LSPS1OrderState::from_native(inner_val)
}
/// The current state of the order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_set_order_state(this_ptr: &mut LSPS1CreateOrderResponse, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderState) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.order_state = val.into_native();
}
/// Contains details about how to pay for the order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_get_payment(this_ptr: &LSPS1CreateOrderResponse) -> crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment;
	crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo<>) as *mut _) }, is_owned: false }
}
/// Contains details about how to pay for the order.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_set_payment(this_ptr: &mut LSPS1CreateOrderResponse, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Contains information about the channel state.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_get_channel(this_ptr: &LSPS1CreateOrderResponse) -> crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel;
	let mut local_inner_val = crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Contains information about the channel state.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_set_channel(this_ptr: &mut LSPS1CreateOrderResponse, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel = local_val;
}
/// Constructs a new LSPS1CreateOrderResponse given each field
///
/// Note that channel_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_new(mut order_id_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId, mut order_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams, mut created_at_arg: crate::lightning_liquidity::lsps0::ser::LSPSDateTime, mut order_state_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderState, mut payment_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo, mut channel_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo) -> LSPS1CreateOrderResponse {
	let mut local_channel_arg = if channel_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_arg.take_inner()) } }) };
	LSPS1CreateOrderResponse { inner: ObjOps::heap_alloc(nativeLSPS1CreateOrderResponse {
		order_id: *unsafe { Box::from_raw(order_id_arg.take_inner()) },
		order: *unsafe { Box::from_raw(order_arg.take_inner()) },
		created_at: *unsafe { Box::from_raw(created_at_arg.take_inner()) },
		order_state: order_state_arg.into_native(),
		payment: *unsafe { Box::from_raw(payment_arg.take_inner()) },
		channel: local_channel_arg,
	}), is_owned: true }
}
impl Clone for LSPS1CreateOrderResponse {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1CreateOrderResponse>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1CreateOrderResponse_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1CreateOrderResponse)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1CreateOrderResponse
pub extern "C" fn LSPS1CreateOrderResponse_clone(orig: &LSPS1CreateOrderResponse) -> LSPS1CreateOrderResponse {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1CreateOrderResponse object
pub extern "C" fn LSPS1CreateOrderResponse_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse }).into()}
/// Checks if two LSPS1CreateOrderResponses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1CreateOrderResponse_eq(a: &LSPS1CreateOrderResponse, b: &LSPS1CreateOrderResponse) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// An object representing the status of an order.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS1OrderState {
	/// The order has been created.
	Created,
	/// The LSP has opened the channel and published the funding transaction.
	Completed,
	/// The order failed.
	Failed,
}
use lightning_liquidity::lsps1::msgs::LSPS1OrderState as LSPS1OrderStateImport;
pub(crate) type nativeLSPS1OrderState = LSPS1OrderStateImport;

impl LSPS1OrderState {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS1OrderState {
		match self {
			LSPS1OrderState::Created => nativeLSPS1OrderState::Created,
			LSPS1OrderState::Completed => nativeLSPS1OrderState::Completed,
			LSPS1OrderState::Failed => nativeLSPS1OrderState::Failed,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS1OrderState {
		match self {
			LSPS1OrderState::Created => nativeLSPS1OrderState::Created,
			LSPS1OrderState::Completed => nativeLSPS1OrderState::Completed,
			LSPS1OrderState::Failed => nativeLSPS1OrderState::Failed,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS1OrderStateImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS1OrderState) };
		match native {
			nativeLSPS1OrderState::Created => LSPS1OrderState::Created,
			nativeLSPS1OrderState::Completed => LSPS1OrderState::Completed,
			nativeLSPS1OrderState::Failed => LSPS1OrderState::Failed,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS1OrderState) -> Self {
		match native {
			nativeLSPS1OrderState::Created => LSPS1OrderState::Created,
			nativeLSPS1OrderState::Completed => LSPS1OrderState::Completed,
			nativeLSPS1OrderState::Failed => LSPS1OrderState::Failed,
		}
	}
}
/// Creates a copy of the LSPS1OrderState
#[no_mangle]
pub extern "C" fn LSPS1OrderState_clone(orig: &LSPS1OrderState) -> LSPS1OrderState {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OrderState_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS1OrderState)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OrderState_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS1OrderState) };
}
#[no_mangle]
/// Utility method to constructs a new Created-variant LSPS1OrderState
pub extern "C" fn LSPS1OrderState_created() -> LSPS1OrderState {
	LSPS1OrderState::Created}
#[no_mangle]
/// Utility method to constructs a new Completed-variant LSPS1OrderState
pub extern "C" fn LSPS1OrderState_completed() -> LSPS1OrderState {
	LSPS1OrderState::Completed}
#[no_mangle]
/// Utility method to constructs a new Failed-variant LSPS1OrderState
pub extern "C" fn LSPS1OrderState_failed() -> LSPS1OrderState {
	LSPS1OrderState::Failed}
/// Get a string which allows debug introspection of a LSPS1OrderState object
pub extern "C" fn LSPS1OrderState_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1OrderState }).into()}
/// Checks if two LSPS1OrderStates contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS1OrderState_eq(a: &LSPS1OrderState, b: &LSPS1OrderState) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo as nativeLSPS1PaymentInfoImport;
pub(crate) type nativeLSPS1PaymentInfo = nativeLSPS1PaymentInfoImport;

/// Details regarding how to pay for an order.
#[must_use]
#[repr(C)]
pub struct LSPS1PaymentInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1PaymentInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1PaymentInfo {
	type Target = nativeLSPS1PaymentInfo;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1PaymentInfo { }
unsafe impl core::marker::Sync for LSPS1PaymentInfo { }
impl Drop for LSPS1PaymentInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1PaymentInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1PaymentInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1PaymentInfo_free(this_obj: LSPS1PaymentInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1PaymentInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1PaymentInfo) };
}
#[allow(unused)]
impl LSPS1PaymentInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1PaymentInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1PaymentInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1PaymentInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// A Lightning payment using BOLT 11.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn LSPS1PaymentInfo_get_bolt11(this_ptr: &LSPS1PaymentInfo) -> crate::lightning_liquidity::lsps1::msgs::LSPS1Bolt11PaymentInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().bolt11;
	let mut local_inner_val = crate::lightning_liquidity::lsps1::msgs::LSPS1Bolt11PaymentInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning_liquidity::lsps1::msgs::LSPS1Bolt11PaymentInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// A Lightning payment using BOLT 11.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn LSPS1PaymentInfo_set_bolt11(this_ptr: &mut LSPS1PaymentInfo, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1Bolt11PaymentInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.bolt11 = local_val;
}
/// An onchain payment.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn LSPS1PaymentInfo_get_onchain(this_ptr: &LSPS1PaymentInfo) -> crate::lightning_liquidity::lsps1::msgs::LSPS1OnchainPaymentInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().onchain;
	let mut local_inner_val = crate::lightning_liquidity::lsps1::msgs::LSPS1OnchainPaymentInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning_liquidity::lsps1::msgs::LSPS1OnchainPaymentInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// An onchain payment.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn LSPS1PaymentInfo_set_onchain(this_ptr: &mut LSPS1PaymentInfo, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1OnchainPaymentInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.onchain = local_val;
}
/// Constructs a new LSPS1PaymentInfo given each field
///
/// Note that bolt11_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
/// Note that onchain_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1PaymentInfo_new(mut bolt11_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1Bolt11PaymentInfo, mut onchain_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1OnchainPaymentInfo) -> LSPS1PaymentInfo {
	let mut local_bolt11_arg = if bolt11_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(bolt11_arg.take_inner()) } }) };
	let mut local_onchain_arg = if onchain_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(onchain_arg.take_inner()) } }) };
	LSPS1PaymentInfo { inner: ObjOps::heap_alloc(nativeLSPS1PaymentInfo {
		bolt11: local_bolt11_arg,
		onchain: local_onchain_arg,
	}), is_owned: true }
}
impl Clone for LSPS1PaymentInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1PaymentInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1PaymentInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1PaymentInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1PaymentInfo
pub extern "C" fn LSPS1PaymentInfo_clone(orig: &LSPS1PaymentInfo) -> LSPS1PaymentInfo {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1PaymentInfo object
pub extern "C" fn LSPS1PaymentInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo }).into()}
/// Checks if two LSPS1PaymentInfos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1PaymentInfo_eq(a: &LSPS1PaymentInfo, b: &LSPS1PaymentInfo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1Bolt11PaymentInfo as nativeLSPS1Bolt11PaymentInfoImport;
pub(crate) type nativeLSPS1Bolt11PaymentInfo = nativeLSPS1Bolt11PaymentInfoImport;

/// A Lightning payment using BOLT 11.
#[must_use]
#[repr(C)]
pub struct LSPS1Bolt11PaymentInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1Bolt11PaymentInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1Bolt11PaymentInfo {
	type Target = nativeLSPS1Bolt11PaymentInfo;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1Bolt11PaymentInfo { }
unsafe impl core::marker::Sync for LSPS1Bolt11PaymentInfo { }
impl Drop for LSPS1Bolt11PaymentInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1Bolt11PaymentInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1Bolt11PaymentInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_free(this_obj: LSPS1Bolt11PaymentInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Bolt11PaymentInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1Bolt11PaymentInfo) };
}
#[allow(unused)]
impl LSPS1Bolt11PaymentInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1Bolt11PaymentInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1Bolt11PaymentInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1Bolt11PaymentInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Indicates the current state of the payment.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_get_state(this_ptr: &LSPS1Bolt11PaymentInfo) -> crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().state;
	crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState::from_native(inner_val)
}
/// Indicates the current state of the payment.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_set_state(this_ptr: &mut LSPS1Bolt11PaymentInfo, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.state = val.into_native();
}
/// The datetime when the payment option expires.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_get_expires_at(this_ptr: &LSPS1Bolt11PaymentInfo) -> crate::lightning_liquidity::lsps0::ser::LSPSDateTime {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().expires_at;
	crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps0::ser::LSPSDateTime<>) as *mut _) }, is_owned: false }
}
/// The datetime when the payment option expires.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_set_expires_at(this_ptr: &mut LSPS1Bolt11PaymentInfo, mut val: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.expires_at = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The total fee the LSP will charge to open this channel in satoshi.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_get_fee_total_sat(this_ptr: &LSPS1Bolt11PaymentInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_total_sat;
	*inner_val
}
/// The total fee the LSP will charge to open this channel in satoshi.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_set_fee_total_sat(this_ptr: &mut LSPS1Bolt11PaymentInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_total_sat = val;
}
/// The amount the client needs to pay to have the requested channel openend.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_get_order_total_sat(this_ptr: &LSPS1Bolt11PaymentInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().order_total_sat;
	*inner_val
}
/// The amount the client needs to pay to have the requested channel openend.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_set_order_total_sat(this_ptr: &mut LSPS1Bolt11PaymentInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.order_total_sat = val;
}
/// A BOLT11 invoice the client can pay to have to channel opened.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_get_invoice(this_ptr: &LSPS1Bolt11PaymentInfo) -> crate::lightning_invoice::Bolt11Invoice {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().invoice;
	crate::lightning_invoice::Bolt11Invoice { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_invoice::Bolt11Invoice<>) as *mut _) }, is_owned: false }
}
/// A BOLT11 invoice the client can pay to have to channel opened.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_set_invoice(this_ptr: &mut LSPS1Bolt11PaymentInfo, mut val: crate::lightning_invoice::Bolt11Invoice) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.invoice = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new LSPS1Bolt11PaymentInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_new(mut state_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState, mut expires_at_arg: crate::lightning_liquidity::lsps0::ser::LSPSDateTime, mut fee_total_sat_arg: u64, mut order_total_sat_arg: u64, mut invoice_arg: crate::lightning_invoice::Bolt11Invoice) -> LSPS1Bolt11PaymentInfo {
	LSPS1Bolt11PaymentInfo { inner: ObjOps::heap_alloc(nativeLSPS1Bolt11PaymentInfo {
		state: state_arg.into_native(),
		expires_at: *unsafe { Box::from_raw(expires_at_arg.take_inner()) },
		fee_total_sat: fee_total_sat_arg,
		order_total_sat: order_total_sat_arg,
		invoice: *unsafe { Box::from_raw(invoice_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for LSPS1Bolt11PaymentInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1Bolt11PaymentInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Bolt11PaymentInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1Bolt11PaymentInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1Bolt11PaymentInfo
pub extern "C" fn LSPS1Bolt11PaymentInfo_clone(orig: &LSPS1Bolt11PaymentInfo) -> LSPS1Bolt11PaymentInfo {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1Bolt11PaymentInfo object
pub extern "C" fn LSPS1Bolt11PaymentInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1Bolt11PaymentInfo }).into()}
/// Checks if two LSPS1Bolt11PaymentInfos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1Bolt11PaymentInfo_eq(a: &LSPS1Bolt11PaymentInfo, b: &LSPS1Bolt11PaymentInfo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1OnchainPaymentInfo as nativeLSPS1OnchainPaymentInfoImport;
pub(crate) type nativeLSPS1OnchainPaymentInfo = nativeLSPS1OnchainPaymentInfoImport;

/// An onchain payment.
#[must_use]
#[repr(C)]
pub struct LSPS1OnchainPaymentInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1OnchainPaymentInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1OnchainPaymentInfo {
	type Target = nativeLSPS1OnchainPaymentInfo;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1OnchainPaymentInfo { }
unsafe impl core::marker::Sync for LSPS1OnchainPaymentInfo { }
impl Drop for LSPS1OnchainPaymentInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1OnchainPaymentInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1OnchainPaymentInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_free(this_obj: LSPS1OnchainPaymentInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OnchainPaymentInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1OnchainPaymentInfo) };
}
#[allow(unused)]
impl LSPS1OnchainPaymentInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1OnchainPaymentInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1OnchainPaymentInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1OnchainPaymentInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Indicates the current state of the payment.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_get_state(this_ptr: &LSPS1OnchainPaymentInfo) -> crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().state;
	crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState::from_native(inner_val)
}
/// Indicates the current state of the payment.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_set_state(this_ptr: &mut LSPS1OnchainPaymentInfo, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.state = val.into_native();
}
/// The datetime when the payment option expires.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_get_expires_at(this_ptr: &LSPS1OnchainPaymentInfo) -> crate::lightning_liquidity::lsps0::ser::LSPSDateTime {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().expires_at;
	crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps0::ser::LSPSDateTime<>) as *mut _) }, is_owned: false }
}
/// The datetime when the payment option expires.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_set_expires_at(this_ptr: &mut LSPS1OnchainPaymentInfo, mut val: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.expires_at = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The total fee the LSP will charge to open this channel in satoshi.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_get_fee_total_sat(this_ptr: &LSPS1OnchainPaymentInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_total_sat;
	*inner_val
}
/// The total fee the LSP will charge to open this channel in satoshi.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_set_fee_total_sat(this_ptr: &mut LSPS1OnchainPaymentInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_total_sat = val;
}
/// The amount the client needs to pay to have the requested channel openend.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_get_order_total_sat(this_ptr: &LSPS1OnchainPaymentInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().order_total_sat;
	*inner_val
}
/// The amount the client needs to pay to have the requested channel openend.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_set_order_total_sat(this_ptr: &mut LSPS1OnchainPaymentInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.order_total_sat = val;
}
/// An on-chain address the client can send [`Self::order_total_sat`] to to have the channel
/// opened.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_get_address(this_ptr: &LSPS1OnchainPaymentInfo) -> crate::c_types::Address {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().address;
	crate::c_types::Address::from_rust(inner_val)
}
/// An on-chain address the client can send [`Self::order_total_sat`] to to have the channel
/// opened.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_set_address(this_ptr: &mut LSPS1OnchainPaymentInfo, mut val: crate::c_types::Address) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.address = val.into_rust();
}
/// The minimum number of block confirmations that are required for the on-chain payment to be
/// considered confirmed.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_get_min_onchain_payment_confirmations(this_ptr: &LSPS1OnchainPaymentInfo) -> crate::c_types::derived::COption_u16Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_onchain_payment_confirmations;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u16Z::None } else { crate::c_types::derived::COption_u16Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The minimum number of block confirmations that are required for the on-chain payment to be
/// considered confirmed.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_set_min_onchain_payment_confirmations(this_ptr: &mut LSPS1OnchainPaymentInfo, mut val: crate::c_types::derived::COption_u16Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_onchain_payment_confirmations = local_val;
}
/// The address where the LSP will send the funds if the order fails.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_get_refund_onchain_address(this_ptr: &LSPS1OnchainPaymentInfo) -> crate::c_types::derived::COption_AddressZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().refund_onchain_address;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_AddressZ::None } else { crate::c_types::derived::COption_AddressZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::Address::from_rust(&(*inner_val.as_ref().unwrap()).clone()) }) };
	local_inner_val
}
/// The address where the LSP will send the funds if the order fails.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_set_refund_onchain_address(this_ptr: &mut LSPS1OnchainPaymentInfo, mut val: crate::c_types::derived::COption_AddressZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_rust() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.refund_onchain_address = local_val;
}
impl Clone for LSPS1OnchainPaymentInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1OnchainPaymentInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OnchainPaymentInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1OnchainPaymentInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1OnchainPaymentInfo
pub extern "C" fn LSPS1OnchainPaymentInfo_clone(orig: &LSPS1OnchainPaymentInfo) -> LSPS1OnchainPaymentInfo {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1OnchainPaymentInfo object
pub extern "C" fn LSPS1OnchainPaymentInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1OnchainPaymentInfo }).into()}
/// Checks if two LSPS1OnchainPaymentInfos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPaymentInfo_eq(a: &LSPS1OnchainPaymentInfo, b: &LSPS1OnchainPaymentInfo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// The state of a payment.
///
/// *Note*: Previously, the spec also knew a `CANCELLED` state for BOLT11 payments, which has since
/// been deprecated and `REFUNDED` should be used instead.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS1PaymentState {
	/// A payment is expected.
	ExpectPayment,
	/// A sufficient payment has been received.
	Paid,
	/// The payment has been refunded.
	Refunded,
}
use lightning_liquidity::lsps1::msgs::LSPS1PaymentState as LSPS1PaymentStateImport;
pub(crate) type nativeLSPS1PaymentState = LSPS1PaymentStateImport;

impl LSPS1PaymentState {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS1PaymentState {
		match self {
			LSPS1PaymentState::ExpectPayment => nativeLSPS1PaymentState::ExpectPayment,
			LSPS1PaymentState::Paid => nativeLSPS1PaymentState::Paid,
			LSPS1PaymentState::Refunded => nativeLSPS1PaymentState::Refunded,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS1PaymentState {
		match self {
			LSPS1PaymentState::ExpectPayment => nativeLSPS1PaymentState::ExpectPayment,
			LSPS1PaymentState::Paid => nativeLSPS1PaymentState::Paid,
			LSPS1PaymentState::Refunded => nativeLSPS1PaymentState::Refunded,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS1PaymentStateImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS1PaymentState) };
		match native {
			nativeLSPS1PaymentState::ExpectPayment => LSPS1PaymentState::ExpectPayment,
			nativeLSPS1PaymentState::Paid => LSPS1PaymentState::Paid,
			nativeLSPS1PaymentState::Refunded => LSPS1PaymentState::Refunded,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS1PaymentState) -> Self {
		match native {
			nativeLSPS1PaymentState::ExpectPayment => LSPS1PaymentState::ExpectPayment,
			nativeLSPS1PaymentState::Paid => LSPS1PaymentState::Paid,
			nativeLSPS1PaymentState::Refunded => LSPS1PaymentState::Refunded,
		}
	}
}
/// Creates a copy of the LSPS1PaymentState
#[no_mangle]
pub extern "C" fn LSPS1PaymentState_clone(orig: &LSPS1PaymentState) -> LSPS1PaymentState {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1PaymentState_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS1PaymentState)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1PaymentState_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS1PaymentState) };
}
#[no_mangle]
/// Utility method to constructs a new ExpectPayment-variant LSPS1PaymentState
pub extern "C" fn LSPS1PaymentState_expect_payment() -> LSPS1PaymentState {
	LSPS1PaymentState::ExpectPayment}
#[no_mangle]
/// Utility method to constructs a new Paid-variant LSPS1PaymentState
pub extern "C" fn LSPS1PaymentState_paid() -> LSPS1PaymentState {
	LSPS1PaymentState::Paid}
#[no_mangle]
/// Utility method to constructs a new Refunded-variant LSPS1PaymentState
pub extern "C" fn LSPS1PaymentState_refunded() -> LSPS1PaymentState {
	LSPS1PaymentState::Refunded}
/// Get a string which allows debug introspection of a LSPS1PaymentState object
pub extern "C" fn LSPS1PaymentState_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentState }).into()}
/// Checks if two LSPS1PaymentStates contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS1PaymentState_eq(a: &LSPS1PaymentState, b: &LSPS1PaymentState) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1OnchainPayment as nativeLSPS1OnchainPaymentImport;
pub(crate) type nativeLSPS1OnchainPayment = nativeLSPS1OnchainPaymentImport;

/// Details regarding a detected on-chain payment.
#[must_use]
#[repr(C)]
pub struct LSPS1OnchainPayment {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1OnchainPayment,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1OnchainPayment {
	type Target = nativeLSPS1OnchainPayment;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1OnchainPayment { }
unsafe impl core::marker::Sync for LSPS1OnchainPayment { }
impl Drop for LSPS1OnchainPayment {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1OnchainPayment>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1OnchainPayment, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_free(this_obj: LSPS1OnchainPayment) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OnchainPayment_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1OnchainPayment) };
}
#[allow(unused)]
impl LSPS1OnchainPayment {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1OnchainPayment {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1OnchainPayment {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1OnchainPayment {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The outpoint of the payment.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_get_outpoint(this_ptr: &LSPS1OnchainPayment) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outpoint;
	inner_val.as_str().into()
}
/// The outpoint of the payment.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_set_outpoint(this_ptr: &mut LSPS1OnchainPayment, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = val.into_string();
}
/// The amount of satoshi paid.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_get_sat(this_ptr: &LSPS1OnchainPayment) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().sat;
	*inner_val
}
/// The amount of satoshi paid.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_set_sat(this_ptr: &mut LSPS1OnchainPayment, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.sat = val;
}
/// Indicates if the LSP regards the transaction as sufficiently confirmed.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_get_confirmed(this_ptr: &LSPS1OnchainPayment) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().confirmed;
	*inner_val
}
/// Indicates if the LSP regards the transaction as sufficiently confirmed.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_set_confirmed(this_ptr: &mut LSPS1OnchainPayment, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.confirmed = val;
}
/// Constructs a new LSPS1OnchainPayment given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_new(mut outpoint_arg: crate::c_types::Str, mut sat_arg: u64, mut confirmed_arg: bool) -> LSPS1OnchainPayment {
	LSPS1OnchainPayment { inner: ObjOps::heap_alloc(nativeLSPS1OnchainPayment {
		outpoint: outpoint_arg.into_string(),
		sat: sat_arg,
		confirmed: confirmed_arg,
	}), is_owned: true }
}
impl Clone for LSPS1OnchainPayment {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1OnchainPayment>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1OnchainPayment_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1OnchainPayment)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1OnchainPayment
pub extern "C" fn LSPS1OnchainPayment_clone(orig: &LSPS1OnchainPayment) -> LSPS1OnchainPayment {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1OnchainPayment object
pub extern "C" fn LSPS1OnchainPayment_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1OnchainPayment }).into()}
/// Checks if two LSPS1OnchainPayments contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1OnchainPayment_eq(a: &LSPS1OnchainPayment, b: &LSPS1OnchainPayment) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo as nativeLSPS1ChannelInfoImport;
pub(crate) type nativeLSPS1ChannelInfo = nativeLSPS1ChannelInfoImport;

/// Details regarding the state of an ordered channel.
#[must_use]
#[repr(C)]
pub struct LSPS1ChannelInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1ChannelInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1ChannelInfo {
	type Target = nativeLSPS1ChannelInfo;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1ChannelInfo { }
unsafe impl core::marker::Sync for LSPS1ChannelInfo { }
impl Drop for LSPS1ChannelInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1ChannelInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1ChannelInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_free(this_obj: LSPS1ChannelInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1ChannelInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1ChannelInfo) };
}
#[allow(unused)]
impl LSPS1ChannelInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1ChannelInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1ChannelInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1ChannelInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The datetime when the funding transaction has been published.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_get_funded_at(this_ptr: &LSPS1ChannelInfo) -> crate::lightning_liquidity::lsps0::ser::LSPSDateTime {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funded_at;
	crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps0::ser::LSPSDateTime<>) as *mut _) }, is_owned: false }
}
/// The datetime when the funding transaction has been published.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_set_funded_at(this_ptr: &mut LSPS1ChannelInfo, mut val: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funded_at = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The outpoint of the funding transaction.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_get_funding_outpoint(this_ptr: &LSPS1ChannelInfo) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funding_outpoint;
	crate::c_types::bitcoin_to_C_outpoint(inner_val)
}
/// The outpoint of the funding transaction.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_set_funding_outpoint(this_ptr: &mut LSPS1ChannelInfo, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funding_outpoint = crate::c_types::C_to_bitcoin_outpoint(val);
}
/// The earliest datetime when the channel may be closed by the LSP.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_get_expires_at(this_ptr: &LSPS1ChannelInfo) -> crate::lightning_liquidity::lsps0::ser::LSPSDateTime {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().expires_at;
	crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps0::ser::LSPSDateTime<>) as *mut _) }, is_owned: false }
}
/// The earliest datetime when the channel may be closed by the LSP.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_set_expires_at(this_ptr: &mut LSPS1ChannelInfo, mut val: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.expires_at = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new LSPS1ChannelInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_new(mut funded_at_arg: crate::lightning_liquidity::lsps0::ser::LSPSDateTime, mut funding_outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut expires_at_arg: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) -> LSPS1ChannelInfo {
	LSPS1ChannelInfo { inner: ObjOps::heap_alloc(nativeLSPS1ChannelInfo {
		funded_at: *unsafe { Box::from_raw(funded_at_arg.take_inner()) },
		funding_outpoint: crate::c_types::C_to_bitcoin_outpoint(funding_outpoint_arg),
		expires_at: *unsafe { Box::from_raw(expires_at_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for LSPS1ChannelInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1ChannelInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1ChannelInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1ChannelInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1ChannelInfo
pub extern "C" fn LSPS1ChannelInfo_clone(orig: &LSPS1ChannelInfo) -> LSPS1ChannelInfo {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1ChannelInfo object
pub extern "C" fn LSPS1ChannelInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo }).into()}
/// Checks if two LSPS1ChannelInfos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1ChannelInfo_eq(a: &LSPS1ChannelInfo, b: &LSPS1ChannelInfo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps1::msgs::LSPS1GetOrderRequest as nativeLSPS1GetOrderRequestImport;
pub(crate) type nativeLSPS1GetOrderRequest = nativeLSPS1GetOrderRequestImport;

/// A request made to an LSP to retrieve information about an previously made order.
///
/// Please refer to the [bLIP-51 / LSPS1
/// specification](https://github.com/lightning/blips/blob/master/blip-0051.md#21-lsps1get_order)
/// for more information.
#[must_use]
#[repr(C)]
pub struct LSPS1GetOrderRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1GetOrderRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1GetOrderRequest {
	type Target = nativeLSPS1GetOrderRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1GetOrderRequest { }
unsafe impl core::marker::Sync for LSPS1GetOrderRequest { }
impl Drop for LSPS1GetOrderRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1GetOrderRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1GetOrderRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1GetOrderRequest_free(this_obj: LSPS1GetOrderRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1GetOrderRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1GetOrderRequest) };
}
#[allow(unused)]
impl LSPS1GetOrderRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1GetOrderRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1GetOrderRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1GetOrderRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The id of the order.
#[no_mangle]
pub extern "C" fn LSPS1GetOrderRequest_get_order_id(this_ptr: &LSPS1GetOrderRequest) -> crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().order_id;
	crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps1::msgs::LSPS1OrderId<>) as *mut _) }, is_owned: false }
}
/// The id of the order.
#[no_mangle]
pub extern "C" fn LSPS1GetOrderRequest_set_order_id(this_ptr: &mut LSPS1GetOrderRequest, mut val: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.order_id = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new LSPS1GetOrderRequest given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1GetOrderRequest_new(mut order_id_arg: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId) -> LSPS1GetOrderRequest {
	LSPS1GetOrderRequest { inner: ObjOps::heap_alloc(nativeLSPS1GetOrderRequest {
		order_id: *unsafe { Box::from_raw(order_id_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for LSPS1GetOrderRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1GetOrderRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1GetOrderRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1GetOrderRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1GetOrderRequest
pub extern "C" fn LSPS1GetOrderRequest_clone(orig: &LSPS1GetOrderRequest) -> LSPS1GetOrderRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1GetOrderRequest object
pub extern "C" fn LSPS1GetOrderRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1GetOrderRequest }).into()}
/// Checks if two LSPS1GetOrderRequests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS1GetOrderRequest_eq(a: &LSPS1GetOrderRequest, b: &LSPS1GetOrderRequest) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// An enum that captures all the valid JSON-RPC requests in the bLIP-51 / LSPS1 protocol.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS1Request {
	/// A request to learn about the options supported by the LSP.
	GetInfo(
		crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoRequest),
	/// A request to create a channel order.
	CreateOrder(
		crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderRequest),
	/// A request to query a previously created channel order.
	GetOrder(
		crate::lightning_liquidity::lsps1::msgs::LSPS1GetOrderRequest),
}
use lightning_liquidity::lsps1::msgs::LSPS1Request as LSPS1RequestImport;
pub(crate) type nativeLSPS1Request = LSPS1RequestImport;

impl LSPS1Request {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS1Request {
		match self {
			LSPS1Request::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Request::GetInfo (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS1Request::CreateOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Request::CreateOrder (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS1Request::GetOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Request::GetOrder (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS1Request {
		match self {
			LSPS1Request::GetInfo (mut a, ) => {
				nativeLSPS1Request::GetInfo (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS1Request::CreateOrder (mut a, ) => {
				nativeLSPS1Request::CreateOrder (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS1Request::GetOrder (mut a, ) => {
				nativeLSPS1Request::GetOrder (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS1RequestImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS1Request) };
		match native {
			nativeLSPS1Request::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Request::GetInfo (
					crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS1Request::CreateOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Request::CreateOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS1Request::GetOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Request::GetOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1GetOrderRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS1Request) -> Self {
		match native {
			nativeLSPS1Request::GetInfo (mut a, ) => {
				LSPS1Request::GetInfo (
					crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS1Request::CreateOrder (mut a, ) => {
				LSPS1Request::CreateOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS1Request::GetOrder (mut a, ) => {
				LSPS1Request::GetOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1GetOrderRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS1Request
#[no_mangle]
pub extern "C" fn LSPS1Request_free(this_ptr: LSPS1Request) { }
/// Creates a copy of the LSPS1Request
#[no_mangle]
pub extern "C" fn LSPS1Request_clone(orig: &LSPS1Request) -> LSPS1Request {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Request_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS1Request)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Request_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS1Request) };
}
#[no_mangle]
/// Utility method to constructs a new GetInfo-variant LSPS1Request
pub extern "C" fn LSPS1Request_get_info(a: crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoRequest) -> LSPS1Request {
	LSPS1Request::GetInfo(a, )
}
#[no_mangle]
/// Utility method to constructs a new CreateOrder-variant LSPS1Request
pub extern "C" fn LSPS1Request_create_order(a: crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderRequest) -> LSPS1Request {
	LSPS1Request::CreateOrder(a, )
}
#[no_mangle]
/// Utility method to constructs a new GetOrder-variant LSPS1Request
pub extern "C" fn LSPS1Request_get_order(a: crate::lightning_liquidity::lsps1::msgs::LSPS1GetOrderRequest) -> LSPS1Request {
	LSPS1Request::GetOrder(a, )
}
/// Get a string which allows debug introspection of a LSPS1Request object
pub extern "C" fn LSPS1Request_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1Request }).into()}
/// Checks if two LSPS1Requests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS1Request_eq(a: &LSPS1Request, b: &LSPS1Request) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An enum that captures all the valid JSON-RPC responses in the bLIP-51 / LSPS1 protocol.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS1Response {
	/// A successful response to a [`LSPS1GetInfoRequest`].
	GetInfo(
		crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoResponse),
	/// An error response to a [`LSPS1GetInfoRequest`].
	GetInfoError(
		crate::lightning_liquidity::lsps0::ser::LSPSResponseError),
	/// A successful response to a [`LSPS1CreateOrderRequest`].
	CreateOrder(
		crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse),
	/// An error response to a [`LSPS1CreateOrderRequest`].
	CreateOrderError(
		crate::lightning_liquidity::lsps0::ser::LSPSResponseError),
	/// A successful response to a [`LSPS1GetOrderRequest`].
	GetOrder(
		crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse),
	/// An error response to a [`LSPS1GetOrderRequest`].
	GetOrderError(
		crate::lightning_liquidity::lsps0::ser::LSPSResponseError),
}
use lightning_liquidity::lsps1::msgs::LSPS1Response as LSPS1ResponseImport;
pub(crate) type nativeLSPS1Response = LSPS1ResponseImport;

impl LSPS1Response {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS1Response {
		match self {
			LSPS1Response::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Response::GetInfo (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS1Response::GetInfoError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Response::GetInfoError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS1Response::CreateOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Response::CreateOrder (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS1Response::CreateOrderError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Response::CreateOrderError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS1Response::GetOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Response::GetOrder (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS1Response::GetOrderError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS1Response::GetOrderError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS1Response {
		match self {
			LSPS1Response::GetInfo (mut a, ) => {
				nativeLSPS1Response::GetInfo (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS1Response::GetInfoError (mut a, ) => {
				nativeLSPS1Response::GetInfoError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS1Response::CreateOrder (mut a, ) => {
				nativeLSPS1Response::CreateOrder (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS1Response::CreateOrderError (mut a, ) => {
				nativeLSPS1Response::CreateOrderError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS1Response::GetOrder (mut a, ) => {
				nativeLSPS1Response::GetOrder (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS1Response::GetOrderError (mut a, ) => {
				nativeLSPS1Response::GetOrderError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS1ResponseImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS1Response) };
		match native {
			nativeLSPS1Response::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Response::GetInfo (
					crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoResponse { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS1Response::GetInfoError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Response::GetInfoError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS1Response::CreateOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Response::CreateOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS1Response::CreateOrderError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Response::CreateOrderError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS1Response::GetOrder (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Response::GetOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS1Response::GetOrderError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS1Response::GetOrderError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS1Response) -> Self {
		match native {
			nativeLSPS1Response::GetInfo (mut a, ) => {
				LSPS1Response::GetInfo (
					crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoResponse { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS1Response::GetInfoError (mut a, ) => {
				LSPS1Response::GetInfoError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS1Response::CreateOrder (mut a, ) => {
				LSPS1Response::CreateOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS1Response::CreateOrderError (mut a, ) => {
				LSPS1Response::CreateOrderError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS1Response::GetOrder (mut a, ) => {
				LSPS1Response::GetOrder (
					crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS1Response::GetOrderError (mut a, ) => {
				LSPS1Response::GetOrderError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS1Response
#[no_mangle]
pub extern "C" fn LSPS1Response_free(this_ptr: LSPS1Response) { }
/// Creates a copy of the LSPS1Response
#[no_mangle]
pub extern "C" fn LSPS1Response_clone(orig: &LSPS1Response) -> LSPS1Response {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Response_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS1Response)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Response_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS1Response) };
}
#[no_mangle]
/// Utility method to constructs a new GetInfo-variant LSPS1Response
pub extern "C" fn LSPS1Response_get_info(a: crate::lightning_liquidity::lsps1::msgs::LSPS1GetInfoResponse) -> LSPS1Response {
	LSPS1Response::GetInfo(a, )
}
#[no_mangle]
/// Utility method to constructs a new GetInfoError-variant LSPS1Response
pub extern "C" fn LSPS1Response_get_info_error(a: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS1Response {
	LSPS1Response::GetInfoError(a, )
}
#[no_mangle]
/// Utility method to constructs a new CreateOrder-variant LSPS1Response
pub extern "C" fn LSPS1Response_create_order(a: crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse) -> LSPS1Response {
	LSPS1Response::CreateOrder(a, )
}
#[no_mangle]
/// Utility method to constructs a new CreateOrderError-variant LSPS1Response
pub extern "C" fn LSPS1Response_create_order_error(a: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS1Response {
	LSPS1Response::CreateOrderError(a, )
}
#[no_mangle]
/// Utility method to constructs a new GetOrder-variant LSPS1Response
pub extern "C" fn LSPS1Response_get_order(a: crate::lightning_liquidity::lsps1::msgs::LSPS1CreateOrderResponse) -> LSPS1Response {
	LSPS1Response::GetOrder(a, )
}
#[no_mangle]
/// Utility method to constructs a new GetOrderError-variant LSPS1Response
pub extern "C" fn LSPS1Response_get_order_error(a: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS1Response {
	LSPS1Response::GetOrderError(a, )
}
/// Get a string which allows debug introspection of a LSPS1Response object
pub extern "C" fn LSPS1Response_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1Response }).into()}
/// Checks if two LSPS1Responses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS1Response_eq(a: &LSPS1Response, b: &LSPS1Response) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An enum that captures all valid JSON-RPC messages in the bLIP-51 / LSPS1 protocol.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS1Message {
	/// An LSPS1 JSON-RPC request.
	Request(
		crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		crate::lightning_liquidity::lsps1::msgs::LSPS1Request),
	/// An LSPS1 JSON-RPC response.
	Response(
		crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		crate::lightning_liquidity::lsps1::msgs::LSPS1Response),
}
use lightning_liquidity::lsps1::msgs::LSPS1Message as LSPS1MessageImport;
pub(crate) type nativeLSPS1Message = LSPS1MessageImport;

impl LSPS1Message {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS1Message {
		match self {
			LSPS1Message::Request (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativeLSPS1Message::Request (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
					b_nonref.into_native(),
				)
			},
			LSPS1Message::Response (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativeLSPS1Message::Response (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
					b_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS1Message {
		match self {
			LSPS1Message::Request (mut a, mut b, ) => {
				nativeLSPS1Message::Request (
					*unsafe { Box::from_raw(a.take_inner()) },
					b.into_native(),
				)
			},
			LSPS1Message::Response (mut a, mut b, ) => {
				nativeLSPS1Message::Response (
					*unsafe { Box::from_raw(a.take_inner()) },
					b.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS1MessageImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS1Message) };
		match native {
			nativeLSPS1Message::Request (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				LSPS1Message::Request (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
					crate::lightning_liquidity::lsps1::msgs::LSPS1Request::native_into(b_nonref),
				)
			},
			nativeLSPS1Message::Response (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				LSPS1Message::Response (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
					crate::lightning_liquidity::lsps1::msgs::LSPS1Response::native_into(b_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS1Message) -> Self {
		match native {
			nativeLSPS1Message::Request (mut a, mut b, ) => {
				LSPS1Message::Request (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a), is_owned: true },
					crate::lightning_liquidity::lsps1::msgs::LSPS1Request::native_into(b),
				)
			},
			nativeLSPS1Message::Response (mut a, mut b, ) => {
				LSPS1Message::Response (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a), is_owned: true },
					crate::lightning_liquidity::lsps1::msgs::LSPS1Response::native_into(b),
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS1Message
#[no_mangle]
pub extern "C" fn LSPS1Message_free(this_ptr: LSPS1Message) { }
/// Creates a copy of the LSPS1Message
#[no_mangle]
pub extern "C" fn LSPS1Message_clone(orig: &LSPS1Message) -> LSPS1Message {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Message_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS1Message)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1Message_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS1Message) };
}
#[no_mangle]
/// Utility method to constructs a new Request-variant LSPS1Message
pub extern "C" fn LSPS1Message_request(a: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,b: crate::lightning_liquidity::lsps1::msgs::LSPS1Request) -> LSPS1Message {
	LSPS1Message::Request(a, b, )
}
#[no_mangle]
/// Utility method to constructs a new Response-variant LSPS1Message
pub extern "C" fn LSPS1Message_response(a: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,b: crate::lightning_liquidity::lsps1::msgs::LSPS1Response) -> LSPS1Message {
	LSPS1Message::Response(a, b, )
}
/// Get a string which allows debug introspection of a LSPS1Message object
pub extern "C" fn LSPS1Message_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::msgs::LSPS1Message }).into()}
/// Checks if two LSPS1Messages contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS1Message_eq(a: &LSPS1Message, b: &LSPS1Message) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
