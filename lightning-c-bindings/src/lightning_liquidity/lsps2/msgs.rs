// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Message, request, and other primitive types used to implement bLIP-52 / LSPS2.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::lsps2::msgs::LSPS2GetInfoRequest as nativeLSPS2GetInfoRequestImport;
pub(crate) type nativeLSPS2GetInfoRequest = nativeLSPS2GetInfoRequestImport;

/// A request made to an LSP to learn their current channel fees and parameters.
#[must_use]
#[repr(C)]
pub struct LSPS2GetInfoRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2GetInfoRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2GetInfoRequest {
	type Target = nativeLSPS2GetInfoRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2GetInfoRequest { }
unsafe impl core::marker::Sync for LSPS2GetInfoRequest { }
impl Drop for LSPS2GetInfoRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2GetInfoRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2GetInfoRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoRequest_free(this_obj: LSPS2GetInfoRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2GetInfoRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2GetInfoRequest) };
}
#[allow(unused)]
impl LSPS2GetInfoRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2GetInfoRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2GetInfoRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2GetInfoRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// An optional token to provide to the LSP.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoRequest_get_token(this_ptr: &LSPS2GetInfoRequest) -> crate::c_types::derived::COption_StrZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().token;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_StrZ::None } else { crate::c_types::derived::COption_StrZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { (*inner_val.as_ref().unwrap()).clone().into() }) };
	local_inner_val
}
/// An optional token to provide to the LSP.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoRequest_set_token(this_ptr: &mut LSPS2GetInfoRequest, mut val: crate::c_types::derived::COption_StrZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_string() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.token = local_val;
}
/// Constructs a new LSPS2GetInfoRequest given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2GetInfoRequest_new(mut token_arg: crate::c_types::derived::COption_StrZ) -> LSPS2GetInfoRequest {
	let mut local_token_arg = { /*token_arg*/ let token_arg_opt = token_arg; if token_arg_opt.is_none() { None } else { Some({ { { token_arg_opt.take() }.into_string() }})} };
	LSPS2GetInfoRequest { inner: ObjOps::heap_alloc(nativeLSPS2GetInfoRequest {
		token: local_token_arg,
	}), is_owned: true }
}
impl Clone for LSPS2GetInfoRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2GetInfoRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2GetInfoRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2GetInfoRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2GetInfoRequest
pub extern "C" fn LSPS2GetInfoRequest_clone(orig: &LSPS2GetInfoRequest) -> LSPS2GetInfoRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2GetInfoRequest object
pub extern "C" fn LSPS2GetInfoRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoRequest }).into()}
/// Checks if two LSPS2GetInfoRequests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoRequest_eq(a: &LSPS2GetInfoRequest, b: &LSPS2GetInfoRequest) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams as nativeLSPS2RawOpeningFeeParamsImport;
pub(crate) type nativeLSPS2RawOpeningFeeParams = nativeLSPS2RawOpeningFeeParamsImport;

/// Fees and parameters for a JIT Channel without the promise.
///
/// The promise will be calculated automatically for the LSP and this type converted
/// into an [`LSPS2OpeningFeeParams`] for transit over the wire.
#[must_use]
#[repr(C)]
pub struct LSPS2RawOpeningFeeParams {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2RawOpeningFeeParams,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2RawOpeningFeeParams {
	type Target = nativeLSPS2RawOpeningFeeParams;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2RawOpeningFeeParams { }
unsafe impl core::marker::Sync for LSPS2RawOpeningFeeParams { }
impl Drop for LSPS2RawOpeningFeeParams {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2RawOpeningFeeParams>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2RawOpeningFeeParams, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_free(this_obj: LSPS2RawOpeningFeeParams) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2RawOpeningFeeParams_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2RawOpeningFeeParams) };
}
#[allow(unused)]
impl LSPS2RawOpeningFeeParams {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2RawOpeningFeeParams {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2RawOpeningFeeParams {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2RawOpeningFeeParams {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The minimum fee required for the channel open.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_get_min_fee_msat(this_ptr: &LSPS2RawOpeningFeeParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_fee_msat;
	*inner_val
}
/// The minimum fee required for the channel open.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_set_min_fee_msat(this_ptr: &mut LSPS2RawOpeningFeeParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_fee_msat = val;
}
/// A fee proportional to the size of the initial payment.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_get_proportional(this_ptr: &LSPS2RawOpeningFeeParams) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().proportional;
	*inner_val
}
/// A fee proportional to the size of the initial payment.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_set_proportional(this_ptr: &mut LSPS2RawOpeningFeeParams, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.proportional = val;
}
/// An [`ISO8601`](https://www.iso.org/iso-8601-date-and-time-format.html) formatted date for which these params are valid.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_get_valid_until(this_ptr: &LSPS2RawOpeningFeeParams) -> crate::lightning_liquidity::lsps0::ser::LSPSDateTime {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().valid_until;
	crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps0::ser::LSPSDateTime<>) as *mut _) }, is_owned: false }
}
/// An [`ISO8601`](https://www.iso.org/iso-8601-date-and-time-format.html) formatted date for which these params are valid.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_set_valid_until(this_ptr: &mut LSPS2RawOpeningFeeParams, mut val: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.valid_until = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The number of blocks after confirmation that the LSP promises it will keep the channel alive without closing.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_get_min_lifetime(this_ptr: &LSPS2RawOpeningFeeParams) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_lifetime;
	*inner_val
}
/// The number of blocks after confirmation that the LSP promises it will keep the channel alive without closing.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_set_min_lifetime(this_ptr: &mut LSPS2RawOpeningFeeParams, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_lifetime = val;
}
/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_get_max_client_to_self_delay(this_ptr: &LSPS2RawOpeningFeeParams) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_client_to_self_delay;
	*inner_val
}
/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_set_max_client_to_self_delay(this_ptr: &mut LSPS2RawOpeningFeeParams, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_client_to_self_delay = val;
}
/// The minimum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_get_min_payment_size_msat(this_ptr: &LSPS2RawOpeningFeeParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_payment_size_msat;
	*inner_val
}
/// The minimum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_set_min_payment_size_msat(this_ptr: &mut LSPS2RawOpeningFeeParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_payment_size_msat = val;
}
/// The maximum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_get_max_payment_size_msat(this_ptr: &LSPS2RawOpeningFeeParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_payment_size_msat;
	*inner_val
}
/// The maximum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_set_max_payment_size_msat(this_ptr: &mut LSPS2RawOpeningFeeParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_payment_size_msat = val;
}
/// Constructs a new LSPS2RawOpeningFeeParams given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2RawOpeningFeeParams_new(mut min_fee_msat_arg: u64, mut proportional_arg: u32, mut valid_until_arg: crate::lightning_liquidity::lsps0::ser::LSPSDateTime, mut min_lifetime_arg: u32, mut max_client_to_self_delay_arg: u32, mut min_payment_size_msat_arg: u64, mut max_payment_size_msat_arg: u64) -> LSPS2RawOpeningFeeParams {
	LSPS2RawOpeningFeeParams { inner: ObjOps::heap_alloc(nativeLSPS2RawOpeningFeeParams {
		min_fee_msat: min_fee_msat_arg,
		proportional: proportional_arg,
		valid_until: *unsafe { Box::from_raw(valid_until_arg.take_inner()) },
		min_lifetime: min_lifetime_arg,
		max_client_to_self_delay: max_client_to_self_delay_arg,
		min_payment_size_msat: min_payment_size_msat_arg,
		max_payment_size_msat: max_payment_size_msat_arg,
	}), is_owned: true }
}

use lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams as nativeLSPS2OpeningFeeParamsImport;
pub(crate) type nativeLSPS2OpeningFeeParams = nativeLSPS2OpeningFeeParamsImport;

/// Fees and parameters for a JIT Channel including the promise.
///
/// The promise is an HMAC calculated using a secret known to the LSP and the rest of the fields as input.
/// It exists so the LSP can verify the authenticity of a client provided LSPS2OpeningFeeParams by recalculating
/// the promise using the secret. Once verified they can be confident it was not modified by the client.
#[must_use]
#[repr(C)]
pub struct LSPS2OpeningFeeParams {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2OpeningFeeParams,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2OpeningFeeParams {
	type Target = nativeLSPS2OpeningFeeParams;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2OpeningFeeParams { }
unsafe impl core::marker::Sync for LSPS2OpeningFeeParams { }
impl Drop for LSPS2OpeningFeeParams {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2OpeningFeeParams>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2OpeningFeeParams, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_free(this_obj: LSPS2OpeningFeeParams) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2OpeningFeeParams_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2OpeningFeeParams) };
}
#[allow(unused)]
impl LSPS2OpeningFeeParams {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2OpeningFeeParams {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2OpeningFeeParams {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2OpeningFeeParams {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The minimum fee required for the channel open.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_min_fee_msat(this_ptr: &LSPS2OpeningFeeParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_fee_msat;
	*inner_val
}
/// The minimum fee required for the channel open.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_min_fee_msat(this_ptr: &mut LSPS2OpeningFeeParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_fee_msat = val;
}
/// A fee proportional to the size of the initial payment.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_proportional(this_ptr: &LSPS2OpeningFeeParams) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().proportional;
	*inner_val
}
/// A fee proportional to the size of the initial payment.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_proportional(this_ptr: &mut LSPS2OpeningFeeParams, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.proportional = val;
}
/// An [`ISO8601`](https://www.iso.org/iso-8601-date-and-time-format.html) formatted date for which these params are valid.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_valid_until(this_ptr: &LSPS2OpeningFeeParams) -> crate::lightning_liquidity::lsps0::ser::LSPSDateTime {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().valid_until;
	crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps0::ser::LSPSDateTime<>) as *mut _) }, is_owned: false }
}
/// An [`ISO8601`](https://www.iso.org/iso-8601-date-and-time-format.html) formatted date for which these params are valid.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_valid_until(this_ptr: &mut LSPS2OpeningFeeParams, mut val: crate::lightning_liquidity::lsps0::ser::LSPSDateTime) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.valid_until = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The number of blocks after confirmation that the LSP promises it will keep the channel alive without closing.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_min_lifetime(this_ptr: &LSPS2OpeningFeeParams) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_lifetime;
	*inner_val
}
/// The number of blocks after confirmation that the LSP promises it will keep the channel alive without closing.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_min_lifetime(this_ptr: &mut LSPS2OpeningFeeParams, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_lifetime = val;
}
/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_max_client_to_self_delay(this_ptr: &LSPS2OpeningFeeParams) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_client_to_self_delay;
	*inner_val
}
/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_max_client_to_self_delay(this_ptr: &mut LSPS2OpeningFeeParams, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_client_to_self_delay = val;
}
/// The minimum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_min_payment_size_msat(this_ptr: &LSPS2OpeningFeeParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_payment_size_msat;
	*inner_val
}
/// The minimum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_min_payment_size_msat(this_ptr: &mut LSPS2OpeningFeeParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_payment_size_msat = val;
}
/// The maximum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_max_payment_size_msat(this_ptr: &LSPS2OpeningFeeParams) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_payment_size_msat;
	*inner_val
}
/// The maximum payment size that the LSP will accept when opening a channel.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_max_payment_size_msat(this_ptr: &mut LSPS2OpeningFeeParams, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_payment_size_msat = val;
}
/// The HMAC used to verify the authenticity of these parameters.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_get_promise(this_ptr: &LSPS2OpeningFeeParams) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().promise;
	inner_val.as_str().into()
}
/// The HMAC used to verify the authenticity of these parameters.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_set_promise(this_ptr: &mut LSPS2OpeningFeeParams, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.promise = val.into_string();
}
/// Constructs a new LSPS2OpeningFeeParams given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_new(mut min_fee_msat_arg: u64, mut proportional_arg: u32, mut valid_until_arg: crate::lightning_liquidity::lsps0::ser::LSPSDateTime, mut min_lifetime_arg: u32, mut max_client_to_self_delay_arg: u32, mut min_payment_size_msat_arg: u64, mut max_payment_size_msat_arg: u64, mut promise_arg: crate::c_types::Str) -> LSPS2OpeningFeeParams {
	LSPS2OpeningFeeParams { inner: ObjOps::heap_alloc(nativeLSPS2OpeningFeeParams {
		min_fee_msat: min_fee_msat_arg,
		proportional: proportional_arg,
		valid_until: *unsafe { Box::from_raw(valid_until_arg.take_inner()) },
		min_lifetime: min_lifetime_arg,
		max_client_to_self_delay: max_client_to_self_delay_arg,
		min_payment_size_msat: min_payment_size_msat_arg,
		max_payment_size_msat: max_payment_size_msat_arg,
		promise: promise_arg.into_string(),
	}), is_owned: true }
}
impl Clone for LSPS2OpeningFeeParams {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2OpeningFeeParams>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2OpeningFeeParams_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2OpeningFeeParams)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2OpeningFeeParams
pub extern "C" fn LSPS2OpeningFeeParams_clone(orig: &LSPS2OpeningFeeParams) -> LSPS2OpeningFeeParams {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2OpeningFeeParams object
pub extern "C" fn LSPS2OpeningFeeParams_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams }).into()}
/// Checks if two LSPS2OpeningFeeParamss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS2OpeningFeeParams_eq(a: &LSPS2OpeningFeeParams, b: &LSPS2OpeningFeeParams) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps2::msgs::LSPS2GetInfoResponse as nativeLSPS2GetInfoResponseImport;
pub(crate) type nativeLSPS2GetInfoResponse = nativeLSPS2GetInfoResponseImport;

/// A response to a [`LSPS2GetInfoRequest`]
#[must_use]
#[repr(C)]
pub struct LSPS2GetInfoResponse {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2GetInfoResponse,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2GetInfoResponse {
	type Target = nativeLSPS2GetInfoResponse;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2GetInfoResponse { }
unsafe impl core::marker::Sync for LSPS2GetInfoResponse { }
impl Drop for LSPS2GetInfoResponse {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2GetInfoResponse>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2GetInfoResponse, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoResponse_free(this_obj: LSPS2GetInfoResponse) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2GetInfoResponse_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2GetInfoResponse) };
}
#[allow(unused)]
impl LSPS2GetInfoResponse {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2GetInfoResponse {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2GetInfoResponse {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2GetInfoResponse {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// A set of opening fee parameters.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoResponse_get_opening_fee_params_menu(this_ptr: &LSPS2GetInfoResponse) -> crate::c_types::derived::CVec_LSPS2OpeningFeeParamsZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().opening_fee_params_menu;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// A set of opening fee parameters.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoResponse_set_opening_fee_params_menu(this_ptr: &mut LSPS2GetInfoResponse, mut val: crate::c_types::derived::CVec_LSPS2OpeningFeeParamsZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.opening_fee_params_menu = local_val;
}
/// Constructs a new LSPS2GetInfoResponse given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2GetInfoResponse_new(mut opening_fee_params_menu_arg: crate::c_types::derived::CVec_LSPS2OpeningFeeParamsZ) -> LSPS2GetInfoResponse {
	let mut local_opening_fee_params_menu_arg = Vec::new(); for mut item in opening_fee_params_menu_arg.into_rust().drain(..) { local_opening_fee_params_menu_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	LSPS2GetInfoResponse { inner: ObjOps::heap_alloc(nativeLSPS2GetInfoResponse {
		opening_fee_params_menu: local_opening_fee_params_menu_arg,
	}), is_owned: true }
}
impl Clone for LSPS2GetInfoResponse {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2GetInfoResponse>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2GetInfoResponse_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2GetInfoResponse)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2GetInfoResponse
pub extern "C" fn LSPS2GetInfoResponse_clone(orig: &LSPS2GetInfoResponse) -> LSPS2GetInfoResponse {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2GetInfoResponse object
pub extern "C" fn LSPS2GetInfoResponse_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoResponse }).into()}
/// Checks if two LSPS2GetInfoResponses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS2GetInfoResponse_eq(a: &LSPS2GetInfoResponse, b: &LSPS2GetInfoResponse) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps2::msgs::LSPS2BuyRequest as nativeLSPS2BuyRequestImport;
pub(crate) type nativeLSPS2BuyRequest = nativeLSPS2BuyRequestImport;

/// A request to buy a JIT channel.
#[must_use]
#[repr(C)]
pub struct LSPS2BuyRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2BuyRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2BuyRequest {
	type Target = nativeLSPS2BuyRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2BuyRequest { }
unsafe impl core::marker::Sync for LSPS2BuyRequest { }
impl Drop for LSPS2BuyRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2BuyRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2BuyRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2BuyRequest_free(this_obj: LSPS2BuyRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2BuyRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2BuyRequest) };
}
#[allow(unused)]
impl LSPS2BuyRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2BuyRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2BuyRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2BuyRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The fee parameters you would like to use.
#[no_mangle]
pub extern "C" fn LSPS2BuyRequest_get_opening_fee_params(this_ptr: &LSPS2BuyRequest) -> crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().opening_fee_params;
	crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams<>) as *mut _) }, is_owned: false }
}
/// The fee parameters you would like to use.
#[no_mangle]
pub extern "C" fn LSPS2BuyRequest_set_opening_fee_params(this_ptr: &mut LSPS2BuyRequest, mut val: crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.opening_fee_params = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The size of the initial payment you expect to receive.
#[no_mangle]
pub extern "C" fn LSPS2BuyRequest_get_payment_size_msat(this_ptr: &LSPS2BuyRequest) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_size_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The size of the initial payment you expect to receive.
#[no_mangle]
pub extern "C" fn LSPS2BuyRequest_set_payment_size_msat(this_ptr: &mut LSPS2BuyRequest, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_size_msat = local_val;
}
/// Constructs a new LSPS2BuyRequest given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2BuyRequest_new(mut opening_fee_params_arg: crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams, mut payment_size_msat_arg: crate::c_types::derived::COption_u64Z) -> LSPS2BuyRequest {
	let mut local_payment_size_msat_arg = if payment_size_msat_arg.is_some() { Some( { payment_size_msat_arg.take() }) } else { None };
	LSPS2BuyRequest { inner: ObjOps::heap_alloc(nativeLSPS2BuyRequest {
		opening_fee_params: *unsafe { Box::from_raw(opening_fee_params_arg.take_inner()) },
		payment_size_msat: local_payment_size_msat_arg,
	}), is_owned: true }
}
impl Clone for LSPS2BuyRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2BuyRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2BuyRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2BuyRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2BuyRequest
pub extern "C" fn LSPS2BuyRequest_clone(orig: &LSPS2BuyRequest) -> LSPS2BuyRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2BuyRequest object
pub extern "C" fn LSPS2BuyRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2BuyRequest }).into()}
/// Checks if two LSPS2BuyRequests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS2BuyRequest_eq(a: &LSPS2BuyRequest, b: &LSPS2BuyRequest) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps2::msgs::LSPS2InterceptScid as nativeLSPS2InterceptScidImport;
pub(crate) type nativeLSPS2InterceptScid = nativeLSPS2InterceptScidImport;

/// A newtype that holds a `short_channel_id` in human readable format of BBBxTTTx000.
#[must_use]
#[repr(C)]
pub struct LSPS2InterceptScid {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2InterceptScid,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2InterceptScid {
	type Target = nativeLSPS2InterceptScid;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2InterceptScid { }
unsafe impl core::marker::Sync for LSPS2InterceptScid { }
impl Drop for LSPS2InterceptScid {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2InterceptScid>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2InterceptScid, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2InterceptScid_free(this_obj: LSPS2InterceptScid) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2InterceptScid_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2InterceptScid) };
}
#[allow(unused)]
impl LSPS2InterceptScid {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2InterceptScid {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2InterceptScid {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2InterceptScid {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for LSPS2InterceptScid {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2InterceptScid>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2InterceptScid_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2InterceptScid)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2InterceptScid
pub extern "C" fn LSPS2InterceptScid_clone(orig: &LSPS2InterceptScid) -> LSPS2InterceptScid {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2InterceptScid object
pub extern "C" fn LSPS2InterceptScid_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2InterceptScid }).into()}
/// Checks if two LSPS2InterceptScids contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS2InterceptScid_eq(a: &LSPS2InterceptScid, b: &LSPS2InterceptScid) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Try to convert a [`LSPS2InterceptScid`] into a u64 used by LDK.
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2InterceptScid_to_scid(this_arg: &crate::lightning_liquidity::lsps2::msgs::LSPS2InterceptScid) -> crate::c_types::derived::CResult_u64NoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_scid();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}


use lightning_liquidity::lsps2::msgs::LSPS2BuyResponse as nativeLSPS2BuyResponseImport;
pub(crate) type nativeLSPS2BuyResponse = nativeLSPS2BuyResponseImport;

/// A response to a [`LSPS2BuyRequest`].
///
/// Includes information needed to construct an invoice.
#[must_use]
#[repr(C)]
pub struct LSPS2BuyResponse {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2BuyResponse,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2BuyResponse {
	type Target = nativeLSPS2BuyResponse;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2BuyResponse { }
unsafe impl core::marker::Sync for LSPS2BuyResponse { }
impl Drop for LSPS2BuyResponse {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2BuyResponse>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2BuyResponse, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_free(this_obj: LSPS2BuyResponse) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2BuyResponse_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2BuyResponse) };
}
#[allow(unused)]
impl LSPS2BuyResponse {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2BuyResponse {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2BuyResponse {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2BuyResponse {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The intercept short channel id used by LSP to identify need to open channel.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_get_jit_channel_scid(this_ptr: &LSPS2BuyResponse) -> crate::lightning_liquidity::lsps2::msgs::LSPS2InterceptScid {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().jit_channel_scid;
	crate::lightning_liquidity::lsps2::msgs::LSPS2InterceptScid { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_liquidity::lsps2::msgs::LSPS2InterceptScid<>) as *mut _) }, is_owned: false }
}
/// The intercept short channel id used by LSP to identify need to open channel.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_set_jit_channel_scid(this_ptr: &mut LSPS2BuyResponse, mut val: crate::lightning_liquidity::lsps2::msgs::LSPS2InterceptScid) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.jit_channel_scid = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The locktime expiry delta the lsp requires.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_get_lsp_cltv_expiry_delta(this_ptr: &LSPS2BuyResponse) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().lsp_cltv_expiry_delta;
	*inner_val
}
/// The locktime expiry delta the lsp requires.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_set_lsp_cltv_expiry_delta(this_ptr: &mut LSPS2BuyResponse, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.lsp_cltv_expiry_delta = val;
}
/// A flag that indicates who is trusting who.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_get_client_trusts_lsp(this_ptr: &LSPS2BuyResponse) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().client_trusts_lsp;
	*inner_val
}
/// A flag that indicates who is trusting who.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_set_client_trusts_lsp(this_ptr: &mut LSPS2BuyResponse, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.client_trusts_lsp = val;
}
/// Constructs a new LSPS2BuyResponse given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_new(mut jit_channel_scid_arg: crate::lightning_liquidity::lsps2::msgs::LSPS2InterceptScid, mut lsp_cltv_expiry_delta_arg: u32, mut client_trusts_lsp_arg: bool) -> LSPS2BuyResponse {
	LSPS2BuyResponse { inner: ObjOps::heap_alloc(nativeLSPS2BuyResponse {
		jit_channel_scid: *unsafe { Box::from_raw(jit_channel_scid_arg.take_inner()) },
		lsp_cltv_expiry_delta: lsp_cltv_expiry_delta_arg,
		client_trusts_lsp: client_trusts_lsp_arg,
	}), is_owned: true }
}
impl Clone for LSPS2BuyResponse {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2BuyResponse>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2BuyResponse_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2BuyResponse)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2BuyResponse
pub extern "C" fn LSPS2BuyResponse_clone(orig: &LSPS2BuyResponse) -> LSPS2BuyResponse {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2BuyResponse object
pub extern "C" fn LSPS2BuyResponse_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2BuyResponse }).into()}
/// Checks if two LSPS2BuyResponses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS2BuyResponse_eq(a: &LSPS2BuyResponse, b: &LSPS2BuyResponse) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// An enum that captures all the valid JSON-RPC requests in the bLIP-52 / LSPS2 protocol.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS2Request {
	/// A request to learn an LSP's channel fees and parameters.
	GetInfo(
		crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoRequest),
	/// A request to buy a JIT channel from an LSP.
	Buy(
		crate::lightning_liquidity::lsps2::msgs::LSPS2BuyRequest),
}
use lightning_liquidity::lsps2::msgs::LSPS2Request as LSPS2RequestImport;
pub(crate) type nativeLSPS2Request = LSPS2RequestImport;

impl LSPS2Request {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS2Request {
		match self {
			LSPS2Request::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS2Request::GetInfo (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS2Request::Buy (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS2Request::Buy (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS2Request {
		match self {
			LSPS2Request::GetInfo (mut a, ) => {
				nativeLSPS2Request::GetInfo (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS2Request::Buy (mut a, ) => {
				nativeLSPS2Request::Buy (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS2RequestImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS2Request) };
		match native {
			nativeLSPS2Request::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS2Request::GetInfo (
					crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS2Request::Buy (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS2Request::Buy (
					crate::lightning_liquidity::lsps2::msgs::LSPS2BuyRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS2Request) -> Self {
		match native {
			nativeLSPS2Request::GetInfo (mut a, ) => {
				LSPS2Request::GetInfo (
					crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS2Request::Buy (mut a, ) => {
				LSPS2Request::Buy (
					crate::lightning_liquidity::lsps2::msgs::LSPS2BuyRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS2Request
#[no_mangle]
pub extern "C" fn LSPS2Request_free(this_ptr: LSPS2Request) { }
/// Creates a copy of the LSPS2Request
#[no_mangle]
pub extern "C" fn LSPS2Request_clone(orig: &LSPS2Request) -> LSPS2Request {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2Request_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS2Request)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2Request_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS2Request) };
}
#[no_mangle]
/// Utility method to constructs a new GetInfo-variant LSPS2Request
pub extern "C" fn LSPS2Request_get_info(a: crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoRequest) -> LSPS2Request {
	LSPS2Request::GetInfo(a, )
}
#[no_mangle]
/// Utility method to constructs a new Buy-variant LSPS2Request
pub extern "C" fn LSPS2Request_buy(a: crate::lightning_liquidity::lsps2::msgs::LSPS2BuyRequest) -> LSPS2Request {
	LSPS2Request::Buy(a, )
}
/// Get a string which allows debug introspection of a LSPS2Request object
pub extern "C" fn LSPS2Request_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2Request }).into()}
/// Checks if two LSPS2Requests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS2Request_eq(a: &LSPS2Request, b: &LSPS2Request) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An enum that captures all the valid JSON-RPC responses in the bLIP-52 / LSPS2 protocol.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS2Response {
	/// A successful response to a [`LSPS2Request::GetInfo`] request.
	GetInfo(
		crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoResponse),
	/// An error response to a [`LSPS2Request::GetInfo`] request.
	GetInfoError(
		crate::lightning_liquidity::lsps0::ser::LSPSResponseError),
	/// A successful response to a [`LSPS2Request::Buy`] request.
	Buy(
		crate::lightning_liquidity::lsps2::msgs::LSPS2BuyResponse),
	/// An error response to a [`LSPS2Request::Buy`] request.
	BuyError(
		crate::lightning_liquidity::lsps0::ser::LSPSResponseError),
}
use lightning_liquidity::lsps2::msgs::LSPS2Response as LSPS2ResponseImport;
pub(crate) type nativeLSPS2Response = LSPS2ResponseImport;

impl LSPS2Response {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS2Response {
		match self {
			LSPS2Response::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS2Response::GetInfo (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS2Response::GetInfoError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS2Response::GetInfoError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS2Response::Buy (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS2Response::Buy (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS2Response::BuyError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS2Response::BuyError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS2Response {
		match self {
			LSPS2Response::GetInfo (mut a, ) => {
				nativeLSPS2Response::GetInfo (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS2Response::GetInfoError (mut a, ) => {
				nativeLSPS2Response::GetInfoError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS2Response::Buy (mut a, ) => {
				nativeLSPS2Response::Buy (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS2Response::BuyError (mut a, ) => {
				nativeLSPS2Response::BuyError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS2ResponseImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS2Response) };
		match native {
			nativeLSPS2Response::GetInfo (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS2Response::GetInfo (
					crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoResponse { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS2Response::GetInfoError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS2Response::GetInfoError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS2Response::Buy (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS2Response::Buy (
					crate::lightning_liquidity::lsps2::msgs::LSPS2BuyResponse { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS2Response::BuyError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS2Response::BuyError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS2Response) -> Self {
		match native {
			nativeLSPS2Response::GetInfo (mut a, ) => {
				LSPS2Response::GetInfo (
					crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoResponse { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS2Response::GetInfoError (mut a, ) => {
				LSPS2Response::GetInfoError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS2Response::Buy (mut a, ) => {
				LSPS2Response::Buy (
					crate::lightning_liquidity::lsps2::msgs::LSPS2BuyResponse { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS2Response::BuyError (mut a, ) => {
				LSPS2Response::BuyError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS2Response
#[no_mangle]
pub extern "C" fn LSPS2Response_free(this_ptr: LSPS2Response) { }
/// Creates a copy of the LSPS2Response
#[no_mangle]
pub extern "C" fn LSPS2Response_clone(orig: &LSPS2Response) -> LSPS2Response {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2Response_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS2Response)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2Response_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS2Response) };
}
#[no_mangle]
/// Utility method to constructs a new GetInfo-variant LSPS2Response
pub extern "C" fn LSPS2Response_get_info(a: crate::lightning_liquidity::lsps2::msgs::LSPS2GetInfoResponse) -> LSPS2Response {
	LSPS2Response::GetInfo(a, )
}
#[no_mangle]
/// Utility method to constructs a new GetInfoError-variant LSPS2Response
pub extern "C" fn LSPS2Response_get_info_error(a: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS2Response {
	LSPS2Response::GetInfoError(a, )
}
#[no_mangle]
/// Utility method to constructs a new Buy-variant LSPS2Response
pub extern "C" fn LSPS2Response_buy(a: crate::lightning_liquidity::lsps2::msgs::LSPS2BuyResponse) -> LSPS2Response {
	LSPS2Response::Buy(a, )
}
#[no_mangle]
/// Utility method to constructs a new BuyError-variant LSPS2Response
pub extern "C" fn LSPS2Response_buy_error(a: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS2Response {
	LSPS2Response::BuyError(a, )
}
/// Get a string which allows debug introspection of a LSPS2Response object
pub extern "C" fn LSPS2Response_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2Response }).into()}
/// Checks if two LSPS2Responses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS2Response_eq(a: &LSPS2Response, b: &LSPS2Response) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An enum that captures all valid JSON-RPC messages in the bLIP-52 / LSPS2 protocol.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS2Message {
	/// An LSPS2 JSON-RPC request.
	Request(
		crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		crate::lightning_liquidity::lsps2::msgs::LSPS2Request),
	/// An LSPS2 JSON-RPC response.
	Response(
		crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		crate::lightning_liquidity::lsps2::msgs::LSPS2Response),
}
use lightning_liquidity::lsps2::msgs::LSPS2Message as LSPS2MessageImport;
pub(crate) type nativeLSPS2Message = LSPS2MessageImport;

impl LSPS2Message {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS2Message {
		match self {
			LSPS2Message::Request (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativeLSPS2Message::Request (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
					b_nonref.into_native(),
				)
			},
			LSPS2Message::Response (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativeLSPS2Message::Response (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
					b_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS2Message {
		match self {
			LSPS2Message::Request (mut a, mut b, ) => {
				nativeLSPS2Message::Request (
					*unsafe { Box::from_raw(a.take_inner()) },
					b.into_native(),
				)
			},
			LSPS2Message::Response (mut a, mut b, ) => {
				nativeLSPS2Message::Response (
					*unsafe { Box::from_raw(a.take_inner()) },
					b.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS2MessageImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS2Message) };
		match native {
			nativeLSPS2Message::Request (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				LSPS2Message::Request (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
					crate::lightning_liquidity::lsps2::msgs::LSPS2Request::native_into(b_nonref),
				)
			},
			nativeLSPS2Message::Response (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				LSPS2Message::Response (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
					crate::lightning_liquidity::lsps2::msgs::LSPS2Response::native_into(b_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS2Message) -> Self {
		match native {
			nativeLSPS2Message::Request (mut a, mut b, ) => {
				LSPS2Message::Request (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a), is_owned: true },
					crate::lightning_liquidity::lsps2::msgs::LSPS2Request::native_into(b),
				)
			},
			nativeLSPS2Message::Response (mut a, mut b, ) => {
				LSPS2Message::Response (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a), is_owned: true },
					crate::lightning_liquidity::lsps2::msgs::LSPS2Response::native_into(b),
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS2Message
#[no_mangle]
pub extern "C" fn LSPS2Message_free(this_ptr: LSPS2Message) { }
/// Creates a copy of the LSPS2Message
#[no_mangle]
pub extern "C" fn LSPS2Message_clone(orig: &LSPS2Message) -> LSPS2Message {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2Message_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS2Message)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2Message_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS2Message) };
}
#[no_mangle]
/// Utility method to constructs a new Request-variant LSPS2Message
pub extern "C" fn LSPS2Message_request(a: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,b: crate::lightning_liquidity::lsps2::msgs::LSPS2Request) -> LSPS2Message {
	LSPS2Message::Request(a, b, )
}
#[no_mangle]
/// Utility method to constructs a new Response-variant LSPS2Message
pub extern "C" fn LSPS2Message_response(a: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,b: crate::lightning_liquidity::lsps2::msgs::LSPS2Response) -> LSPS2Message {
	LSPS2Message::Response(a, b, )
}
/// Get a string which allows debug introspection of a LSPS2Message object
pub extern "C" fn LSPS2Message_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::msgs::LSPS2Message }).into()}
/// Checks if two LSPS2Messages contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS2Message_eq(a: &LSPS2Message, b: &LSPS2Message) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
