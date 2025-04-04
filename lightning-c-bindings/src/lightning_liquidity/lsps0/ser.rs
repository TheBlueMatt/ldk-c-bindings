// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains basic data types that allow for the (de-)seralization of LSPS messages in the JSON-RPC 2.0 format.
//!
//! Please refer to the [bLIP-50 / LSPS0
//! specification](https://github.com/lightning/blips/blob/master/blip-0050.md) for more
//! information.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// The Lightning message type id for LSPS messages.

#[no_mangle]
pub static LSPS_MESSAGE_TYPE_ID: u16 = lightning_liquidity::lsps0::ser::LSPS_MESSAGE_TYPE_ID;

use lightning_liquidity::lsps0::ser::RawLSPSMessage as nativeRawLSPSMessageImport;
pub(crate) type nativeRawLSPSMessage = nativeRawLSPSMessageImport;

/// Lightning message type used by LSPS protocols.
#[must_use]
#[repr(C)]
pub struct RawLSPSMessage {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRawLSPSMessage,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for RawLSPSMessage {
	type Target = nativeRawLSPSMessage;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for RawLSPSMessage { }
unsafe impl core::marker::Sync for RawLSPSMessage { }
impl Drop for RawLSPSMessage {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRawLSPSMessage>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RawLSPSMessage, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RawLSPSMessage_free(this_obj: RawLSPSMessage) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RawLSPSMessage_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRawLSPSMessage) };
}
#[allow(unused)]
impl RawLSPSMessage {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRawLSPSMessage {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRawLSPSMessage {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRawLSPSMessage {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The raw string payload that holds the actual message.
#[no_mangle]
pub extern "C" fn RawLSPSMessage_get_payload(this_ptr: &RawLSPSMessage) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payload;
	inner_val.as_str().into()
}
/// The raw string payload that holds the actual message.
#[no_mangle]
pub extern "C" fn RawLSPSMessage_set_payload(this_ptr: &mut RawLSPSMessage, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payload = val.into_string();
}
/// Constructs a new RawLSPSMessage given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RawLSPSMessage_new(mut payload_arg: crate::c_types::Str) -> RawLSPSMessage {
	RawLSPSMessage { inner: ObjOps::heap_alloc(nativeRawLSPSMessage {
		payload: payload_arg.into_string(),
	}), is_owned: true }
}
impl Clone for RawLSPSMessage {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRawLSPSMessage>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RawLSPSMessage_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRawLSPSMessage)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RawLSPSMessage
pub extern "C" fn RawLSPSMessage_clone(orig: &RawLSPSMessage) -> RawLSPSMessage {
	orig.clone()
}
/// Get a string which allows debug introspection of a RawLSPSMessage object
pub extern "C" fn RawLSPSMessage_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::ser::RawLSPSMessage }).into()}
/// Checks if two RawLSPSMessages contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RawLSPSMessage_eq(a: &RawLSPSMessage, b: &RawLSPSMessage) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the RawLSPSMessage object into a byte array which can be read by RawLSPSMessage_read
pub extern "C" fn RawLSPSMessage_write(obj: &crate::lightning_liquidity::lsps0::ser::RawLSPSMessage) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn RawLSPSMessage_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_liquidity::lsps0::ser::nativeRawLSPSMessage) })
}
#[no_mangle]
/// Read a RawLSPSMessage from a byte array, created by RawLSPSMessage_write
pub extern "C" fn RawLSPSMessage_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RawLSPSMessageDecodeErrorZ {
	let res: Result<lightning_liquidity::lsps0::ser::RawLSPSMessage, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_liquidity::lsps0::ser::RawLSPSMessage { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
impl From<nativeRawLSPSMessage> for crate::lightning::ln::wire::Type {
	fn from(obj: nativeRawLSPSMessage) -> Self {
		let rust_obj = crate::lightning_liquidity::lsps0::ser::RawLSPSMessage { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = RawLSPSMessage_as_Type(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(RawLSPSMessage_free_void);
		ret
	}
}
/// Constructs a new Type which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Type must be freed before this_arg is
#[no_mangle]
pub extern "C" fn RawLSPSMessage_as_Type(this_arg: &RawLSPSMessage) -> crate::lightning::ln::wire::Type {
	crate::lightning::ln::wire::Type {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		type_id: RawLSPSMessage_Type_type_id,
		debug_str: RawLSPSMessage_debug_str_void,
		write: RawLSPSMessage_write_void,
		cloned: Some(Type_RawLSPSMessage_cloned),
	}
}

#[must_use]
extern "C" fn RawLSPSMessage_Type_type_id(this_arg: *const c_void) -> u16 {
	let mut ret = <nativeRawLSPSMessage as lightning::ln::wire::Type>::type_id(unsafe { &mut *(this_arg as *mut nativeRawLSPSMessage) }, );
	ret
}
extern "C" fn Type_RawLSPSMessage_cloned(new_obj: &mut crate::lightning::ln::wire::Type) {
	new_obj.this_arg = RawLSPSMessage_clone_void(new_obj.this_arg);
	new_obj.free = Some(RawLSPSMessage_free_void);
}


use lightning_liquidity::lsps0::ser::LSPSRequestId as nativeLSPSRequestIdImport;
pub(crate) type nativeLSPSRequestId = nativeLSPSRequestIdImport;

/// A JSON-RPC request's `id`.
///
/// Please refer to the [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification#request_object) for
/// more information.
#[must_use]
#[repr(C)]
pub struct LSPSRequestId {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPSRequestId,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPSRequestId {
	type Target = nativeLSPSRequestId;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPSRequestId { }
unsafe impl core::marker::Sync for LSPSRequestId { }
impl Drop for LSPSRequestId {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPSRequestId>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPSRequestId, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPSRequestId_free(this_obj: LSPSRequestId) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSRequestId_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPSRequestId) };
}
#[allow(unused)]
impl LSPSRequestId {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPSRequestId {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPSRequestId {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPSRequestId {
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
pub extern "C" fn LSPSRequestId_get_a(this_ptr: &LSPSRequestId) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val.as_str().into()
}
#[no_mangle]
pub extern "C" fn LSPSRequestId_set_a(this_ptr: &mut LSPSRequestId, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_string();
}
/// Constructs a new LSPSRequestId given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPSRequestId_new(mut a_arg: crate::c_types::Str) -> LSPSRequestId {
	LSPSRequestId { inner: ObjOps::heap_alloc(lightning_liquidity::lsps0::ser::LSPSRequestId (
		a_arg.into_string(),
	)), is_owned: true }
}
impl Clone for LSPSRequestId {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPSRequestId>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSRequestId_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPSRequestId)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPSRequestId
pub extern "C" fn LSPSRequestId_clone(orig: &LSPSRequestId) -> LSPSRequestId {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPSRequestId object
pub extern "C" fn LSPSRequestId_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::ser::LSPSRequestId }).into()}
/// Checks if two LSPSRequestIds contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPSRequestId_eq(a: &LSPSRequestId, b: &LSPSRequestId) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Generates a non-cryptographic 64-bit hash of the LSPSRequestId.
#[no_mangle]
pub extern "C" fn LSPSRequestId_hash(o: &LSPSRequestId) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning_liquidity::lsps0::ser::LSPSDateTime as nativeLSPSDateTimeImport;
pub(crate) type nativeLSPSDateTime = nativeLSPSDateTimeImport;

/// An object representing datetimes as described in bLIP-50 / LSPS0.
#[must_use]
#[repr(C)]
pub struct LSPSDateTime {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPSDateTime,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPSDateTime {
	type Target = nativeLSPSDateTime;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPSDateTime { }
unsafe impl core::marker::Sync for LSPSDateTime { }
impl Drop for LSPSDateTime {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPSDateTime>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPSDateTime, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPSDateTime_free(this_obj: LSPSDateTime) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSDateTime_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPSDateTime) };
}
#[allow(unused)]
impl LSPSDateTime {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPSDateTime {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPSDateTime {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPSDateTime {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for LSPSDateTime {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPSDateTime>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSDateTime_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPSDateTime)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPSDateTime
pub extern "C" fn LSPSDateTime_clone(orig: &LSPSDateTime) -> LSPSDateTime {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPSDateTime object
pub extern "C" fn LSPSDateTime_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::ser::LSPSDateTime }).into()}
/// Checks if two LSPSDateTimes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPSDateTime_eq(a: &LSPSDateTime, b: &LSPSDateTime) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Generates a non-cryptographic 64-bit hash of the LSPSDateTime.
#[no_mangle]
pub extern "C" fn LSPSDateTime_hash(o: &LSPSDateTime) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Returns the LSPSDateTime as RFC3339 formatted string.
#[must_use]
#[no_mangle]
pub extern "C" fn LSPSDateTime_to_rfc3339(this_arg: &crate::lightning_liquidity::lsps0::ser::LSPSDateTime) -> crate::c_types::Str {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_rfc3339();
	ret.into()
}

/// Returns if the given time is in the past.
#[must_use]
#[no_mangle]
pub extern "C" fn LSPSDateTime_is_past(this_arg: &crate::lightning_liquidity::lsps0::ser::LSPSDateTime) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_past();
	ret
}

#[no_mangle]
/// Read a LSPSDateTime object from a string
pub extern "C" fn LSPSDateTime_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_LSPSDateTimeNoneZ {
	match lightning_liquidity::lsps0::ser::LSPSDateTime::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning_liquidity::lsps0::ser::LSPSDateTime { inner: ObjOps::heap_alloc(r), is_owned: true }
			)
		},
		Err(e) => {
			crate::c_types::CResultTempl::err(
				() /*e*/
			)
		},
	}.into()
}
#[no_mangle]
/// Get the string representation of a LSPSDateTime object
pub extern "C" fn LSPSDateTime_to_str(o: &crate::lightning_liquidity::lsps0::ser::LSPSDateTime) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}

use lightning_liquidity::lsps0::ser::LSPSResponseError as nativeLSPSResponseErrorImport;
pub(crate) type nativeLSPSResponseError = nativeLSPSResponseErrorImport;

/// An error returned in response to an JSON-RPC request.
///
/// Please refer to the [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification#error_object) for
/// more information.
#[must_use]
#[repr(C)]
pub struct LSPSResponseError {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPSResponseError,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPSResponseError {
	type Target = nativeLSPSResponseError;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPSResponseError { }
unsafe impl core::marker::Sync for LSPSResponseError { }
impl Drop for LSPSResponseError {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPSResponseError>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPSResponseError, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPSResponseError_free(this_obj: LSPSResponseError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSResponseError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPSResponseError) };
}
#[allow(unused)]
impl LSPSResponseError {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPSResponseError {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPSResponseError {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPSResponseError {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// A string providing a short description of the error.
#[no_mangle]
pub extern "C" fn LSPSResponseError_get_message(this_ptr: &LSPSResponseError) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().message;
	inner_val.as_str().into()
}
/// A string providing a short description of the error.
#[no_mangle]
pub extern "C" fn LSPSResponseError_set_message(this_ptr: &mut LSPSResponseError, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.message = val.into_string();
}
/// A primitive or structured value that contains additional information about the error.
#[no_mangle]
pub extern "C" fn LSPSResponseError_get_data(this_ptr: &LSPSResponseError) -> crate::c_types::derived::COption_StrZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().data;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_StrZ::None } else { crate::c_types::derived::COption_StrZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { (*inner_val.as_ref().unwrap()).clone().into() }) };
	local_inner_val
}
/// A primitive or structured value that contains additional information about the error.
#[no_mangle]
pub extern "C" fn LSPSResponseError_set_data(this_ptr: &mut LSPSResponseError, mut val: crate::c_types::derived::COption_StrZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_string() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.data = local_val;
}
impl Clone for LSPSResponseError {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPSResponseError>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSResponseError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPSResponseError)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPSResponseError
pub extern "C" fn LSPSResponseError_clone(orig: &LSPSResponseError) -> LSPSResponseError {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPSResponseError object
pub extern "C" fn LSPSResponseError_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::ser::LSPSResponseError }).into()}
/// Checks if two LSPSResponseErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPSResponseError_eq(a: &LSPSResponseError, b: &LSPSResponseError) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// A (de-)serializable LSPS message allowing to be sent over the wire.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPSMessage {
	/// An invalid variant.
	Invalid(
		crate::lightning_liquidity::lsps0::ser::LSPSResponseError),
	/// An LSPS0 message.
	LSPS0(
		crate::lightning_liquidity::lsps0::msgs::LSPS0Message),
	/// An LSPS1 message.
	LSPS1(
		crate::lightning_liquidity::lsps1::msgs::LSPS1Message),
	/// An LSPS2 message.
	LSPS2(
		crate::lightning_liquidity::lsps2::msgs::LSPS2Message),
}
use lightning_liquidity::lsps0::ser::LSPSMessage as LSPSMessageImport;
pub(crate) type nativeLSPSMessage = LSPSMessageImport;

impl LSPSMessage {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPSMessage {
		match self {
			LSPSMessage::Invalid (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPSMessage::Invalid (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPSMessage::LSPS0 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPSMessage::LSPS0 (
					a_nonref.into_native(),
				)
			},
			LSPSMessage::LSPS1 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPSMessage::LSPS1 (
					a_nonref.into_native(),
				)
			},
			LSPSMessage::LSPS2 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPSMessage::LSPS2 (
					a_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPSMessage {
		match self {
			LSPSMessage::Invalid (mut a, ) => {
				nativeLSPSMessage::Invalid (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPSMessage::LSPS0 (mut a, ) => {
				nativeLSPSMessage::LSPS0 (
					a.into_native(),
				)
			},
			LSPSMessage::LSPS1 (mut a, ) => {
				nativeLSPSMessage::LSPS1 (
					a.into_native(),
				)
			},
			LSPSMessage::LSPS2 (mut a, ) => {
				nativeLSPSMessage::LSPS2 (
					a.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPSMessageImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPSMessage) };
		match native {
			nativeLSPSMessage::Invalid (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPSMessage::Invalid (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPSMessage::LSPS0 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPSMessage::LSPS0 (
					crate::lightning_liquidity::lsps0::msgs::LSPS0Message::native_into(a_nonref),
				)
			},
			nativeLSPSMessage::LSPS1 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPSMessage::LSPS1 (
					crate::lightning_liquidity::lsps1::msgs::LSPS1Message::native_into(a_nonref),
				)
			},
			nativeLSPSMessage::LSPS2 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPSMessage::LSPS2 (
					crate::lightning_liquidity::lsps2::msgs::LSPS2Message::native_into(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPSMessage) -> Self {
		match native {
			nativeLSPSMessage::Invalid (mut a, ) => {
				LSPSMessage::Invalid (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPSMessage::LSPS0 (mut a, ) => {
				LSPSMessage::LSPS0 (
					crate::lightning_liquidity::lsps0::msgs::LSPS0Message::native_into(a),
				)
			},
			nativeLSPSMessage::LSPS1 (mut a, ) => {
				LSPSMessage::LSPS1 (
					crate::lightning_liquidity::lsps1::msgs::LSPS1Message::native_into(a),
				)
			},
			nativeLSPSMessage::LSPS2 (mut a, ) => {
				LSPSMessage::LSPS2 (
					crate::lightning_liquidity::lsps2::msgs::LSPS2Message::native_into(a),
				)
			},
		}
	}
}
/// Frees any resources used by the LSPSMessage
#[no_mangle]
pub extern "C" fn LSPSMessage_free(this_ptr: LSPSMessage) { }
/// Creates a copy of the LSPSMessage
#[no_mangle]
pub extern "C" fn LSPSMessage_clone(orig: &LSPSMessage) -> LSPSMessage {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSMessage_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPSMessage)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPSMessage_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPSMessage) };
}
#[no_mangle]
/// Utility method to constructs a new Invalid-variant LSPSMessage
pub extern "C" fn LSPSMessage_invalid(a: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPSMessage {
	LSPSMessage::Invalid(a, )
}
#[no_mangle]
/// Utility method to constructs a new LSPS0-variant LSPSMessage
pub extern "C" fn LSPSMessage_lsps0(a: crate::lightning_liquidity::lsps0::msgs::LSPS0Message) -> LSPSMessage {
	LSPSMessage::LSPS0(a, )
}
#[no_mangle]
/// Utility method to constructs a new LSPS1-variant LSPSMessage
pub extern "C" fn LSPSMessage_lsps1(a: crate::lightning_liquidity::lsps1::msgs::LSPS1Message) -> LSPSMessage {
	LSPSMessage::LSPS1(a, )
}
#[no_mangle]
/// Utility method to constructs a new LSPS2-variant LSPSMessage
pub extern "C" fn LSPSMessage_lsps2(a: crate::lightning_liquidity::lsps2::msgs::LSPS2Message) -> LSPSMessage {
	LSPSMessage::LSPS2(a, )
}
/// Get a string which allows debug introspection of a LSPSMessage object
pub extern "C" fn LSPSMessage_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::ser::LSPSMessage }).into()}
/// Checks if two LSPSMessages contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPSMessage_eq(a: &LSPSMessage, b: &LSPSMessage) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
mod string_amount {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod string_amount_option {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod unchecked_address {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod unchecked_address_option {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod u32_fee_rate {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
