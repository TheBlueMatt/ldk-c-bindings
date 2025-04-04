// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Message, request, and other primitive types used to implement LSPS0.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsRequest as nativeLSPS0ListProtocolsRequestImport;
pub(crate) type nativeLSPS0ListProtocolsRequest = nativeLSPS0ListProtocolsRequestImport;

/// A `list_protocols` request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[must_use]
#[repr(C)]
pub struct LSPS0ListProtocolsRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS0ListProtocolsRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS0ListProtocolsRequest {
	type Target = nativeLSPS0ListProtocolsRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS0ListProtocolsRequest { }
unsafe impl core::marker::Sync for LSPS0ListProtocolsRequest { }
impl Drop for LSPS0ListProtocolsRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS0ListProtocolsRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS0ListProtocolsRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsRequest_free(this_obj: LSPS0ListProtocolsRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ListProtocolsRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS0ListProtocolsRequest) };
}
#[allow(unused)]
impl LSPS0ListProtocolsRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS0ListProtocolsRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS0ListProtocolsRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS0ListProtocolsRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new LSPS0ListProtocolsRequest given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsRequest_new() -> LSPS0ListProtocolsRequest {
	LSPS0ListProtocolsRequest { inner: ObjOps::heap_alloc(nativeLSPS0ListProtocolsRequest {
	}), is_owned: true }
}
impl Clone for LSPS0ListProtocolsRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS0ListProtocolsRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ListProtocolsRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS0ListProtocolsRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS0ListProtocolsRequest
pub extern "C" fn LSPS0ListProtocolsRequest_clone(orig: &LSPS0ListProtocolsRequest) -> LSPS0ListProtocolsRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS0ListProtocolsRequest object
pub extern "C" fn LSPS0ListProtocolsRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsRequest }).into()}
/// Checks if two LSPS0ListProtocolsRequests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsRequest_eq(a: &LSPS0ListProtocolsRequest, b: &LSPS0ListProtocolsRequest) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsResponse as nativeLSPS0ListProtocolsResponseImport;
pub(crate) type nativeLSPS0ListProtocolsResponse = nativeLSPS0ListProtocolsResponseImport;

/// A response to a `list_protocols` request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[must_use]
#[repr(C)]
pub struct LSPS0ListProtocolsResponse {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS0ListProtocolsResponse,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS0ListProtocolsResponse {
	type Target = nativeLSPS0ListProtocolsResponse;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS0ListProtocolsResponse { }
unsafe impl core::marker::Sync for LSPS0ListProtocolsResponse { }
impl Drop for LSPS0ListProtocolsResponse {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS0ListProtocolsResponse>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS0ListProtocolsResponse, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsResponse_free(this_obj: LSPS0ListProtocolsResponse) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ListProtocolsResponse_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS0ListProtocolsResponse) };
}
#[allow(unused)]
impl LSPS0ListProtocolsResponse {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS0ListProtocolsResponse {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS0ListProtocolsResponse {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS0ListProtocolsResponse {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// A list of supported protocols.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsResponse_get_protocols(this_ptr: &LSPS0ListProtocolsResponse) -> crate::c_types::derived::CVec_u16Z {
	let mut inner_val = this_ptr.get_native_mut_ref().protocols.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// A list of supported protocols.
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsResponse_set_protocols(this_ptr: &mut LSPS0ListProtocolsResponse, mut val: crate::c_types::derived::CVec_u16Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.protocols = local_val;
}
/// Constructs a new LSPS0ListProtocolsResponse given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsResponse_new(mut protocols_arg: crate::c_types::derived::CVec_u16Z) -> LSPS0ListProtocolsResponse {
	let mut local_protocols_arg = Vec::new(); for mut item in protocols_arg.into_rust().drain(..) { local_protocols_arg.push( { item }); };
	LSPS0ListProtocolsResponse { inner: ObjOps::heap_alloc(nativeLSPS0ListProtocolsResponse {
		protocols: local_protocols_arg,
	}), is_owned: true }
}
impl Clone for LSPS0ListProtocolsResponse {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS0ListProtocolsResponse>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ListProtocolsResponse_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS0ListProtocolsResponse)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS0ListProtocolsResponse
pub extern "C" fn LSPS0ListProtocolsResponse_clone(orig: &LSPS0ListProtocolsResponse) -> LSPS0ListProtocolsResponse {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS0ListProtocolsResponse object
pub extern "C" fn LSPS0ListProtocolsResponse_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsResponse }).into()}
/// Checks if two LSPS0ListProtocolsResponses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn LSPS0ListProtocolsResponse_eq(a: &LSPS0ListProtocolsResponse, b: &LSPS0ListProtocolsResponse) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// An bLIP-50 / LSPS0 protocol request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS0Request {
	/// A request calling `list_protocols`.
	ListProtocols(
		crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsRequest),
}
use lightning_liquidity::lsps0::msgs::LSPS0Request as LSPS0RequestImport;
pub(crate) type nativeLSPS0Request = LSPS0RequestImport;

impl LSPS0Request {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS0Request {
		match self {
			LSPS0Request::ListProtocols (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS0Request::ListProtocols (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS0Request {
		match self {
			LSPS0Request::ListProtocols (mut a, ) => {
				nativeLSPS0Request::ListProtocols (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS0RequestImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS0Request) };
		match native {
			nativeLSPS0Request::ListProtocols (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS0Request::ListProtocols (
					crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS0Request) -> Self {
		match native {
			nativeLSPS0Request::ListProtocols (mut a, ) => {
				LSPS0Request::ListProtocols (
					crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS0Request
#[no_mangle]
pub extern "C" fn LSPS0Request_free(this_ptr: LSPS0Request) { }
/// Creates a copy of the LSPS0Request
#[no_mangle]
pub extern "C" fn LSPS0Request_clone(orig: &LSPS0Request) -> LSPS0Request {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0Request_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS0Request)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0Request_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS0Request) };
}
#[no_mangle]
/// Utility method to constructs a new ListProtocols-variant LSPS0Request
pub extern "C" fn LSPS0Request_list_protocols(a: crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsRequest) -> LSPS0Request {
	LSPS0Request::ListProtocols(a, )
}
/// Get a string which allows debug introspection of a LSPS0Request object
pub extern "C" fn LSPS0Request_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::msgs::LSPS0Request }).into()}
/// Checks if two LSPS0Requests contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS0Request_eq(a: &LSPS0Request, b: &LSPS0Request) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Returns the method name associated with the given request variant.
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS0Request_method(this_arg: &crate::lightning_liquidity::lsps0::msgs::LSPS0Request) -> crate::c_types::Str {
	let mut ret = this_arg.to_native().method();
	ret.into()
}

/// An bLIP-50 / LSPS0 protocol request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS0Response {
	/// A response to a `list_protocols` request.
	ListProtocols(
		crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsResponse),
	/// An error response to a `list_protocols` request.
	ListProtocolsError(
		crate::lightning_liquidity::lsps0::ser::LSPSResponseError),
}
use lightning_liquidity::lsps0::msgs::LSPS0Response as LSPS0ResponseImport;
pub(crate) type nativeLSPS0Response = LSPS0ResponseImport;

impl LSPS0Response {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS0Response {
		match self {
			LSPS0Response::ListProtocols (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS0Response::ListProtocols (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			LSPS0Response::ListProtocolsError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLSPS0Response::ListProtocolsError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS0Response {
		match self {
			LSPS0Response::ListProtocols (mut a, ) => {
				nativeLSPS0Response::ListProtocols (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			LSPS0Response::ListProtocolsError (mut a, ) => {
				nativeLSPS0Response::ListProtocolsError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS0ResponseImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS0Response) };
		match native {
			nativeLSPS0Response::ListProtocols (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS0Response::ListProtocols (
					crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsResponse { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeLSPS0Response::ListProtocolsError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LSPS0Response::ListProtocolsError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS0Response) -> Self {
		match native {
			nativeLSPS0Response::ListProtocols (mut a, ) => {
				LSPS0Response::ListProtocols (
					crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsResponse { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeLSPS0Response::ListProtocolsError (mut a, ) => {
				LSPS0Response::ListProtocolsError (
					crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS0Response
#[no_mangle]
pub extern "C" fn LSPS0Response_free(this_ptr: LSPS0Response) { }
/// Creates a copy of the LSPS0Response
#[no_mangle]
pub extern "C" fn LSPS0Response_clone(orig: &LSPS0Response) -> LSPS0Response {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0Response_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS0Response)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0Response_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS0Response) };
}
#[no_mangle]
/// Utility method to constructs a new ListProtocols-variant LSPS0Response
pub extern "C" fn LSPS0Response_list_protocols(a: crate::lightning_liquidity::lsps0::msgs::LSPS0ListProtocolsResponse) -> LSPS0Response {
	LSPS0Response::ListProtocols(a, )
}
#[no_mangle]
/// Utility method to constructs a new ListProtocolsError-variant LSPS0Response
pub extern "C" fn LSPS0Response_list_protocols_error(a: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS0Response {
	LSPS0Response::ListProtocolsError(a, )
}
/// Get a string which allows debug introspection of a LSPS0Response object
pub extern "C" fn LSPS0Response_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::msgs::LSPS0Response }).into()}
/// Checks if two LSPS0Responses contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS0Response_eq(a: &LSPS0Response, b: &LSPS0Response) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An bLIP-50 / LSPS0 protocol message.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS0Message {
	/// A request variant.
	Request(
		crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		crate::lightning_liquidity::lsps0::msgs::LSPS0Request),
	/// A response variant.
	Response(
		crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		crate::lightning_liquidity::lsps0::msgs::LSPS0Response),
}
use lightning_liquidity::lsps0::msgs::LSPS0Message as LSPS0MessageImport;
pub(crate) type nativeLSPS0Message = LSPS0MessageImport;

impl LSPS0Message {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS0Message {
		match self {
			LSPS0Message::Request (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativeLSPS0Message::Request (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
					b_nonref.into_native(),
				)
			},
			LSPS0Message::Response (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativeLSPS0Message::Response (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
					b_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS0Message {
		match self {
			LSPS0Message::Request (mut a, mut b, ) => {
				nativeLSPS0Message::Request (
					*unsafe { Box::from_raw(a.take_inner()) },
					b.into_native(),
				)
			},
			LSPS0Message::Response (mut a, mut b, ) => {
				nativeLSPS0Message::Response (
					*unsafe { Box::from_raw(a.take_inner()) },
					b.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS0MessageImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS0Message) };
		match native {
			nativeLSPS0Message::Request (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				LSPS0Message::Request (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
					crate::lightning_liquidity::lsps0::msgs::LSPS0Request::native_into(b_nonref),
				)
			},
			nativeLSPS0Message::Response (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				LSPS0Message::Response (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
					crate::lightning_liquidity::lsps0::msgs::LSPS0Response::native_into(b_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS0Message) -> Self {
		match native {
			nativeLSPS0Message::Request (mut a, mut b, ) => {
				LSPS0Message::Request (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a), is_owned: true },
					crate::lightning_liquidity::lsps0::msgs::LSPS0Request::native_into(b),
				)
			},
			nativeLSPS0Message::Response (mut a, mut b, ) => {
				LSPS0Message::Response (
					crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(a), is_owned: true },
					crate::lightning_liquidity::lsps0::msgs::LSPS0Response::native_into(b),
				)
			},
		}
	}
}
/// Frees any resources used by the LSPS0Message
#[no_mangle]
pub extern "C" fn LSPS0Message_free(this_ptr: LSPS0Message) { }
/// Creates a copy of the LSPS0Message
#[no_mangle]
pub extern "C" fn LSPS0Message_clone(orig: &LSPS0Message) -> LSPS0Message {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0Message_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS0Message)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0Message_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS0Message) };
}
#[no_mangle]
/// Utility method to constructs a new Request-variant LSPS0Message
pub extern "C" fn LSPS0Message_request(a: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,b: crate::lightning_liquidity::lsps0::msgs::LSPS0Request) -> LSPS0Message {
	LSPS0Message::Request(a, b, )
}
#[no_mangle]
/// Utility method to constructs a new Response-variant LSPS0Message
pub extern "C" fn LSPS0Message_response(a: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,b: crate::lightning_liquidity::lsps0::msgs::LSPS0Response) -> LSPS0Message {
	LSPS0Message::Response(a, b, )
}
/// Get a string which allows debug introspection of a LSPS0Message object
pub extern "C" fn LSPS0Message_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::msgs::LSPS0Message }).into()}
/// Checks if two LSPS0Messages contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS0Message_eq(a: &LSPS0Message, b: &LSPS0Message) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
