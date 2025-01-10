// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Message handling for async payments.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// A handler for an [`OnionMessage`] containing an async payments message as its payload.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[repr(C)]
pub struct AsyncPaymentsMessageHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Handle a [`HeldHtlcAvailable`] message. A [`ReleaseHeldHtlc`] should be returned to release
	/// the held funds.
	///
	/// Note that responder (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub handle_held_htlc_available: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::async_payments::HeldHtlcAvailable, responder: crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::COption_C2Tuple_ReleaseHeldHtlcResponseInstructionZZ,
	/// Handle a [`ReleaseHeldHtlc`] message. If authentication of the message succeeds, an HTLC
	/// should be released to the corresponding payee.
	pub handle_release_held_htlc: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::async_payments::ReleaseHeldHtlc, context: crate::lightning::blinded_path::message::AsyncPaymentsContext),
	/// Release any [`AsyncPaymentsMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating an async payment flow rather than in response
	/// to another message.
	pub release_pending_messages: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C2Tuple_AsyncPaymentsMessageMessageSendInstructionsZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for AsyncPaymentsMessageHandler {}
unsafe impl Sync for AsyncPaymentsMessageHandler {}
#[allow(unused)]
pub(crate) fn AsyncPaymentsMessageHandler_clone_fields(orig: &AsyncPaymentsMessageHandler) -> AsyncPaymentsMessageHandler {
	AsyncPaymentsMessageHandler {
		this_arg: orig.this_arg,
		handle_held_htlc_available: Clone::clone(&orig.handle_held_htlc_available),
		handle_release_held_htlc: Clone::clone(&orig.handle_release_held_htlc),
		release_pending_messages: Clone::clone(&orig.release_pending_messages),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::async_payments::AsyncPaymentsMessageHandler as rustAsyncPaymentsMessageHandler;
impl rustAsyncPaymentsMessageHandler for AsyncPaymentsMessageHandler {
	fn handle_held_htlc_available(&self, mut message: lightning::onion_message::async_payments::HeldHtlcAvailable, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::ReleaseHeldHtlc, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.handle_held_htlc_available)(self.this_arg, crate::lightning::onion_message::async_payments::HeldHtlcAvailable { inner: ObjOps::heap_alloc(message), is_owned: true }, local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_release_held_htlc(&self, mut message: lightning::onion_message::async_payments::ReleaseHeldHtlc, mut context: lightning::blinded_path::message::AsyncPaymentsContext) {
		(self.handle_release_held_htlc)(self.this_arg, crate::lightning::onion_message::async_payments::ReleaseHeldHtlc { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context))
	}
	fn release_pending_messages(&self) -> Vec<(lightning::onion_message::async_payments::AsyncPaymentsMessage, lightning::onion_message::messenger::MessageSendInstructions)> {
		let mut ret = (self.release_pending_messages)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_ret_0 = (orig_ret_0_0.into_native(), orig_ret_0_1.into_native()); local_ret_0 }); };
		local_ret
	}
}

pub struct AsyncPaymentsMessageHandlerRef(AsyncPaymentsMessageHandler);
impl rustAsyncPaymentsMessageHandler for AsyncPaymentsMessageHandlerRef {
	fn handle_held_htlc_available(&self, mut message: lightning::onion_message::async_payments::HeldHtlcAvailable, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::ReleaseHeldHtlc, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.0.handle_held_htlc_available)(self.0.this_arg, crate::lightning::onion_message::async_payments::HeldHtlcAvailable { inner: ObjOps::heap_alloc(message), is_owned: true }, local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_release_held_htlc(&self, mut message: lightning::onion_message::async_payments::ReleaseHeldHtlc, mut context: lightning::blinded_path::message::AsyncPaymentsContext) {
		(self.0.handle_release_held_htlc)(self.0.this_arg, crate::lightning::onion_message::async_payments::ReleaseHeldHtlc { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context))
	}
	fn release_pending_messages(&self) -> Vec<(lightning::onion_message::async_payments::AsyncPaymentsMessage, lightning::onion_message::messenger::MessageSendInstructions)> {
		let mut ret = (self.0.release_pending_messages)(self.0.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_ret_0 = (orig_ret_0_0.into_native(), orig_ret_0_1.into_native()); local_ret_0 }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for AsyncPaymentsMessageHandler {
	type Target = AsyncPaymentsMessageHandlerRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const AsyncPaymentsMessageHandlerRef) }
	}
}
impl core::ops::DerefMut for AsyncPaymentsMessageHandler {
	fn deref_mut(&mut self) -> &mut AsyncPaymentsMessageHandlerRef {
		unsafe { &mut *(self as *mut _ as *mut AsyncPaymentsMessageHandlerRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn AsyncPaymentsMessageHandler_free(this_ptr: AsyncPaymentsMessageHandler) { }
impl Drop for AsyncPaymentsMessageHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Possible async payment messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum AsyncPaymentsMessage {
	/// An HTLC is being held upstream for the often-offline recipient, to be released via
	/// [`ReleaseHeldHtlc`].
	HeldHtlcAvailable(
		crate::lightning::onion_message::async_payments::HeldHtlcAvailable),
	/// Releases the HTLC corresponding to an inbound [`HeldHtlcAvailable`] message.
	ReleaseHeldHtlc(
		crate::lightning::onion_message::async_payments::ReleaseHeldHtlc),
}
use lightning::onion_message::async_payments::AsyncPaymentsMessage as AsyncPaymentsMessageImport;
pub(crate) type nativeAsyncPaymentsMessage = AsyncPaymentsMessageImport;

impl AsyncPaymentsMessage {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeAsyncPaymentsMessage {
		match self {
			AsyncPaymentsMessage::HeldHtlcAvailable (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeAsyncPaymentsMessage::HeldHtlcAvailable (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			AsyncPaymentsMessage::ReleaseHeldHtlc (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeAsyncPaymentsMessage::ReleaseHeldHtlc (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeAsyncPaymentsMessage {
		match self {
			AsyncPaymentsMessage::HeldHtlcAvailable (mut a, ) => {
				nativeAsyncPaymentsMessage::HeldHtlcAvailable (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			AsyncPaymentsMessage::ReleaseHeldHtlc (mut a, ) => {
				nativeAsyncPaymentsMessage::ReleaseHeldHtlc (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &AsyncPaymentsMessageImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeAsyncPaymentsMessage) };
		match native {
			nativeAsyncPaymentsMessage::HeldHtlcAvailable (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				AsyncPaymentsMessage::HeldHtlcAvailable (
					crate::lightning::onion_message::async_payments::HeldHtlcAvailable { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::ReleaseHeldHtlc (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				AsyncPaymentsMessage::ReleaseHeldHtlc (
					crate::lightning::onion_message::async_payments::ReleaseHeldHtlc { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeAsyncPaymentsMessage) -> Self {
		match native {
			nativeAsyncPaymentsMessage::HeldHtlcAvailable (mut a, ) => {
				AsyncPaymentsMessage::HeldHtlcAvailable (
					crate::lightning::onion_message::async_payments::HeldHtlcAvailable { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::ReleaseHeldHtlc (mut a, ) => {
				AsyncPaymentsMessage::ReleaseHeldHtlc (
					crate::lightning::onion_message::async_payments::ReleaseHeldHtlc { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the AsyncPaymentsMessage
#[no_mangle]
pub extern "C" fn AsyncPaymentsMessage_free(this_ptr: AsyncPaymentsMessage) { }
/// Creates a copy of the AsyncPaymentsMessage
#[no_mangle]
pub extern "C" fn AsyncPaymentsMessage_clone(orig: &AsyncPaymentsMessage) -> AsyncPaymentsMessage {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AsyncPaymentsMessage_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const AsyncPaymentsMessage)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AsyncPaymentsMessage_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut AsyncPaymentsMessage) };
}
#[no_mangle]
/// Utility method to constructs a new HeldHtlcAvailable-variant AsyncPaymentsMessage
pub extern "C" fn AsyncPaymentsMessage_held_htlc_available(a: crate::lightning::onion_message::async_payments::HeldHtlcAvailable) -> AsyncPaymentsMessage {
	AsyncPaymentsMessage::HeldHtlcAvailable(a, )
}
#[no_mangle]
/// Utility method to constructs a new ReleaseHeldHtlc-variant AsyncPaymentsMessage
pub extern "C" fn AsyncPaymentsMessage_release_held_htlc(a: crate::lightning::onion_message::async_payments::ReleaseHeldHtlc) -> AsyncPaymentsMessage {
	AsyncPaymentsMessage::ReleaseHeldHtlc(a, )
}
/// Get a string which allows debug introspection of a AsyncPaymentsMessage object
pub extern "C" fn AsyncPaymentsMessage_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::AsyncPaymentsMessage }).into()}

use lightning::onion_message::async_payments::HeldHtlcAvailable as nativeHeldHtlcAvailableImport;
pub(crate) type nativeHeldHtlcAvailable = nativeHeldHtlcAvailableImport;

/// An HTLC destined for the recipient of this message is being held upstream. The reply path
/// accompanying this onion message should be used to send a [`ReleaseHeldHtlc`] response, which
/// will cause the upstream HTLC to be released.
#[must_use]
#[repr(C)]
pub struct HeldHtlcAvailable {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHeldHtlcAvailable,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for HeldHtlcAvailable {
	type Target = nativeHeldHtlcAvailable;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for HeldHtlcAvailable { }
unsafe impl core::marker::Sync for HeldHtlcAvailable { }
impl Drop for HeldHtlcAvailable {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHeldHtlcAvailable>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the HeldHtlcAvailable, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn HeldHtlcAvailable_free(this_obj: HeldHtlcAvailable) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HeldHtlcAvailable_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHeldHtlcAvailable) };
}
#[allow(unused)]
impl HeldHtlcAvailable {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHeldHtlcAvailable {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHeldHtlcAvailable {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHeldHtlcAvailable {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new HeldHtlcAvailable given each field
#[must_use]
#[no_mangle]
pub extern "C" fn HeldHtlcAvailable_new() -> HeldHtlcAvailable {
	HeldHtlcAvailable { inner: ObjOps::heap_alloc(nativeHeldHtlcAvailable {
	}), is_owned: true }
}
impl Clone for HeldHtlcAvailable {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHeldHtlcAvailable>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HeldHtlcAvailable_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeHeldHtlcAvailable)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the HeldHtlcAvailable
pub extern "C" fn HeldHtlcAvailable_clone(orig: &HeldHtlcAvailable) -> HeldHtlcAvailable {
	orig.clone()
}
/// Get a string which allows debug introspection of a HeldHtlcAvailable object
pub extern "C" fn HeldHtlcAvailable_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::HeldHtlcAvailable }).into()}

use lightning::onion_message::async_payments::ReleaseHeldHtlc as nativeReleaseHeldHtlcImport;
pub(crate) type nativeReleaseHeldHtlc = nativeReleaseHeldHtlcImport;

/// Releases the HTLC corresponding to an inbound [`HeldHtlcAvailable`] message.
#[must_use]
#[repr(C)]
pub struct ReleaseHeldHtlc {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeReleaseHeldHtlc,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ReleaseHeldHtlc {
	type Target = nativeReleaseHeldHtlc;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ReleaseHeldHtlc { }
unsafe impl core::marker::Sync for ReleaseHeldHtlc { }
impl Drop for ReleaseHeldHtlc {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeReleaseHeldHtlc>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ReleaseHeldHtlc, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ReleaseHeldHtlc_free(this_obj: ReleaseHeldHtlc) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReleaseHeldHtlc_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeReleaseHeldHtlc) };
}
#[allow(unused)]
impl ReleaseHeldHtlc {
	pub(crate) fn get_native_ref(&self) -> &'static nativeReleaseHeldHtlc {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeReleaseHeldHtlc {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeReleaseHeldHtlc {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new ReleaseHeldHtlc given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ReleaseHeldHtlc_new() -> ReleaseHeldHtlc {
	ReleaseHeldHtlc { inner: ObjOps::heap_alloc(nativeReleaseHeldHtlc {
	}), is_owned: true }
}
impl Clone for ReleaseHeldHtlc {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeReleaseHeldHtlc>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReleaseHeldHtlc_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeReleaseHeldHtlc)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ReleaseHeldHtlc
pub extern "C" fn ReleaseHeldHtlc_clone(orig: &ReleaseHeldHtlc) -> ReleaseHeldHtlc {
	orig.clone()
}
/// Get a string which allows debug introspection of a ReleaseHeldHtlc object
pub extern "C" fn ReleaseHeldHtlc_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::ReleaseHeldHtlc }).into()}
impl From<nativeReleaseHeldHtlc> for crate::lightning::onion_message::packet::OnionMessageContents {
	fn from(obj: nativeReleaseHeldHtlc) -> Self {
		let rust_obj = crate::lightning::onion_message::async_payments::ReleaseHeldHtlc { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ReleaseHeldHtlc_as_OnionMessageContents(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(ReleaseHeldHtlc_free_void);
		ret
	}
}
/// Constructs a new OnionMessageContents which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageContents must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ReleaseHeldHtlc_as_OnionMessageContents(this_arg: &ReleaseHeldHtlc) -> crate::lightning::onion_message::packet::OnionMessageContents {
	crate::lightning::onion_message::packet::OnionMessageContents {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		tlv_type: ReleaseHeldHtlc_OnionMessageContents_tlv_type,
		msg_type: ReleaseHeldHtlc_OnionMessageContents_msg_type,
		write: ReleaseHeldHtlc_write_void,
		debug_str: ReleaseHeldHtlc_debug_str_void,
		cloned: Some(OnionMessageContents_ReleaseHeldHtlc_cloned),
	}
}

#[must_use]
extern "C" fn ReleaseHeldHtlc_OnionMessageContents_tlv_type(this_arg: *const c_void) -> u64 {
	let mut ret = <nativeReleaseHeldHtlc as lightning::onion_message::packet::OnionMessageContents>::tlv_type(unsafe { &mut *(this_arg as *mut nativeReleaseHeldHtlc) }, );
	ret
}
#[must_use]
extern "C" fn ReleaseHeldHtlc_OnionMessageContents_msg_type(this_arg: *const c_void) -> crate::c_types::Str {
	let mut ret = <nativeReleaseHeldHtlc as lightning::onion_message::packet::OnionMessageContents>::msg_type(unsafe { &mut *(this_arg as *mut nativeReleaseHeldHtlc) }, );
	ret.into()
}
extern "C" fn OnionMessageContents_ReleaseHeldHtlc_cloned(new_obj: &mut crate::lightning::onion_message::packet::OnionMessageContents) {
	new_obj.this_arg = ReleaseHeldHtlc_clone_void(new_obj.this_arg);
	new_obj.free = Some(ReleaseHeldHtlc_free_void);
}

#[no_mangle]
/// Serialize the HeldHtlcAvailable object into a byte array which can be read by HeldHtlcAvailable_read
pub extern "C" fn HeldHtlcAvailable_write(obj: &crate::lightning::onion_message::async_payments::HeldHtlcAvailable) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn HeldHtlcAvailable_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::async_payments::nativeHeldHtlcAvailable) })
}
#[no_mangle]
/// Read a HeldHtlcAvailable from a byte array, created by HeldHtlcAvailable_write
pub extern "C" fn HeldHtlcAvailable_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HeldHtlcAvailableDecodeErrorZ {
	let res: Result<lightning::onion_message::async_payments::HeldHtlcAvailable, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::async_payments::HeldHtlcAvailable { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ReleaseHeldHtlc object into a byte array which can be read by ReleaseHeldHtlc_read
pub extern "C" fn ReleaseHeldHtlc_write(obj: &crate::lightning::onion_message::async_payments::ReleaseHeldHtlc) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ReleaseHeldHtlc_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::async_payments::nativeReleaseHeldHtlc) })
}
#[no_mangle]
/// Read a ReleaseHeldHtlc from a byte array, created by ReleaseHeldHtlc_write
pub extern "C" fn ReleaseHeldHtlc_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ReleaseHeldHtlcDecodeErrorZ {
	let res: Result<lightning::onion_message::async_payments::ReleaseHeldHtlc, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::async_payments::ReleaseHeldHtlc { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Returns whether `tlv_type` corresponds to a TLV record for async payment messages.
#[must_use]
#[no_mangle]
pub extern "C" fn AsyncPaymentsMessage_is_known_type(mut tlv_type: u64) -> bool {
	let mut ret = lightning::onion_message::async_payments::AsyncPaymentsMessage::is_known_type(tlv_type);
	ret
}

impl From<nativeAsyncPaymentsMessage> for crate::lightning::onion_message::packet::OnionMessageContents {
	fn from(obj: nativeAsyncPaymentsMessage) -> Self {
		let rust_obj = crate::lightning::onion_message::async_payments::AsyncPaymentsMessage::native_into(obj);
		let mut ret = AsyncPaymentsMessage_as_OnionMessageContents(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(AsyncPaymentsMessage_free_void);
		ret
	}
}
/// Constructs a new OnionMessageContents which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageContents must be freed before this_arg is
#[no_mangle]
pub extern "C" fn AsyncPaymentsMessage_as_OnionMessageContents(this_arg: &AsyncPaymentsMessage) -> crate::lightning::onion_message::packet::OnionMessageContents {
	crate::lightning::onion_message::packet::OnionMessageContents {
		this_arg: unsafe { ObjOps::untweak_ptr(this_arg as *const AsyncPaymentsMessage as *mut AsyncPaymentsMessage) as *mut c_void },
		free: None,
		tlv_type: AsyncPaymentsMessage_OnionMessageContents_tlv_type,
		msg_type: AsyncPaymentsMessage_OnionMessageContents_msg_type,
		write: AsyncPaymentsMessage_write_void,
		debug_str: AsyncPaymentsMessage_debug_str_void,
		cloned: Some(OnionMessageContents_AsyncPaymentsMessage_cloned),
	}
}

#[must_use]
extern "C" fn AsyncPaymentsMessage_OnionMessageContents_tlv_type(this_arg: *const c_void) -> u64 {
	let mut ret = <nativeAsyncPaymentsMessage as lightning::onion_message::packet::OnionMessageContents>::tlv_type(unsafe { &mut *(this_arg as *mut nativeAsyncPaymentsMessage) }, );
	ret
}
#[must_use]
extern "C" fn AsyncPaymentsMessage_OnionMessageContents_msg_type(this_arg: *const c_void) -> crate::c_types::Str {
	let mut ret = <nativeAsyncPaymentsMessage as lightning::onion_message::packet::OnionMessageContents>::msg_type(unsafe { &mut *(this_arg as *mut nativeAsyncPaymentsMessage) }, );
	ret.into()
}
extern "C" fn OnionMessageContents_AsyncPaymentsMessage_cloned(new_obj: &mut crate::lightning::onion_message::packet::OnionMessageContents) {
	new_obj.this_arg = AsyncPaymentsMessage_clone_void(new_obj.this_arg);
	new_obj.free = Some(AsyncPaymentsMessage_free_void);
}

#[no_mangle]
/// Serialize the AsyncPaymentsMessage object into a byte array which can be read by AsyncPaymentsMessage_read
pub extern "C" fn AsyncPaymentsMessage_write(obj: &crate::lightning::onion_message::async_payments::AsyncPaymentsMessage) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn AsyncPaymentsMessage_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	AsyncPaymentsMessage_write(unsafe { &*(obj as *const AsyncPaymentsMessage) })
}
#[no_mangle]
/// Read a AsyncPaymentsMessage from a byte array, created by AsyncPaymentsMessage_write
pub extern "C" fn AsyncPaymentsMessage_read(ser: crate::c_types::u8slice, arg: u64) -> crate::c_types::derived::CResult_AsyncPaymentsMessageDecodeErrorZ {
	let arg_conv = arg;
	let res: Result<lightning::onion_message::async_payments::AsyncPaymentsMessage, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::async_payments::AsyncPaymentsMessage::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
