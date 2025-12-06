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
/// The [`AsyncPaymentsContext`]s provided to each method was authenticated by the
/// [`OnionMessenger`] as coming from a blinded path that we created.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
#[repr(C)]
pub struct AsyncPaymentsMessageHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Handle an [`OfferPathsRequest`] message. If we are a static invoice server and the message was
	/// sent over paths that we previously provided to an async recipient, an [`OfferPaths`] message
	/// should be returned.
	///
	/// Note that responder (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub handle_offer_paths_request: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::async_payments::OfferPathsRequest, context: crate::lightning::blinded_path::message::AsyncPaymentsContext, responder: crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::COption_C2Tuple_OfferPathsResponseInstructionZZ,
	/// Handle an [`OfferPaths`] message. If this is in response to an [`OfferPathsRequest`] that
	/// we previously sent as an async recipient, we should build an [`Offer`] containing the
	/// included [`OfferPaths::paths`] and a corresponding [`StaticInvoice`], and reply with
	/// [`ServeStaticInvoice`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	///
	/// Note that responder (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub handle_offer_paths: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::async_payments::OfferPaths, context: crate::lightning::blinded_path::message::AsyncPaymentsContext, responder: crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::COption_C2Tuple_ServeStaticInvoiceResponseInstructionZZ,
	/// Handle a [`ServeStaticInvoice`] message. If this is in response to an [`OfferPaths`] message
	/// we previously sent as a static invoice server, a [`StaticInvoicePersisted`] message should be
	/// sent once the message is handled.
	///
	/// Note that responder (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub handle_serve_static_invoice: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::async_payments::ServeStaticInvoice, context: crate::lightning::blinded_path::message::AsyncPaymentsContext, responder: crate::lightning::onion_message::messenger::Responder),
	/// Handle a [`StaticInvoicePersisted`] message. If this is in response to a
	/// [`ServeStaticInvoice`] message we previously sent as an async recipient, then the offer we
	/// generated on receipt of a previous [`OfferPaths`] message is now ready to be used for async
	/// payments.
	pub handle_static_invoice_persisted: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::async_payments::StaticInvoicePersisted, context: crate::lightning::blinded_path::message::AsyncPaymentsContext),
	/// Handle a [`HeldHtlcAvailable`] message. A [`ReleaseHeldHtlc`] should be returned to release
	/// the held funds.
	///
	/// Note that responder (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub handle_held_htlc_available: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::async_payments::HeldHtlcAvailable, context: crate::lightning::blinded_path::message::AsyncPaymentsContext, responder: crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::COption_C2Tuple_ReleaseHeldHtlcResponseInstructionZZ,
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
		handle_offer_paths_request: Clone::clone(&orig.handle_offer_paths_request),
		handle_offer_paths: Clone::clone(&orig.handle_offer_paths),
		handle_serve_static_invoice: Clone::clone(&orig.handle_serve_static_invoice),
		handle_static_invoice_persisted: Clone::clone(&orig.handle_static_invoice_persisted),
		handle_held_htlc_available: Clone::clone(&orig.handle_held_htlc_available),
		handle_release_held_htlc: Clone::clone(&orig.handle_release_held_htlc),
		release_pending_messages: Clone::clone(&orig.release_pending_messages),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::async_payments::AsyncPaymentsMessageHandler as rustAsyncPaymentsMessageHandler;
impl rustAsyncPaymentsMessageHandler for AsyncPaymentsMessageHandler {
	fn handle_offer_paths_request(&self, mut message: lightning::onion_message::async_payments::OfferPathsRequest, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::OfferPaths, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.handle_offer_paths_request)(self.this_arg, crate::lightning::onion_message::async_payments::OfferPathsRequest { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_offer_paths(&self, mut message: lightning::onion_message::async_payments::OfferPaths, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::ServeStaticInvoice, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.handle_offer_paths)(self.this_arg, crate::lightning::onion_message::async_payments::OfferPaths { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_serve_static_invoice(&self, mut message: lightning::onion_message::async_payments::ServeStaticInvoice, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		(self.handle_serve_static_invoice)(self.this_arg, crate::lightning::onion_message::async_payments::ServeStaticInvoice { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder)
	}
	fn handle_static_invoice_persisted(&self, mut message: lightning::onion_message::async_payments::StaticInvoicePersisted, mut context: lightning::blinded_path::message::AsyncPaymentsContext) {
		(self.handle_static_invoice_persisted)(self.this_arg, crate::lightning::onion_message::async_payments::StaticInvoicePersisted { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context))
	}
	fn handle_held_htlc_available(&self, mut message: lightning::onion_message::async_payments::HeldHtlcAvailable, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::ReleaseHeldHtlc, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.handle_held_htlc_available)(self.this_arg, crate::lightning::onion_message::async_payments::HeldHtlcAvailable { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder);
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
	fn handle_offer_paths_request(&self, mut message: lightning::onion_message::async_payments::OfferPathsRequest, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::OfferPaths, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.0.handle_offer_paths_request)(self.0.this_arg, crate::lightning::onion_message::async_payments::OfferPathsRequest { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_offer_paths(&self, mut message: lightning::onion_message::async_payments::OfferPaths, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::ServeStaticInvoice, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.0.handle_offer_paths)(self.0.this_arg, crate::lightning::onion_message::async_payments::OfferPaths { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_serve_static_invoice(&self, mut message: lightning::onion_message::async_payments::ServeStaticInvoice, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		(self.0.handle_serve_static_invoice)(self.0.this_arg, crate::lightning::onion_message::async_payments::ServeStaticInvoice { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder)
	}
	fn handle_static_invoice_persisted(&self, mut message: lightning::onion_message::async_payments::StaticInvoicePersisted, mut context: lightning::blinded_path::message::AsyncPaymentsContext) {
		(self.0.handle_static_invoice_persisted)(self.0.this_arg, crate::lightning::onion_message::async_payments::StaticInvoicePersisted { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context))
	}
	fn handle_held_htlc_available(&self, mut message: lightning::onion_message::async_payments::HeldHtlcAvailable, mut context: lightning::blinded_path::message::AsyncPaymentsContext, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::async_payments::ReleaseHeldHtlc, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.0.handle_held_htlc_available)(self.0.this_arg, crate::lightning::onion_message::async_payments::HeldHtlcAvailable { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(context), local_responder);
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
	/// A request from an async recipient for [`BlindedMessagePath`]s, sent to a static invoice
	/// server.
	OfferPathsRequest(
		crate::lightning::onion_message::async_payments::OfferPathsRequest),
	/// [`BlindedMessagePath`]s to be included in an async recipient's [`Offer::paths`], sent by a
	/// static invoice server in response to an [`OfferPathsRequest`].
	///
	/// [`Offer::paths`]: crate::offers::offer::Offer::paths
	OfferPaths(
		crate::lightning::onion_message::async_payments::OfferPaths),
	/// A request from an async recipient to a static invoice server that a [`StaticInvoice`] be
	/// provided in response to [`InvoiceRequest`]s from payers.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	ServeStaticInvoice(
		crate::lightning::onion_message::async_payments::ServeStaticInvoice),
	/// Confirmation from a static invoice server that a [`StaticInvoice`] was persisted and the
	/// corresponding [`Offer`] is ready to be used to receive async payments. Sent to an async
	/// recipient in response to a [`ServeStaticInvoice`] message.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	StaticInvoicePersisted(
		crate::lightning::onion_message::async_payments::StaticInvoicePersisted),
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
			AsyncPaymentsMessage::OfferPathsRequest (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeAsyncPaymentsMessage::OfferPathsRequest (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			AsyncPaymentsMessage::OfferPaths (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeAsyncPaymentsMessage::OfferPaths (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			AsyncPaymentsMessage::ServeStaticInvoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeAsyncPaymentsMessage::ServeStaticInvoice (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			AsyncPaymentsMessage::StaticInvoicePersisted (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeAsyncPaymentsMessage::StaticInvoicePersisted (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
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
			AsyncPaymentsMessage::OfferPathsRequest (mut a, ) => {
				nativeAsyncPaymentsMessage::OfferPathsRequest (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			AsyncPaymentsMessage::OfferPaths (mut a, ) => {
				nativeAsyncPaymentsMessage::OfferPaths (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			AsyncPaymentsMessage::ServeStaticInvoice (mut a, ) => {
				nativeAsyncPaymentsMessage::ServeStaticInvoice (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			AsyncPaymentsMessage::StaticInvoicePersisted (mut a, ) => {
				nativeAsyncPaymentsMessage::StaticInvoicePersisted (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
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
			nativeAsyncPaymentsMessage::OfferPathsRequest (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				AsyncPaymentsMessage::OfferPathsRequest (
					crate::lightning::onion_message::async_payments::OfferPathsRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::OfferPaths (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				AsyncPaymentsMessage::OfferPaths (
					crate::lightning::onion_message::async_payments::OfferPaths { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::ServeStaticInvoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				AsyncPaymentsMessage::ServeStaticInvoice (
					crate::lightning::onion_message::async_payments::ServeStaticInvoice { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::StaticInvoicePersisted (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				AsyncPaymentsMessage::StaticInvoicePersisted (
					crate::lightning::onion_message::async_payments::StaticInvoicePersisted { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
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
			nativeAsyncPaymentsMessage::OfferPathsRequest (mut a, ) => {
				AsyncPaymentsMessage::OfferPathsRequest (
					crate::lightning::onion_message::async_payments::OfferPathsRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::OfferPaths (mut a, ) => {
				AsyncPaymentsMessage::OfferPaths (
					crate::lightning::onion_message::async_payments::OfferPaths { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::ServeStaticInvoice (mut a, ) => {
				AsyncPaymentsMessage::ServeStaticInvoice (
					crate::lightning::onion_message::async_payments::ServeStaticInvoice { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeAsyncPaymentsMessage::StaticInvoicePersisted (mut a, ) => {
				AsyncPaymentsMessage::StaticInvoicePersisted (
					crate::lightning::onion_message::async_payments::StaticInvoicePersisted { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
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
/// Utility method to constructs a new OfferPathsRequest-variant AsyncPaymentsMessage
pub extern "C" fn AsyncPaymentsMessage_offer_paths_request(a: crate::lightning::onion_message::async_payments::OfferPathsRequest) -> AsyncPaymentsMessage {
	AsyncPaymentsMessage::OfferPathsRequest(a, )
}
#[no_mangle]
/// Utility method to constructs a new OfferPaths-variant AsyncPaymentsMessage
pub extern "C" fn AsyncPaymentsMessage_offer_paths(a: crate::lightning::onion_message::async_payments::OfferPaths) -> AsyncPaymentsMessage {
	AsyncPaymentsMessage::OfferPaths(a, )
}
#[no_mangle]
/// Utility method to constructs a new ServeStaticInvoice-variant AsyncPaymentsMessage
pub extern "C" fn AsyncPaymentsMessage_serve_static_invoice(a: crate::lightning::onion_message::async_payments::ServeStaticInvoice) -> AsyncPaymentsMessage {
	AsyncPaymentsMessage::ServeStaticInvoice(a, )
}
#[no_mangle]
/// Utility method to constructs a new StaticInvoicePersisted-variant AsyncPaymentsMessage
pub extern "C" fn AsyncPaymentsMessage_static_invoice_persisted(a: crate::lightning::onion_message::async_payments::StaticInvoicePersisted) -> AsyncPaymentsMessage {
	AsyncPaymentsMessage::StaticInvoicePersisted(a, )
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

use lightning::onion_message::async_payments::OfferPathsRequest as nativeOfferPathsRequestImport;
pub(crate) type nativeOfferPathsRequest = nativeOfferPathsRequestImport;

/// A request from an async recipient for [`BlindedMessagePath`]s from a static invoice server.
/// These paths will be used in the async recipient's [`Offer::paths`], so payers can request
/// [`StaticInvoice`]s from the static invoice server.
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[repr(C)]
pub struct OfferPathsRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOfferPathsRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OfferPathsRequest {
	type Target = nativeOfferPathsRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OfferPathsRequest { }
unsafe impl core::marker::Sync for OfferPathsRequest { }
impl Drop for OfferPathsRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOfferPathsRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OfferPathsRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OfferPathsRequest_free(this_obj: OfferPathsRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferPathsRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOfferPathsRequest) };
}
#[allow(unused)]
impl OfferPathsRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOfferPathsRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOfferPathsRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOfferPathsRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The \"slot\" in the static invoice server's database that this invoice should go into. This
/// allows us as the recipient to replace a specific invoice that is stored by the server, which
/// is useful for limiting the number of invoices stored by the server while also keeping all the
/// invoices persisted with the server fresh.
#[no_mangle]
pub extern "C" fn OfferPathsRequest_get_invoice_slot(this_ptr: &OfferPathsRequest) -> u16 {
	let mut inner_val = &mut OfferPathsRequest::get_native_mut_ref(this_ptr).invoice_slot;
	*inner_val
}
/// The \"slot\" in the static invoice server's database that this invoice should go into. This
/// allows us as the recipient to replace a specific invoice that is stored by the server, which
/// is useful for limiting the number of invoices stored by the server while also keeping all the
/// invoices persisted with the server fresh.
#[no_mangle]
pub extern "C" fn OfferPathsRequest_set_invoice_slot(this_ptr: &mut OfferPathsRequest, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.invoice_slot = val;
}
/// Constructs a new OfferPathsRequest given each field
#[must_use]
#[no_mangle]
pub extern "C" fn OfferPathsRequest_new(mut invoice_slot_arg: u16) -> OfferPathsRequest {
	OfferPathsRequest { inner: ObjOps::heap_alloc(nativeOfferPathsRequest {
		invoice_slot: invoice_slot_arg,
	}), is_owned: true }
}
impl Clone for OfferPathsRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOfferPathsRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferPathsRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeOfferPathsRequest) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OfferPathsRequest
pub extern "C" fn OfferPathsRequest_clone(orig: &OfferPathsRequest) -> OfferPathsRequest {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a OfferPathsRequest object
pub extern "C" fn OfferPathsRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::OfferPathsRequest }).into()}

use lightning::onion_message::async_payments::OfferPaths as nativeOfferPathsImport;
pub(crate) type nativeOfferPaths = nativeOfferPathsImport;

/// [`BlindedMessagePath`]s to be included in an async recipient's [`Offer::paths`], sent by a
/// static invoice server in response to an [`OfferPathsRequest`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[repr(C)]
pub struct OfferPaths {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOfferPaths,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OfferPaths {
	type Target = nativeOfferPaths;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OfferPaths { }
unsafe impl core::marker::Sync for OfferPaths { }
impl Drop for OfferPaths {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOfferPaths>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OfferPaths, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OfferPaths_free(this_obj: OfferPaths) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferPaths_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOfferPaths) };
}
#[allow(unused)]
impl OfferPaths {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOfferPaths {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOfferPaths {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOfferPaths {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The paths that should be included in the async recipient's [`Offer::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[no_mangle]
pub extern "C" fn OfferPaths_get_paths(this_ptr: &OfferPaths) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut inner_val = &mut OfferPaths::get_native_mut_ref(this_ptr).paths;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::blinded_path::message::BlindedMessagePath<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The paths that should be included in the async recipient's [`Offer::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[no_mangle]
pub extern "C" fn OfferPaths_set_paths(this_ptr: &mut OfferPaths, mut val: crate::c_types::derived::CVec_BlindedMessagePathZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.paths = local_val;
}
/// The time as seconds since the Unix epoch at which the [`Self::paths`] expire.
#[no_mangle]
pub extern "C" fn OfferPaths_get_paths_absolute_expiry(this_ptr: &OfferPaths) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut OfferPaths::get_native_mut_ref(this_ptr).paths_absolute_expiry;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The time as seconds since the Unix epoch at which the [`Self::paths`] expire.
#[no_mangle]
pub extern "C" fn OfferPaths_set_paths_absolute_expiry(this_ptr: &mut OfferPaths, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.paths_absolute_expiry = local_val;
}
/// Constructs a new OfferPaths given each field
#[must_use]
#[no_mangle]
pub extern "C" fn OfferPaths_new(mut paths_arg: crate::c_types::derived::CVec_BlindedMessagePathZ, mut paths_absolute_expiry_arg: crate::c_types::derived::COption_u64Z) -> OfferPaths {
	let mut local_paths_arg = Vec::new(); for mut item in paths_arg.into_rust().drain(..) { local_paths_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_paths_absolute_expiry_arg = if paths_absolute_expiry_arg.is_some() { Some( { paths_absolute_expiry_arg.take() }) } else { None };
	OfferPaths { inner: ObjOps::heap_alloc(nativeOfferPaths {
		paths: local_paths_arg,
		paths_absolute_expiry: local_paths_absolute_expiry_arg,
	}), is_owned: true }
}
impl Clone for OfferPaths {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOfferPaths>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferPaths_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeOfferPaths) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OfferPaths
pub extern "C" fn OfferPaths_clone(orig: &OfferPaths) -> OfferPaths {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a OfferPaths object
pub extern "C" fn OfferPaths_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::OfferPaths }).into()}

use lightning::onion_message::async_payments::ServeStaticInvoice as nativeServeStaticInvoiceImport;
pub(crate) type nativeServeStaticInvoice = nativeServeStaticInvoiceImport;

/// A request from an async recipient to a static invoice server that a [`StaticInvoice`] be
/// provided in response to [`InvoiceRequest`]s from payers.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[must_use]
#[repr(C)]
pub struct ServeStaticInvoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeServeStaticInvoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ServeStaticInvoice {
	type Target = nativeServeStaticInvoice;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ServeStaticInvoice { }
unsafe impl core::marker::Sync for ServeStaticInvoice { }
impl Drop for ServeStaticInvoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeServeStaticInvoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ServeStaticInvoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ServeStaticInvoice_free(this_obj: ServeStaticInvoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ServeStaticInvoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeServeStaticInvoice) };
}
#[allow(unused)]
impl ServeStaticInvoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeServeStaticInvoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeServeStaticInvoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeServeStaticInvoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The invoice that should be served by the static invoice server. Once this invoice has been
/// persisted, the [`Responder`] accompanying this message should be used to send
/// [`StaticInvoicePersisted`] to the recipient to confirm that the offer corresponding to the
/// invoice is ready to receive async payments.
#[no_mangle]
pub extern "C" fn ServeStaticInvoice_get_invoice(this_ptr: &ServeStaticInvoice) -> crate::lightning::offers::static_invoice::StaticInvoice {
	let mut inner_val = &mut ServeStaticInvoice::get_native_mut_ref(this_ptr).invoice;
	crate::lightning::offers::static_invoice::StaticInvoice { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::offers::static_invoice::StaticInvoice<>) as *mut _) }, is_owned: false }
}
/// The invoice that should be served by the static invoice server. Once this invoice has been
/// persisted, the [`Responder`] accompanying this message should be used to send
/// [`StaticInvoicePersisted`] to the recipient to confirm that the offer corresponding to the
/// invoice is ready to receive async payments.
#[no_mangle]
pub extern "C" fn ServeStaticInvoice_set_invoice(this_ptr: &mut ServeStaticInvoice, mut val: crate::lightning::offers::static_invoice::StaticInvoice) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.invoice = *unsafe { Box::from_raw(val.take_inner()) };
}
/// If a static invoice server receives an [`InvoiceRequest`] for a [`StaticInvoice`], they should
/// also forward the [`InvoiceRequest`] to the async recipient so they can respond with a fresh
/// [`Bolt12Invoice`] if the recipient is online at the time. Use this path to forward the
/// [`InvoiceRequest`] to the async recipient.
///
/// This path's [`BlindedMessagePath::introduction_node`] MUST be set to the static invoice server
/// node or one of its peers. This is because, for DoS protection, invoice requests forwarded over
/// this path are treated by the server node like any other onion message forward and the server
/// will not directly connect to the introduction node if they are not already peers.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[no_mangle]
pub extern "C" fn ServeStaticInvoice_get_forward_invoice_request_path(this_ptr: &ServeStaticInvoice) -> crate::lightning::blinded_path::message::BlindedMessagePath {
	let mut inner_val = &mut ServeStaticInvoice::get_native_mut_ref(this_ptr).forward_invoice_request_path;
	crate::lightning::blinded_path::message::BlindedMessagePath { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::message::BlindedMessagePath<>) as *mut _) }, is_owned: false }
}
/// If a static invoice server receives an [`InvoiceRequest`] for a [`StaticInvoice`], they should
/// also forward the [`InvoiceRequest`] to the async recipient so they can respond with a fresh
/// [`Bolt12Invoice`] if the recipient is online at the time. Use this path to forward the
/// [`InvoiceRequest`] to the async recipient.
///
/// This path's [`BlindedMessagePath::introduction_node`] MUST be set to the static invoice server
/// node or one of its peers. This is because, for DoS protection, invoice requests forwarded over
/// this path are treated by the server node like any other onion message forward and the server
/// will not directly connect to the introduction node if they are not already peers.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[no_mangle]
pub extern "C" fn ServeStaticInvoice_set_forward_invoice_request_path(this_ptr: &mut ServeStaticInvoice, mut val: crate::lightning::blinded_path::message::BlindedMessagePath) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.forward_invoice_request_path = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new ServeStaticInvoice given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ServeStaticInvoice_new(mut invoice_arg: crate::lightning::offers::static_invoice::StaticInvoice, mut forward_invoice_request_path_arg: crate::lightning::blinded_path::message::BlindedMessagePath) -> ServeStaticInvoice {
	ServeStaticInvoice { inner: ObjOps::heap_alloc(nativeServeStaticInvoice {
		invoice: *unsafe { Box::from_raw(invoice_arg.take_inner()) },
		forward_invoice_request_path: *unsafe { Box::from_raw(forward_invoice_request_path_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for ServeStaticInvoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeServeStaticInvoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ServeStaticInvoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeServeStaticInvoice) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ServeStaticInvoice
pub extern "C" fn ServeStaticInvoice_clone(orig: &ServeStaticInvoice) -> ServeStaticInvoice {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a ServeStaticInvoice object
pub extern "C" fn ServeStaticInvoice_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::ServeStaticInvoice }).into()}

use lightning::onion_message::async_payments::StaticInvoicePersisted as nativeStaticInvoicePersistedImport;
pub(crate) type nativeStaticInvoicePersisted = nativeStaticInvoicePersistedImport;

/// Confirmation from a static invoice server  that a [`StaticInvoice`] was persisted and the
/// corresponding [`Offer`] is ready to be used to receive async payments. Sent to an async
/// recipient in response to a [`ServeStaticInvoice`] message.
///
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[repr(C)]
pub struct StaticInvoicePersisted {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeStaticInvoicePersisted,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for StaticInvoicePersisted {
	type Target = nativeStaticInvoicePersisted;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for StaticInvoicePersisted { }
unsafe impl core::marker::Sync for StaticInvoicePersisted { }
impl Drop for StaticInvoicePersisted {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeStaticInvoicePersisted>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the StaticInvoicePersisted, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn StaticInvoicePersisted_free(this_obj: StaticInvoicePersisted) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn StaticInvoicePersisted_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeStaticInvoicePersisted) };
}
#[allow(unused)]
impl StaticInvoicePersisted {
	pub(crate) fn get_native_ref(&self) -> &'static nativeStaticInvoicePersisted {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeStaticInvoicePersisted {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeStaticInvoicePersisted {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new StaticInvoicePersisted given each field
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoicePersisted_new() -> StaticInvoicePersisted {
	StaticInvoicePersisted { inner: ObjOps::heap_alloc(nativeStaticInvoicePersisted {
	}), is_owned: true }
}
impl Clone for StaticInvoicePersisted {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeStaticInvoicePersisted>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn StaticInvoicePersisted_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeStaticInvoicePersisted) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the StaticInvoicePersisted
pub extern "C" fn StaticInvoicePersisted_clone(orig: &StaticInvoicePersisted) -> StaticInvoicePersisted {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a StaticInvoicePersisted object
pub extern "C" fn StaticInvoicePersisted_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::StaticInvoicePersisted }).into()}

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
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HeldHtlcAvailable_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeHeldHtlcAvailable) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the HeldHtlcAvailable
pub extern "C" fn HeldHtlcAvailable_clone(orig: &HeldHtlcAvailable) -> HeldHtlcAvailable {
	Clone::clone(orig)
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
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReleaseHeldHtlc_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeReleaseHeldHtlc) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ReleaseHeldHtlc
pub extern "C" fn ReleaseHeldHtlc_clone(orig: &ReleaseHeldHtlc) -> ReleaseHeldHtlc {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a ReleaseHeldHtlc object
pub extern "C" fn ReleaseHeldHtlc_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::async_payments::ReleaseHeldHtlc }).into()}
impl From<nativeOfferPaths> for crate::lightning::onion_message::packet::OnionMessageContents {
	fn from(obj: nativeOfferPaths) -> Self {
		let rust_obj = crate::lightning::onion_message::async_payments::OfferPaths { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OfferPaths_as_OnionMessageContents(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(OfferPaths_free_void);
		ret
	}
}
/// Constructs a new OnionMessageContents which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageContents must be freed before this_arg is
#[no_mangle]
pub extern "C" fn OfferPaths_as_OnionMessageContents(this_arg: &OfferPaths) -> crate::lightning::onion_message::packet::OnionMessageContents {
	crate::lightning::onion_message::packet::OnionMessageContents {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		tlv_type: OfferPaths_OnionMessageContents_tlv_type,
		msg_type: OfferPaths_OnionMessageContents_msg_type,
		write: OfferPaths_write_void,
		debug_str: OfferPaths_debug_str_void,
		cloned: Some(OnionMessageContents_OfferPaths_cloned),
	}
}

#[must_use]
extern "C" fn OfferPaths_OnionMessageContents_tlv_type(this_arg: *const c_void) -> u64 {
	let mut ret = <nativeOfferPaths as lightning::onion_message::packet::OnionMessageContents>::tlv_type(unsafe { &mut *(this_arg as *mut nativeOfferPaths) }, );
	ret
}
#[must_use]
extern "C" fn OfferPaths_OnionMessageContents_msg_type(this_arg: *const c_void) -> crate::c_types::Str {
	let mut ret = <nativeOfferPaths as lightning::onion_message::packet::OnionMessageContents>::msg_type(unsafe { &mut *(this_arg as *mut nativeOfferPaths) }, );
	ret.into()
}
extern "C" fn OnionMessageContents_OfferPaths_cloned(new_obj: &mut crate::lightning::onion_message::packet::OnionMessageContents) {
	new_obj.this_arg = OfferPaths_clone_void(new_obj.this_arg);
	new_obj.free = Some(OfferPaths_free_void);
}

impl From<nativeServeStaticInvoice> for crate::lightning::onion_message::packet::OnionMessageContents {
	fn from(obj: nativeServeStaticInvoice) -> Self {
		let rust_obj = crate::lightning::onion_message::async_payments::ServeStaticInvoice { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ServeStaticInvoice_as_OnionMessageContents(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(ServeStaticInvoice_free_void);
		ret
	}
}
/// Constructs a new OnionMessageContents which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageContents must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ServeStaticInvoice_as_OnionMessageContents(this_arg: &ServeStaticInvoice) -> crate::lightning::onion_message::packet::OnionMessageContents {
	crate::lightning::onion_message::packet::OnionMessageContents {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		tlv_type: ServeStaticInvoice_OnionMessageContents_tlv_type,
		msg_type: ServeStaticInvoice_OnionMessageContents_msg_type,
		write: ServeStaticInvoice_write_void,
		debug_str: ServeStaticInvoice_debug_str_void,
		cloned: Some(OnionMessageContents_ServeStaticInvoice_cloned),
	}
}

#[must_use]
extern "C" fn ServeStaticInvoice_OnionMessageContents_tlv_type(this_arg: *const c_void) -> u64 {
	let mut ret = <nativeServeStaticInvoice as lightning::onion_message::packet::OnionMessageContents>::tlv_type(unsafe { &mut *(this_arg as *mut nativeServeStaticInvoice) }, );
	ret
}
#[must_use]
extern "C" fn ServeStaticInvoice_OnionMessageContents_msg_type(this_arg: *const c_void) -> crate::c_types::Str {
	let mut ret = <nativeServeStaticInvoice as lightning::onion_message::packet::OnionMessageContents>::msg_type(unsafe { &mut *(this_arg as *mut nativeServeStaticInvoice) }, );
	ret.into()
}
extern "C" fn OnionMessageContents_ServeStaticInvoice_cloned(new_obj: &mut crate::lightning::onion_message::packet::OnionMessageContents) {
	new_obj.this_arg = ServeStaticInvoice_clone_void(new_obj.this_arg);
	new_obj.free = Some(ServeStaticInvoice_free_void);
}

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
/// Serialize the OfferPathsRequest object into a byte array which can be read by OfferPathsRequest_read
pub extern "C" fn OfferPathsRequest_write(obj: &crate::lightning::onion_message::async_payments::OfferPathsRequest) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn OfferPathsRequest_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::async_payments::nativeOfferPathsRequest) })
}
#[no_mangle]
/// Read a OfferPathsRequest from a byte array, created by OfferPathsRequest_write
pub extern "C" fn OfferPathsRequest_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OfferPathsRequestDecodeErrorZ {
	let res: Result<lightning::onion_message::async_payments::OfferPathsRequest, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::async_payments::OfferPathsRequest { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the OfferPaths object into a byte array which can be read by OfferPaths_read
pub extern "C" fn OfferPaths_write(obj: &crate::lightning::onion_message::async_payments::OfferPaths) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn OfferPaths_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::async_payments::nativeOfferPaths) })
}
#[no_mangle]
/// Read a OfferPaths from a byte array, created by OfferPaths_write
pub extern "C" fn OfferPaths_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OfferPathsDecodeErrorZ {
	let res: Result<lightning::onion_message::async_payments::OfferPaths, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::async_payments::OfferPaths { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ServeStaticInvoice object into a byte array which can be read by ServeStaticInvoice_read
pub extern "C" fn ServeStaticInvoice_write(obj: &crate::lightning::onion_message::async_payments::ServeStaticInvoice) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ServeStaticInvoice_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::async_payments::nativeServeStaticInvoice) })
}
#[no_mangle]
/// Read a ServeStaticInvoice from a byte array, created by ServeStaticInvoice_write
pub extern "C" fn ServeStaticInvoice_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ServeStaticInvoiceDecodeErrorZ {
	let res: Result<lightning::onion_message::async_payments::ServeStaticInvoice, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::async_payments::ServeStaticInvoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the StaticInvoicePersisted object into a byte array which can be read by StaticInvoicePersisted_read
pub extern "C" fn StaticInvoicePersisted_write(obj: &crate::lightning::onion_message::async_payments::StaticInvoicePersisted) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn StaticInvoicePersisted_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::async_payments::nativeStaticInvoicePersisted) })
}
#[no_mangle]
/// Read a StaticInvoicePersisted from a byte array, created by StaticInvoicePersisted_write
pub extern "C" fn StaticInvoicePersisted_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_StaticInvoicePersistedDecodeErrorZ {
	let res: Result<lightning::onion_message::async_payments::StaticInvoicePersisted, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::async_payments::StaticInvoicePersisted { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
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
