// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling BOLT12 messages and payments.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::flow::OffersMessageFlow as nativeOffersMessageFlowImport;
pub(crate) type nativeOffersMessageFlow = nativeOffersMessageFlowImport<crate::lightning::onion_message::messenger::MessageRouter, crate::lightning::util::logger::Logger, >;

/// A BOLT12 offers code and flow utility provider, which facilitates
/// BOLT12 builder generation and onion message handling.
///
/// [`OffersMessageFlow`] is parameterized by a [`MessageRouter`], which is responsible
/// for finding message paths when initiating and retrying onion messages.
#[must_use]
#[repr(C)]
pub struct OffersMessageFlow {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOffersMessageFlow,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OffersMessageFlow {
	type Target = nativeOffersMessageFlow;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OffersMessageFlow { }
unsafe impl core::marker::Sync for OffersMessageFlow { }
impl Drop for OffersMessageFlow {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOffersMessageFlow>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OffersMessageFlow, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OffersMessageFlow_free(this_obj: OffersMessageFlow) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OffersMessageFlow_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOffersMessageFlow) };
}
#[allow(unused)]
impl OffersMessageFlow {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOffersMessageFlow {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOffersMessageFlow {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOffersMessageFlow {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Creates a new [`OffersMessageFlow`]
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_new(mut chain_hash: crate::c_types::ThirtyTwoBytes, mut best_block: crate::lightning::chain::BestBlock, mut our_network_pubkey: crate::c_types::PublicKey, mut current_timestamp: u32, mut inbound_payment_key: crate::lightning::ln::inbound_payment::ExpandedKey, mut receive_auth_key: crate::lightning::sign::ReceiveAuthKey, mut message_router: crate::lightning::onion_message::messenger::MessageRouter, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::offers::flow::OffersMessageFlow {
	let mut ret = lightning::offers::flow::OffersMessageFlow::new(::bitcoin::constants::ChainHash::from(&chain_hash.data), *unsafe { Box::from_raw(best_block.take_inner()) }, our_network_pubkey.into_rust(), current_timestamp, *unsafe { Box::from_raw(inbound_payment_key.take_inner()) }, *unsafe { Box::from_raw(receive_auth_key.take_inner()) }, message_router, logger);
	crate::lightning::offers::flow::OffersMessageFlow { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// If we are an async recipient, on startup we'll interactively build offers and static invoices
/// with an always-online node that will serve static invoices on our behalf. Once the offer is
/// built and the static invoice is confirmed as persisted by the server, the underlying
/// [`AsyncReceiveOfferCache`] should be persisted using
/// [`Self::writeable_async_receive_offer_cache`] so we remember the offers we've built.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_with_async_payments_offers_cache(mut this_arg: crate::lightning::offers::flow::OffersMessageFlow, mut async_receive_offer_cache: crate::lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache) -> crate::lightning::offers::flow::OffersMessageFlow {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).with_async_payments_offers_cache(*unsafe { Box::from_raw(async_receive_offer_cache.take_inner()) });
	crate::lightning::offers::flow::OffersMessageFlow { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Sets the [`BlindedMessagePath`]s that we will use as an async recipient to interactively build
/// [`Offer`]s with a static invoice server, so the server can serve [`StaticInvoice`]s to payers
/// on our behalf when we're offline.
///
/// This method will also send out messages initiating async offer creation to the static invoice
/// server, if any peers are connected.
///
/// This method only needs to be called once when the server first takes on the recipient as a
/// client, or when the paths change, e.g. if the paths are set to expire at a particular time.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_set_paths_to_static_invoice_server(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut paths_to_static_invoice_server: crate::c_types::derived::CVec_BlindedMessagePathZ, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut local_paths_to_static_invoice_server = Vec::new(); for mut item in paths_to_static_invoice_server.into_rust().drain(..) { local_paths_to_static_invoice_server.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.set_paths_to_static_invoice_server(local_paths_to_static_invoice_server, local_peers);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Notifies the [`OffersMessageFlow`] that a new block has been observed.
///
/// This allows the flow to keep in sync with the latest block timestamp,
/// which may be used for time-sensitive operations.
///
/// Must be called whenever a new chain tip becomes available. May be skipped
/// for intermediary blocks.
#[no_mangle]
pub extern "C" fn OffersMessageFlow_best_block_updated(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, header: *const [u8; 80], mut height: u32) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.best_block_updated(&::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}

/// The maximum size of a received [`StaticInvoice`] before we'll fail verification in
/// [`OffersMessageFlow::verify_serve_static_invoice_message].

#[no_mangle]
pub static MAX_STATIC_INVOICE_SIZE_BYTES: usize = lightning::offers::flow::MAX_STATIC_INVOICE_SIZE_BYTES;
/// [`BlindedMessagePath`]s for an async recipient to communicate with this node and interactively
/// build [`Offer`]s and [`StaticInvoice`]s for receiving async payments.
///
/// If `relative_expiry` is unset, the [`BlindedMessagePath`]s will never expire.
///
/// Returns the paths that the recipient should be configured with via
/// [`Self::set_paths_to_static_invoice_server`].
///
/// Errors if blinded path creation fails or the provided `recipient_id` is larger than 1KiB.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_blinded_paths_for_async_recipient(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut recipient_id: crate::c_types::derived::CVec_u8Z, mut relative_expiry: crate::c_types::derived::COption_u64Z, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::CResult_CVec_BlindedMessagePathZNoneZ {
	let mut local_recipient_id = Vec::new(); for mut item in recipient_id.into_rust().drain(..) { local_recipient_id.push( { item }); };
	let mut local_relative_expiry = { /*relative_expiry*/ let relative_expiry_opt = relative_expiry; if relative_expiry_opt.is_none() { None } else { Some({ { core::time::Duration::from_secs({ relative_expiry_opt.take() }) }})} };
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.blinded_paths_for_async_recipient(local_recipient_id, local_relative_expiry, local_peers);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Instructions for how to respond to an `InvoiceRequest`.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum InvreqResponseInstructions {
	/// We are the recipient of this payment, and a [`Bolt12Invoice`] should be sent in response to
	/// the invoice request since it is now verified.
	SendInvoice(
		crate::lightning::offers::invoice_request::VerifiedInvoiceRequest),
	/// We are a static invoice server and should respond to this invoice request by retrieving the
	/// [`StaticInvoice`] corresponding to the `recipient_id` and `invoice_slot` and calling
	/// [`OffersMessageFlow::enqueue_static_invoice`].
	///
	/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
	SendStaticInvoice {
		/// An identifier for the async recipient for whom we are serving [`StaticInvoice`]s.
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		recipient_id: crate::c_types::derived::CVec_u8Z,
		/// The slot number for the specific invoice being requested by the payer.
		invoice_slot: u16,
		/// The invoice request that should be forwarded to the async recipient in case the
		/// recipient is online to respond. Should be forwarded by calling
		/// [`OffersMessageFlow::enqueue_invoice_request_to_forward`].
		invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest,
	},
}
use lightning::offers::flow::InvreqResponseInstructions as InvreqResponseInstructionsImport;
pub(crate) type nativeInvreqResponseInstructions = InvreqResponseInstructionsImport;

impl InvreqResponseInstructions {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeInvreqResponseInstructions {
		match self {
			InvreqResponseInstructions::SendInvoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeInvreqResponseInstructions::SendInvoice (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			InvreqResponseInstructions::SendStaticInvoice {ref recipient_id, ref invoice_slot, ref invoice_request, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.into_rust().drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut invoice_request_nonref = Clone::clone(invoice_request);
				nativeInvreqResponseInstructions::SendStaticInvoice {
					recipient_id: local_recipient_id_nonref,
					invoice_slot: invoice_slot_nonref,
					invoice_request: *unsafe { Box::from_raw(invoice_request_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeInvreqResponseInstructions {
		match self {
			InvreqResponseInstructions::SendInvoice (mut a, ) => {
				nativeInvreqResponseInstructions::SendInvoice (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			InvreqResponseInstructions::SendStaticInvoice {mut recipient_id, mut invoice_slot, mut invoice_request, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.into_rust().drain(..) { local_recipient_id.push( { item }); };
				nativeInvreqResponseInstructions::SendStaticInvoice {
					recipient_id: local_recipient_id,
					invoice_slot: invoice_slot,
					invoice_request: *unsafe { Box::from_raw(invoice_request.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &InvreqResponseInstructionsImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeInvreqResponseInstructions) };
		match native {
			nativeInvreqResponseInstructions::SendInvoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				InvreqResponseInstructions::SendInvoice (
					crate::lightning::offers::invoice_request::VerifiedInvoiceRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeInvreqResponseInstructions::SendStaticInvoice {ref recipient_id, ref invoice_slot, ref invoice_request, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut invoice_request_nonref = Clone::clone(invoice_request);
				InvreqResponseInstructions::SendStaticInvoice {
					recipient_id: local_recipient_id_nonref.into(),
					invoice_slot: invoice_slot_nonref,
					invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest { inner: ObjOps::heap_alloc(invoice_request_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeInvreqResponseInstructions) -> Self {
		match native {
			nativeInvreqResponseInstructions::SendInvoice (mut a, ) => {
				InvreqResponseInstructions::SendInvoice (
					crate::lightning::offers::invoice_request::VerifiedInvoiceRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeInvreqResponseInstructions::SendStaticInvoice {mut recipient_id, mut invoice_slot, mut invoice_request, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.drain(..) { local_recipient_id.push( { item }); };
				InvreqResponseInstructions::SendStaticInvoice {
					recipient_id: local_recipient_id.into(),
					invoice_slot: invoice_slot,
					invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest { inner: ObjOps::heap_alloc(invoice_request), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the InvreqResponseInstructions
#[no_mangle]
pub extern "C" fn InvreqResponseInstructions_free(this_ptr: InvreqResponseInstructions) { }
/// Creates a copy of the InvreqResponseInstructions
#[no_mangle]
pub extern "C" fn InvreqResponseInstructions_clone(orig: &InvreqResponseInstructions) -> InvreqResponseInstructions {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvreqResponseInstructions_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const InvreqResponseInstructions)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvreqResponseInstructions_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut InvreqResponseInstructions) };
}
#[no_mangle]
/// Utility method to constructs a new SendInvoice-variant InvreqResponseInstructions
pub extern "C" fn InvreqResponseInstructions_send_invoice(a: crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> InvreqResponseInstructions {
	InvreqResponseInstructions::SendInvoice(a, )
}
#[no_mangle]
/// Utility method to constructs a new SendStaticInvoice-variant InvreqResponseInstructions
pub extern "C" fn InvreqResponseInstructions_send_static_invoice(recipient_id: crate::c_types::derived::CVec_u8Z, invoice_slot: u16, invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest) -> InvreqResponseInstructions {
	InvreqResponseInstructions::SendStaticInvoice {
		recipient_id,
		invoice_slot,
		invoice_request,
	}
}
/// Parameters for the reply path to a [`HeldHtlcAvailable`] onion message.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum HeldHtlcReplyPath {
	/// The reply path to the [`HeldHtlcAvailable`] message should terminate at our node.
	ToUs {
		/// The id of the payment.
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The peers to use when creating this reply path.
		peers: crate::c_types::derived::CVec_MessageForwardNodeZ,
	},
	/// The reply path to the [`HeldHtlcAvailable`] message should terminate at our next-hop channel
	/// counterparty, as they are holding our HTLC until they receive the corresponding
	/// [`ReleaseHeldHtlc`] message.
	///
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	ToCounterparty {
		/// The blinded path provided to us by our counterparty.
		path: crate::lightning::blinded_path::message::BlindedMessagePath,
	},
}
use lightning::offers::flow::HeldHtlcReplyPath as HeldHtlcReplyPathImport;
pub(crate) type nativeHeldHtlcReplyPath = HeldHtlcReplyPathImport;

impl HeldHtlcReplyPath {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeHeldHtlcReplyPath {
		match self {
			HeldHtlcReplyPath::ToUs {ref payment_id, ref peers, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut peers_nonref = Clone::clone(peers);
				let mut local_peers_nonref = Vec::new(); for mut item in peers_nonref.into_rust().drain(..) { local_peers_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeHeldHtlcReplyPath::ToUs {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					peers: local_peers_nonref,
				}
			},
			HeldHtlcReplyPath::ToCounterparty {ref path, } => {
				let mut path_nonref = Clone::clone(path);
				nativeHeldHtlcReplyPath::ToCounterparty {
					path: *unsafe { Box::from_raw(path_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeHeldHtlcReplyPath {
		match self {
			HeldHtlcReplyPath::ToUs {mut payment_id, mut peers, } => {
				let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeHeldHtlcReplyPath::ToUs {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					peers: local_peers,
				}
			},
			HeldHtlcReplyPath::ToCounterparty {mut path, } => {
				nativeHeldHtlcReplyPath::ToCounterparty {
					path: *unsafe { Box::from_raw(path.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &HeldHtlcReplyPathImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeHeldHtlcReplyPath) };
		match native {
			nativeHeldHtlcReplyPath::ToUs {ref payment_id, ref peers, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut peers_nonref = Clone::clone(peers);
				let mut local_peers_nonref = Vec::new(); for mut item in peers_nonref.drain(..) { local_peers_nonref.push( { crate::lightning::blinded_path::message::MessageForwardNode { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				HeldHtlcReplyPath::ToUs {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					peers: local_peers_nonref.into(),
				}
			},
			nativeHeldHtlcReplyPath::ToCounterparty {ref path, } => {
				let mut path_nonref = Clone::clone(path);
				HeldHtlcReplyPath::ToCounterparty {
					path: crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(path_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeHeldHtlcReplyPath) -> Self {
		match native {
			nativeHeldHtlcReplyPath::ToUs {mut payment_id, mut peers, } => {
				let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::lightning::blinded_path::message::MessageForwardNode { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				HeldHtlcReplyPath::ToUs {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					peers: local_peers.into(),
				}
			},
			nativeHeldHtlcReplyPath::ToCounterparty {mut path, } => {
				HeldHtlcReplyPath::ToCounterparty {
					path: crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(path), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the HeldHtlcReplyPath
#[no_mangle]
pub extern "C" fn HeldHtlcReplyPath_free(this_ptr: HeldHtlcReplyPath) { }
/// Creates a copy of the HeldHtlcReplyPath
#[no_mangle]
pub extern "C" fn HeldHtlcReplyPath_clone(orig: &HeldHtlcReplyPath) -> HeldHtlcReplyPath {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HeldHtlcReplyPath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const HeldHtlcReplyPath)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HeldHtlcReplyPath_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut HeldHtlcReplyPath) };
}
#[no_mangle]
/// Utility method to constructs a new ToUs-variant HeldHtlcReplyPath
pub extern "C" fn HeldHtlcReplyPath_to_us(payment_id: crate::c_types::ThirtyTwoBytes, peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> HeldHtlcReplyPath {
	HeldHtlcReplyPath::ToUs {
		payment_id,
		peers,
	}
}
#[no_mangle]
/// Utility method to constructs a new ToCounterparty-variant HeldHtlcReplyPath
pub extern "C" fn HeldHtlcReplyPath_to_counterparty(path: crate::lightning::blinded_path::message::BlindedMessagePath) -> HeldHtlcReplyPath {
	HeldHtlcReplyPath::ToCounterparty {
		path,
	}
}
/// Verifies an [`InvoiceRequest`] using the provided [`OffersContext`] or the [`InvoiceRequest::metadata`].
///
/// - If an [`OffersContext::InvoiceRequest`] with a `nonce` is provided, verification is performed using recipient context data.
/// - If no context is provided but the [`InvoiceRequest`] contains [`Offer`] metadata, verification is performed using that metadata.
/// - If neither is available, verification fails.
///
/// # Errors
///
/// Returns an error if:
/// - Both [`OffersContext`] and [`InvoiceRequest`] metadata are absent or invalid.
/// - The verification process (via recipient context data or metadata) fails.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_verify_invoice_request(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest, mut context: crate::c_types::derived::COption_OffersContextZ) -> crate::c_types::derived::CResult_InvreqResponseInstructionsNoneZ {
	let mut local_context = { /*context*/ let context_opt = context; if context_opt.is_none() { None } else { Some({ { { context_opt.take() }.into_native() }})} };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify_invoice_request(*unsafe { Box::from_raw(invoice_request.take_inner()) }, local_context);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::flow::InvreqResponseInstructions::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Verifies a [`Bolt12Invoice`] using the provided [`OffersContext`] or the invoice's payer metadata,
/// returning the corresponding [`PaymentId`] if successful.
///
/// - If an [`OffersContext::OutboundPayment`] with a `nonce` is provided, verification is performed
///   using this to form the payer metadata.
/// - If no context is provided and the invoice corresponds to a [`Refund`] without blinded paths,
///   verification is performed using the [`Bolt12Invoice::payer_metadata`].
/// - If neither condition is met, verification fails.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_verify_bolt12_invoice(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, invoice: &crate::lightning::offers::invoice::Bolt12Invoice, mut context: crate::c_types::derived::COption_OffersContextZ) -> crate::c_types::derived::CResult_ThirtyTwoBytesNoneZ {
	let mut local_context_base = { /*context*/ let context_opt = context; if context_opt.is_none() { None } else { Some({ { { context_opt.take() }.into_native() }})} }; let mut local_context = local_context_base.as_ref();
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify_bolt12_invoice(invoice.get_native_ref(), local_context);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Verifies the provided [`AsyncPaymentsContext`] for an inbound [`HeldHtlcAvailable`] message.
///
/// Because blinded path contexts are verified as a part of onion message processing, this only
/// validates that the context is not yet expired based on `path_absolute_expiry`.
///
/// # Errors
///
/// Returns `Err(())` if:
/// - The inbound payment context has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_verify_inbound_async_payment_context(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut context: crate::lightning::blinded_path::message::AsyncPaymentsContext) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify_inbound_async_payment_context(context.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Creates a response for the provided [`VerifiedInvoiceRequest`].
///
/// A response can be either an [`OffersMessage::Invoice`] with additional [`MessageContext`],
/// or an [`OffersMessage::InvoiceError`], depending on the [`InvoiceRequest`].
///
/// An [`OffersMessage::InvoiceError`] will be generated if:
/// - We fail to generate valid payment paths to include in the [`Bolt12Invoice`].
/// - We fail to generate a valid signed [`Bolt12Invoice`] for the [`InvoiceRequest`].
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_create_response_for_invoice_request(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, signer: &crate::lightning::sign::NodeSigner, router: &crate::lightning::routing::router::Router, mut entropy_source: crate::lightning::sign::EntropySource, mut invoice_request: crate::lightning::offers::invoice_request::VerifiedInvoiceRequest, mut amount_msats: u64, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut payment_secret: crate::c_types::ThirtyTwoBytes, mut usable_channels: crate::c_types::derived::CVec_ChannelDetailsZ) -> crate::c_types::derived::C2Tuple_OffersMessageCOption_MessageContextZZ {
	let mut local_usable_channels = Vec::new(); for mut item in usable_channels.into_rust().drain(..) { local_usable_channels.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.create_response_for_invoice_request(signer, router, entropy_source, *unsafe { Box::from_raw(invoice_request.take_inner()) }, amount_msats, ::lightning::types::payment::PaymentHash(payment_hash.data), ::lightning::types::payment::PaymentSecret(payment_secret.data), local_usable_channels);
	let (mut orig_ret_0, mut orig_ret_1) = ret; let mut local_orig_ret_1 = if orig_ret_1.is_none() { crate::c_types::derived::COption_MessageContextZ::None } else { crate::c_types::derived::COption_MessageContextZ::Some( { crate::lightning::blinded_path::message::MessageContext::native_into(orig_ret_1.unwrap()) }) }; let mut local_ret = (crate::lightning::onion_message::offers::OffersMessage::native_into(orig_ret_0), local_orig_ret_1).into();
	local_ret
}

/// Enqueues the created [`InvoiceRequest`] to be sent to the counterparty.
///
/// # Payment
///
/// The provided `payment_id` is used to create a unique [`MessageContext`] for the
/// blinded paths sent to the counterparty. This allows them to respond with an invoice,
/// over those blinded paths, which can be verified against the intended outbound payment,
/// ensuring the invoice corresponds to a payment we actually want to make.
///
/// # Nonce
/// The nonce is used to create a unique [`MessageContext`] for the reply paths.
/// These will be used to verify the corresponding [`Bolt12Invoice`] when it is received.
///
/// Note: The provided [`Nonce`] MUST be the same as the [`Nonce`] used for creating the
/// [`InvoiceRequest`] to ensure correct verification of the corresponding [`Bolt12Invoice`].
///
/// See [`OffersMessageFlow::create_invoice_request_builder`] for more details.
///
/// # Peers
///
/// The user must provide a list of [`MessageForwardNode`] that will be used to generate
/// valid reply paths for the counterparty to send back the corresponding [`Bolt12Invoice`]
/// or [`InvoiceError`].
///
/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_enqueue_invoice_request(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest, mut payment_id: crate::c_types::ThirtyTwoBytes, mut nonce: crate::lightning::offers::nonce::Nonce, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.enqueue_invoice_request(*unsafe { Box::from_raw(invoice_request.take_inner()) }, ::lightning::ln::channelmanager::PaymentId(payment_id.data), *unsafe { Box::from_raw(nonce.take_inner()) }, local_peers);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Enqueues the created [`Bolt12Invoice`] corresponding to a [`Refund`] to be sent
/// to the counterparty.
///
/// # Peers
///
/// The user must provide a list of [`MessageForwardNode`] that will be used to generate valid
/// reply paths for the counterparty to send back the corresponding [`InvoiceError`] if we fail
/// to create blinded reply paths
///
/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_enqueue_invoice(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut invoice: crate::lightning::offers::invoice::Bolt12Invoice, refund: &crate::lightning::offers::refund::Refund, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.enqueue_invoice(*unsafe { Box::from_raw(invoice.take_inner()) }, refund.get_native_ref(), local_peers);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Forwards a [`StaticInvoice`] over the provided [`Responder`] in response to an
/// [`InvoiceRequest`] that we as a static invoice server received on behalf of an often-offline
/// recipient.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_enqueue_static_invoice(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut invoice: crate::lightning::offers::static_invoice::StaticInvoice, mut responder: crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.enqueue_static_invoice(*unsafe { Box::from_raw(invoice.take_inner()) }, *unsafe { Box::from_raw(responder.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Forwards an [`InvoiceRequest`] to the specified [`BlindedMessagePath`]. If we receive an
/// invoice request as a static invoice server on behalf of an often-offline recipient this
/// can be used to forward the request to give the recipient a chance to provide an
/// invoice if the recipient is online. The reply_path [`Responder`] provided is the path to
/// the sender where the recipient can send the invoice.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
/// [`Responder`]: crate::onion_message::messenger::Responder
#[no_mangle]
pub extern "C" fn OffersMessageFlow_enqueue_invoice_request_to_forward(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest, mut destination: crate::lightning::blinded_path::message::BlindedMessagePath, mut reply_path: crate::lightning::onion_message::messenger::Responder) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.enqueue_invoice_request_to_forward(*unsafe { Box::from_raw(invoice_request.take_inner()) }, *unsafe { Box::from_raw(destination.take_inner()) }, *unsafe { Box::from_raw(reply_path.take_inner()) })
}

/// Enqueues `held_htlc_available` onion messages to be sent to the payee via the reply paths
/// contained within the provided [`StaticInvoice`].
///
/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_enqueue_held_htlc_available(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, invoice: &crate::lightning::offers::static_invoice::StaticInvoice, mut reply_path_params: crate::lightning::offers::flow::HeldHtlcReplyPath) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.enqueue_held_htlc_available(invoice.get_native_ref(), reply_path_params.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// If we are holding an HTLC on behalf of an often-offline sender, this method allows us to
/// create a path for the sender to use as the reply path when they send the recipient a
/// [`HeldHtlcAvailable`] onion message, so the recipient's [`ReleaseHeldHtlc`] response will be
/// received to our node.
///
/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_path_for_release_held_htlc(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut intercept_id: crate::c_types::ThirtyTwoBytes, mut prev_outbound_scid_alias: u64, mut htlc_id: u64, mut entropy: crate::lightning::sign::EntropySource) -> crate::lightning::blinded_path::message::BlindedMessagePath {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.path_for_release_held_htlc(::lightning::ln::channelmanager::InterceptId(intercept_id.data), prev_outbound_scid_alias, htlc_id, entropy);
	crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Enqueues the created [`DNSSECQuery`] to be sent to the counterparty.
///
/// # Peers
///
/// The user must provide a list of [`MessageForwardNode`] that will be used to generate
/// valid reply paths for the counterparty to send back the corresponding response for
/// the [`DNSSECQuery`] message.
///
/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_enqueue_dns_onion_message(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut message: crate::lightning::onion_message::dns_resolution::DNSSECQuery, mut context: crate::lightning::blinded_path::message::DNSResolverContext, mut dns_resolvers: crate::c_types::derived::CVec_DestinationZ, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut local_dns_resolvers = Vec::new(); for mut item in dns_resolvers.into_rust().drain(..) { local_dns_resolvers.push( { item.into_native() }); };
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.enqueue_dns_onion_message(*unsafe { Box::from_raw(message.take_inner()) }, *unsafe { Box::from_raw(context.take_inner()) }, local_dns_resolvers, local_peers);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Gets the enqueued [`OffersMessage`] with their corresponding [`MessageSendInstructions`].
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_release_pending_offers_messages(this_arg: &crate::lightning::offers::flow::OffersMessageFlow) -> crate::c_types::derived::CVec_C2Tuple_OffersMessageMessageSendInstructionsZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.release_pending_offers_messages();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item; let mut local_ret_0 = (crate::lightning::onion_message::offers::OffersMessage::native_into(orig_ret_0_0), crate::lightning::onion_message::messenger::MessageSendInstructions::native_into(orig_ret_0_1)).into(); local_ret_0 }); };
	local_ret.into()
}

/// Gets the enqueued [`AsyncPaymentsMessage`] with their corresponding [`MessageSendInstructions`].
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_release_pending_async_messages(this_arg: &crate::lightning::offers::flow::OffersMessageFlow) -> crate::c_types::derived::CVec_C2Tuple_AsyncPaymentsMessageMessageSendInstructionsZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.release_pending_async_messages();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item; let mut local_ret_0 = (crate::lightning::onion_message::async_payments::AsyncPaymentsMessage::native_into(orig_ret_0_0), crate::lightning::onion_message::messenger::MessageSendInstructions::native_into(orig_ret_0_1)).into(); local_ret_0 }); };
	local_ret.into()
}

/// Gets the enqueued [`DNSResolverMessage`] with their corresponding [`MessageSendInstructions`].
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_release_pending_dns_messages(this_arg: &crate::lightning::offers::flow::OffersMessageFlow) -> crate::c_types::derived::CVec_C2Tuple_DNSResolverMessageMessageSendInstructionsZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.release_pending_dns_messages();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item; let mut local_ret_0 = (crate::lightning::onion_message::dns_resolution::DNSResolverMessage::native_into(orig_ret_0_0), crate::lightning::onion_message::messenger::MessageSendInstructions::native_into(orig_ret_0_1)).into(); local_ret_0 }); };
	local_ret.into()
}

/// Retrieve an [`Offer`] for receiving async payments as an often-offline recipient. Will only
/// return an offer if [`Self::set_paths_to_static_invoice_server`] was called and we succeeded in
/// interactively building a [`StaticInvoice`] with the static invoice server.
///
/// Returns the requested offer as well as a bool indicating whether the cache needs to be
/// persisted using [`Self::writeable_async_receive_offer_cache`].
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_get_async_receive_offer(this_arg: &crate::lightning::offers::flow::OffersMessageFlow) -> crate::c_types::derived::CResult_C2Tuple_OfferboolZNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_async_receive_offer();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::lightning::offers::offer::Offer { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, orig_ret_0_1).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sends out [`OfferPathsRequest`] and [`ServeStaticInvoice`] onion messages if we are an
/// often-offline recipient and are configured to interactively build offers and static invoices
/// with a static invoice server.
///
/// # Usage
///
/// This method should be called on peer connection and once per minute or so, to keep the offers
/// cache updated. When calling this method once per minute, SHOULD set `timer_tick_occurred` so
/// the cache can self-regulate the number of messages sent out.
///
/// Errors if we failed to create blinded reply paths when sending an [`OfferPathsRequest`] message.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_check_refresh_async_receive_offer_cache(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ, mut usable_channels: crate::c_types::derived::CVec_ChannelDetailsZ, mut entropy: crate::lightning::sign::EntropySource, mut router: crate::lightning::routing::router::Router, mut timer_tick_occurred: bool) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_usable_channels = Vec::new(); for mut item in usable_channels.into_rust().drain(..) { local_usable_channels.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.check_refresh_async_receive_offer_cache(local_peers, local_usable_channels, entropy, router, timer_tick_occurred);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Handles an incoming [`OfferPathsRequest`] onion message from an often-offline recipient who
/// wants us (the static invoice server) to serve [`StaticInvoice`]s to payers on their behalf.
/// Sends out [`OfferPaths`] onion messages in response.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_handle_offer_paths_request(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, request: &crate::lightning::onion_message::async_payments::OfferPathsRequest, mut context: crate::lightning::blinded_path::message::AsyncPaymentsContext, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::COption_C2Tuple_OfferPathsMessageContextZZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_offer_paths_request(request.get_native_ref(), context.into_native(), local_peers);
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_C2Tuple_OfferPathsMessageContextZZ::None } else { crate::c_types::derived::COption_C2Tuple_OfferPathsMessageContextZZ::Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (ret.unwrap()); let mut local_ret_0 = (crate::lightning::onion_message::async_payments::OfferPaths { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, crate::lightning::blinded_path::message::MessageContext::native_into(orig_ret_0_1)).into(); local_ret_0 }) };
	local_ret
}

/// Handles an incoming [`OfferPaths`] message from the static invoice server, sending out
/// [`ServeStaticInvoice`] onion messages in response if we've built a new async receive offer and
/// need the corresponding [`StaticInvoice`] to be persisted by the static invoice server.
///
/// Returns `None` if we have enough offers cached already, verification of `message` fails, or we
/// fail to create blinded paths.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_handle_offer_paths(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut message: crate::lightning::onion_message::async_payments::OfferPaths, mut context: crate::lightning::blinded_path::message::AsyncPaymentsContext, mut responder: crate::lightning::onion_message::messenger::Responder, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ, mut usable_channels: crate::c_types::derived::CVec_ChannelDetailsZ, mut entropy: crate::lightning::sign::EntropySource, mut router: crate::lightning::routing::router::Router) -> crate::c_types::derived::COption_C2Tuple_ServeStaticInvoiceMessageContextZZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_usable_channels = Vec::new(); for mut item in usable_channels.into_rust().drain(..) { local_usable_channels.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_offer_paths(*unsafe { Box::from_raw(message.take_inner()) }, context.into_native(), *unsafe { Box::from_raw(responder.take_inner()) }, local_peers, local_usable_channels, entropy, router);
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_C2Tuple_ServeStaticInvoiceMessageContextZZ::None } else { crate::c_types::derived::COption_C2Tuple_ServeStaticInvoiceMessageContextZZ::Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (ret.unwrap()); let mut local_ret_0 = (crate::lightning::onion_message::async_payments::ServeStaticInvoice { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, crate::lightning::blinded_path::message::MessageContext::native_into(orig_ret_0_1)).into(); local_ret_0 }) };
	local_ret
}

/// Verifies an incoming [`ServeStaticInvoice`] onion message from an often-offline recipient who
/// wants us as a static invoice server to serve the [`ServeStaticInvoice::invoice`] to payers on
/// their behalf.
///
/// On success, returns `(recipient_id, invoice_slot)` for use in persisting and later retrieving
/// the static invoice from the database.
///
/// Errors if the [`ServeStaticInvoice::invoice`] is expired or larger than
/// [`MAX_STATIC_INVOICE_SIZE_BYTES`].
///
/// [`ServeStaticInvoice::invoice`]: crate::onion_message::async_payments::ServeStaticInvoice::invoice
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_verify_serve_static_invoice_message(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, message: &crate::lightning::onion_message::async_payments::ServeStaticInvoice, mut context: crate::lightning::blinded_path::message::AsyncPaymentsContext) -> crate::c_types::derived::CResult_C2Tuple_CVec_u8Zu16ZNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify_serve_static_invoice_message(message.get_native_ref(), context.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_orig_ret_0_0 = Vec::new(); for mut item in orig_ret_0_0.drain(..) { local_orig_ret_0_0.push( { item }); }; let mut local_ret_0 = (local_orig_ret_0_0.into(), orig_ret_0_1).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Indicates that a [`ServeStaticInvoice::invoice`] has been persisted and is ready to be served
/// to payers on behalf of an often-offline recipient. This method must be called after persisting
/// a [`StaticInvoice`] to confirm to the recipient that their corresponding [`Offer`] is ready to
/// receive async payments.
#[no_mangle]
pub extern "C" fn OffersMessageFlow_static_invoice_persisted(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut responder: crate::lightning::onion_message::messenger::Responder) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.static_invoice_persisted(*unsafe { Box::from_raw(responder.take_inner()) })
}

/// Handles an incoming [`StaticInvoicePersisted`] onion message from the static invoice server.
/// Returns a bool indicating whether the async receive offer cache needs to be re-persisted using
/// [`Self::writeable_async_receive_offer_cache`].
///
/// [`StaticInvoicePersisted`]: crate::onion_message::async_payments::StaticInvoicePersisted
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_handle_static_invoice_persisted(this_arg: &crate::lightning::offers::flow::OffersMessageFlow, mut context: crate::lightning::blinded_path::message::AsyncPaymentsContext) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_static_invoice_persisted(context.into_native());
	ret
}

/// Get the encoded [`AsyncReceiveOfferCache`] for persistence.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessageFlow_writeable_async_receive_offer_cache(this_arg: &crate::lightning::offers::flow::OffersMessageFlow) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.writeable_async_receive_offer_cache();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { item }); };
	local_ret.into()
}

