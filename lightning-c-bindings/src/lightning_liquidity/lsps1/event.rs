// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains bLIP-51 / LSPS1 event types

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An event which an bLIP-51 / LSPS1 client should take some action in response to.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS1ClientEvent {
	/// A request previously issued via [`LSPS1ClientHandler::request_supported_options`]
	/// succeeded as the LSP returned the options it supports.
	///
	/// You must check whether LSP supports the parameters the client wants and then call
	/// [`LSPS1ClientHandler::create_order`] to place an order.
	///
	/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
	/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
	SupportedOptionsReady {
		/// The identifier of the issued bLIP-51 / LSPS1 `get_info` request, as returned by
		/// [`LSPS1ClientHandler::request_supported_options`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: crate::c_types::PublicKey,
		/// All options supported by the LSP.
		supported_options: crate::lightning_liquidity::lsps1::msgs::LSPS1Options,
	},
	/// A request previously issued via [`LSPS1ClientHandler::request_supported_options`]
	/// failed as the LSP returned an error response.
	///
	/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
	SupportedOptionsRequestFailed {
		/// The identifier of the issued bLIP-51 / LSPS1 `get_info` request, as returned by
		/// [`LSPS1ClientHandler::request_supported_options`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The error that was returned.
		error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError,
	},
	/// Confirmation from the LSP about the order created by the client.
	///
	/// When the payment is confirmed, the LSP will open a channel to you
	/// with the below agreed upon parameters.
	///
	/// You must pay the invoice or onchain address if you want to continue and then
	/// call [`LSPS1ClientHandler::check_order_status`] with the order id
	/// to get information from LSP about progress of the order.
	///
	/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
	OrderCreated {
		/// The identifier of the issued bLIP-51 / LSPS1 `create_order` request, as returned by
		/// [`LSPS1ClientHandler::create_order`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The id of the channel order.
		order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId,
		/// The order created by client and approved by LSP.
		order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams,
		/// The details regarding payment of the order
		payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo,
		/// The details regarding state of the channel ordered.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		channel: crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo,
	},
	/// Information from the LSP about the status of a previously created order.
	///
	/// Will be emitted in response to calling [`LSPS1ClientHandler::check_order_status`].
	///
	/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
	OrderStatus {
		/// The identifier of the issued bLIP-51 / LSPS1 `get_order` request, as returned by
		/// [`LSPS1ClientHandler::check_order_status`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The id of the channel order.
		order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId,
		/// The order created by client and approved by LSP.
		order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams,
		/// The details regarding payment of the order
		payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo,
		/// The details regarding state of the channel ordered.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		channel: crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo,
	},
	/// A request previously issued via [`LSPS1ClientHandler::create_order`] or [`LSPS1ClientHandler::check_order_status`].
	/// failed as the LSP returned an error response.
	///
	/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
	/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
	OrderRequestFailed {
		/// The identifier of the issued LSPS1 `create_order` or `get_order` request, as returned by
		/// [`LSPS1ClientHandler::create_order`] or [`LSPS1ClientHandler::check_order_status`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
		/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The error that was returned.
		error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError,
	},
}
use lightning_liquidity::lsps1::event::LSPS1ClientEvent as LSPS1ClientEventImport;
pub(crate) type nativeLSPS1ClientEvent = LSPS1ClientEventImport;

impl LSPS1ClientEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS1ClientEvent {
		match self {
			LSPS1ClientEvent::SupportedOptionsReady {ref request_id, ref counterparty_node_id, ref supported_options, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut supported_options_nonref = Clone::clone(supported_options);
				nativeLSPS1ClientEvent::SupportedOptionsReady {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					supported_options: *unsafe { Box::from_raw(supported_options_nonref.take_inner()) },
				}
			},
			LSPS1ClientEvent::SupportedOptionsRequestFailed {ref request_id, ref counterparty_node_id, ref error, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut error_nonref = Clone::clone(error);
				nativeLSPS1ClientEvent::SupportedOptionsRequestFailed {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					error: *unsafe { Box::from_raw(error_nonref.take_inner()) },
				}
			},
			LSPS1ClientEvent::OrderCreated {ref request_id, ref counterparty_node_id, ref order_id, ref order, ref payment, ref channel, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut order_id_nonref = Clone::clone(order_id);
				let mut order_nonref = Clone::clone(order);
				let mut payment_nonref = Clone::clone(payment);
				let mut channel_nonref = Clone::clone(channel);
				let mut local_channel_nonref = if channel_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_nonref.take_inner()) } }) };
				nativeLSPS1ClientEvent::OrderCreated {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					order_id: *unsafe { Box::from_raw(order_id_nonref.take_inner()) },
					order: *unsafe { Box::from_raw(order_nonref.take_inner()) },
					payment: *unsafe { Box::from_raw(payment_nonref.take_inner()) },
					channel: local_channel_nonref,
				}
			},
			LSPS1ClientEvent::OrderStatus {ref request_id, ref counterparty_node_id, ref order_id, ref order, ref payment, ref channel, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut order_id_nonref = Clone::clone(order_id);
				let mut order_nonref = Clone::clone(order);
				let mut payment_nonref = Clone::clone(payment);
				let mut channel_nonref = Clone::clone(channel);
				let mut local_channel_nonref = if channel_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_nonref.take_inner()) } }) };
				nativeLSPS1ClientEvent::OrderStatus {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					order_id: *unsafe { Box::from_raw(order_id_nonref.take_inner()) },
					order: *unsafe { Box::from_raw(order_nonref.take_inner()) },
					payment: *unsafe { Box::from_raw(payment_nonref.take_inner()) },
					channel: local_channel_nonref,
				}
			},
			LSPS1ClientEvent::OrderRequestFailed {ref request_id, ref counterparty_node_id, ref error, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut error_nonref = Clone::clone(error);
				nativeLSPS1ClientEvent::OrderRequestFailed {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					error: *unsafe { Box::from_raw(error_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS1ClientEvent {
		match self {
			LSPS1ClientEvent::SupportedOptionsReady {mut request_id, mut counterparty_node_id, mut supported_options, } => {
				nativeLSPS1ClientEvent::SupportedOptionsReady {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					supported_options: *unsafe { Box::from_raw(supported_options.take_inner()) },
				}
			},
			LSPS1ClientEvent::SupportedOptionsRequestFailed {mut request_id, mut counterparty_node_id, mut error, } => {
				nativeLSPS1ClientEvent::SupportedOptionsRequestFailed {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					error: *unsafe { Box::from_raw(error.take_inner()) },
				}
			},
			LSPS1ClientEvent::OrderCreated {mut request_id, mut counterparty_node_id, mut order_id, mut order, mut payment, mut channel, } => {
				let mut local_channel = if channel.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel.take_inner()) } }) };
				nativeLSPS1ClientEvent::OrderCreated {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					order_id: *unsafe { Box::from_raw(order_id.take_inner()) },
					order: *unsafe { Box::from_raw(order.take_inner()) },
					payment: *unsafe { Box::from_raw(payment.take_inner()) },
					channel: local_channel,
				}
			},
			LSPS1ClientEvent::OrderStatus {mut request_id, mut counterparty_node_id, mut order_id, mut order, mut payment, mut channel, } => {
				let mut local_channel = if channel.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel.take_inner()) } }) };
				nativeLSPS1ClientEvent::OrderStatus {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					order_id: *unsafe { Box::from_raw(order_id.take_inner()) },
					order: *unsafe { Box::from_raw(order.take_inner()) },
					payment: *unsafe { Box::from_raw(payment.take_inner()) },
					channel: local_channel,
				}
			},
			LSPS1ClientEvent::OrderRequestFailed {mut request_id, mut counterparty_node_id, mut error, } => {
				nativeLSPS1ClientEvent::OrderRequestFailed {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					error: *unsafe { Box::from_raw(error.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS1ClientEventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS1ClientEvent) };
		match native {
			nativeLSPS1ClientEvent::SupportedOptionsReady {ref request_id, ref counterparty_node_id, ref supported_options, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut supported_options_nonref = Clone::clone(supported_options);
				LSPS1ClientEvent::SupportedOptionsReady {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					supported_options: crate::lightning_liquidity::lsps1::msgs::LSPS1Options { inner: ObjOps::heap_alloc(supported_options_nonref), is_owned: true },
				}
			},
			nativeLSPS1ClientEvent::SupportedOptionsRequestFailed {ref request_id, ref counterparty_node_id, ref error, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut error_nonref = Clone::clone(error);
				LSPS1ClientEvent::SupportedOptionsRequestFailed {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(error_nonref), is_owned: true },
				}
			},
			nativeLSPS1ClientEvent::OrderCreated {ref request_id, ref counterparty_node_id, ref order_id, ref order, ref payment, ref channel, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut order_id_nonref = Clone::clone(order_id);
				let mut order_nonref = Clone::clone(order);
				let mut payment_nonref = Clone::clone(payment);
				let mut channel_nonref = Clone::clone(channel);
				let mut local_channel_nonref = crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo { inner: if channel_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_nonref.unwrap())) } }, is_owned: true };
				LSPS1ClientEvent::OrderCreated {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId { inner: ObjOps::heap_alloc(order_id_nonref), is_owned: true },
					order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams { inner: ObjOps::heap_alloc(order_nonref), is_owned: true },
					payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo { inner: ObjOps::heap_alloc(payment_nonref), is_owned: true },
					channel: local_channel_nonref,
				}
			},
			nativeLSPS1ClientEvent::OrderStatus {ref request_id, ref counterparty_node_id, ref order_id, ref order, ref payment, ref channel, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut order_id_nonref = Clone::clone(order_id);
				let mut order_nonref = Clone::clone(order);
				let mut payment_nonref = Clone::clone(payment);
				let mut channel_nonref = Clone::clone(channel);
				let mut local_channel_nonref = crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo { inner: if channel_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_nonref.unwrap())) } }, is_owned: true };
				LSPS1ClientEvent::OrderStatus {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId { inner: ObjOps::heap_alloc(order_id_nonref), is_owned: true },
					order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams { inner: ObjOps::heap_alloc(order_nonref), is_owned: true },
					payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo { inner: ObjOps::heap_alloc(payment_nonref), is_owned: true },
					channel: local_channel_nonref,
				}
			},
			nativeLSPS1ClientEvent::OrderRequestFailed {ref request_id, ref counterparty_node_id, ref error, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut error_nonref = Clone::clone(error);
				LSPS1ClientEvent::OrderRequestFailed {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(error_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS1ClientEvent) -> Self {
		match native {
			nativeLSPS1ClientEvent::SupportedOptionsReady {mut request_id, mut counterparty_node_id, mut supported_options, } => {
				LSPS1ClientEvent::SupportedOptionsReady {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					supported_options: crate::lightning_liquidity::lsps1::msgs::LSPS1Options { inner: ObjOps::heap_alloc(supported_options), is_owned: true },
				}
			},
			nativeLSPS1ClientEvent::SupportedOptionsRequestFailed {mut request_id, mut counterparty_node_id, mut error, } => {
				LSPS1ClientEvent::SupportedOptionsRequestFailed {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(error), is_owned: true },
				}
			},
			nativeLSPS1ClientEvent::OrderCreated {mut request_id, mut counterparty_node_id, mut order_id, mut order, mut payment, mut channel, } => {
				let mut local_channel = crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo { inner: if channel.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel.unwrap())) } }, is_owned: true };
				LSPS1ClientEvent::OrderCreated {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId { inner: ObjOps::heap_alloc(order_id), is_owned: true },
					order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams { inner: ObjOps::heap_alloc(order), is_owned: true },
					payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo { inner: ObjOps::heap_alloc(payment), is_owned: true },
					channel: local_channel,
				}
			},
			nativeLSPS1ClientEvent::OrderStatus {mut request_id, mut counterparty_node_id, mut order_id, mut order, mut payment, mut channel, } => {
				let mut local_channel = crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo { inner: if channel.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel.unwrap())) } }, is_owned: true };
				LSPS1ClientEvent::OrderStatus {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId { inner: ObjOps::heap_alloc(order_id), is_owned: true },
					order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams { inner: ObjOps::heap_alloc(order), is_owned: true },
					payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo { inner: ObjOps::heap_alloc(payment), is_owned: true },
					channel: local_channel,
				}
			},
			nativeLSPS1ClientEvent::OrderRequestFailed {mut request_id, mut counterparty_node_id, mut error, } => {
				LSPS1ClientEvent::OrderRequestFailed {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError { inner: ObjOps::heap_alloc(error), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the LSPS1ClientEvent
#[no_mangle]
pub extern "C" fn LSPS1ClientEvent_free(this_ptr: LSPS1ClientEvent) { }
/// Creates a copy of the LSPS1ClientEvent
#[no_mangle]
pub extern "C" fn LSPS1ClientEvent_clone(orig: &LSPS1ClientEvent) -> LSPS1ClientEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1ClientEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS1ClientEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1ClientEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS1ClientEvent) };
}
#[no_mangle]
/// Utility method to constructs a new SupportedOptionsReady-variant LSPS1ClientEvent
pub extern "C" fn LSPS1ClientEvent_supported_options_ready(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, supported_options: crate::lightning_liquidity::lsps1::msgs::LSPS1Options) -> LSPS1ClientEvent {
	LSPS1ClientEvent::SupportedOptionsReady {
		request_id,
		counterparty_node_id,
		supported_options,
	}
}
#[no_mangle]
/// Utility method to constructs a new SupportedOptionsRequestFailed-variant LSPS1ClientEvent
pub extern "C" fn LSPS1ClientEvent_supported_options_request_failed(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS1ClientEvent {
	LSPS1ClientEvent::SupportedOptionsRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}
}
#[no_mangle]
/// Utility method to constructs a new OrderCreated-variant LSPS1ClientEvent
pub extern "C" fn LSPS1ClientEvent_order_created(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId, order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams, payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo, channel: crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo) -> LSPS1ClientEvent {
	LSPS1ClientEvent::OrderCreated {
		request_id,
		counterparty_node_id,
		order_id,
		order,
		payment,
		channel,
	}
}
#[no_mangle]
/// Utility method to constructs a new OrderStatus-variant LSPS1ClientEvent
pub extern "C" fn LSPS1ClientEvent_order_status(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId, order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams, payment: crate::lightning_liquidity::lsps1::msgs::LSPS1PaymentInfo, channel: crate::lightning_liquidity::lsps1::msgs::LSPS1ChannelInfo) -> LSPS1ClientEvent {
	LSPS1ClientEvent::OrderStatus {
		request_id,
		counterparty_node_id,
		order_id,
		order,
		payment,
		channel,
	}
}
#[no_mangle]
/// Utility method to constructs a new OrderRequestFailed-variant LSPS1ClientEvent
pub extern "C" fn LSPS1ClientEvent_order_request_failed(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, error: crate::lightning_liquidity::lsps0::ser::LSPSResponseError) -> LSPS1ClientEvent {
	LSPS1ClientEvent::OrderRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}
}
/// Get a string which allows debug introspection of a LSPS1ClientEvent object
pub extern "C" fn LSPS1ClientEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::event::LSPS1ClientEvent }).into()}
/// Checks if two LSPS1ClientEvents contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS1ClientEvent_eq(a: &LSPS1ClientEvent, b: &LSPS1ClientEvent) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
