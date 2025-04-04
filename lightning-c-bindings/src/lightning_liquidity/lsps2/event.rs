// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains bLIP-52 / LSPS2 event types

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An event which an LSPS2 client should take some action in response to.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS2ClientEvent {
	/// Information from the LSP about their current fee rates and channel parameters.
	///
	/// You must call [`LSPS2ClientHandler::select_opening_params`] with the fee parameter
	/// you want to use if you wish to proceed opening a channel.
	///
	/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
	OpeningParametersReady {
		/// The identifier of the issued bLIP-52 / LSPS2 `get_info` request, as returned by
		/// [`LSPS2ClientHandler::request_opening_params`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::request_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::request_opening_params
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The menu of fee parameters the LSP is offering at this time.
		/// You must select one of these if you wish to proceed.
		opening_fee_params_menu: crate::c_types::derived::CVec_LSPS2OpeningFeeParamsZ,
	},
	/// Provides the necessary information to generate a payable invoice that then may be given to
	/// the payer.
	///
	/// When the invoice is paid, the LSP will open a channel with the previously agreed upon
	/// parameters to you.
	InvoiceParametersReady {
		/// The identifier of the issued bLIP-52 / LSPS2 `buy` request, as returned by
		/// [`LSPS2ClientHandler::select_opening_params`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The intercept short channel id to use in the route hint.
		intercept_scid: u64,
		/// The `cltv_expiry_delta` to use in the route hint.
		cltv_expiry_delta: u32,
		/// The initial payment size you specified.
		payment_size_msat: crate::c_types::derived::COption_u64Z,
	},
}
use lightning_liquidity::lsps2::event::LSPS2ClientEvent as LSPS2ClientEventImport;
pub(crate) type nativeLSPS2ClientEvent = LSPS2ClientEventImport;

impl LSPS2ClientEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS2ClientEvent {
		match self {
			LSPS2ClientEvent::OpeningParametersReady {ref request_id, ref counterparty_node_id, ref opening_fee_params_menu, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut opening_fee_params_menu_nonref = Clone::clone(opening_fee_params_menu);
				let mut local_opening_fee_params_menu_nonref = Vec::new(); for mut item in opening_fee_params_menu_nonref.into_rust().drain(..) { local_opening_fee_params_menu_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeLSPS2ClientEvent::OpeningParametersReady {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					opening_fee_params_menu: local_opening_fee_params_menu_nonref,
				}
			},
			LSPS2ClientEvent::InvoiceParametersReady {ref request_id, ref counterparty_node_id, ref intercept_scid, ref cltv_expiry_delta, ref payment_size_msat, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut intercept_scid_nonref = Clone::clone(intercept_scid);
				let mut cltv_expiry_delta_nonref = Clone::clone(cltv_expiry_delta);
				let mut payment_size_msat_nonref = Clone::clone(payment_size_msat);
				let mut local_payment_size_msat_nonref = if payment_size_msat_nonref.is_some() { Some( { payment_size_msat_nonref.take() }) } else { None };
				nativeLSPS2ClientEvent::InvoiceParametersReady {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					intercept_scid: intercept_scid_nonref,
					cltv_expiry_delta: cltv_expiry_delta_nonref,
					payment_size_msat: local_payment_size_msat_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS2ClientEvent {
		match self {
			LSPS2ClientEvent::OpeningParametersReady {mut request_id, mut counterparty_node_id, mut opening_fee_params_menu, } => {
				let mut local_opening_fee_params_menu = Vec::new(); for mut item in opening_fee_params_menu.into_rust().drain(..) { local_opening_fee_params_menu.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeLSPS2ClientEvent::OpeningParametersReady {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					opening_fee_params_menu: local_opening_fee_params_menu,
				}
			},
			LSPS2ClientEvent::InvoiceParametersReady {mut request_id, mut counterparty_node_id, mut intercept_scid, mut cltv_expiry_delta, mut payment_size_msat, } => {
				let mut local_payment_size_msat = if payment_size_msat.is_some() { Some( { payment_size_msat.take() }) } else { None };
				nativeLSPS2ClientEvent::InvoiceParametersReady {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					intercept_scid: intercept_scid,
					cltv_expiry_delta: cltv_expiry_delta,
					payment_size_msat: local_payment_size_msat,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS2ClientEventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS2ClientEvent) };
		match native {
			nativeLSPS2ClientEvent::OpeningParametersReady {ref request_id, ref counterparty_node_id, ref opening_fee_params_menu, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut opening_fee_params_menu_nonref = Clone::clone(opening_fee_params_menu);
				let mut local_opening_fee_params_menu_nonref = Vec::new(); for mut item in opening_fee_params_menu_nonref.drain(..) { local_opening_fee_params_menu_nonref.push( { crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				LSPS2ClientEvent::OpeningParametersReady {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					opening_fee_params_menu: local_opening_fee_params_menu_nonref.into(),
				}
			},
			nativeLSPS2ClientEvent::InvoiceParametersReady {ref request_id, ref counterparty_node_id, ref intercept_scid, ref cltv_expiry_delta, ref payment_size_msat, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut intercept_scid_nonref = Clone::clone(intercept_scid);
				let mut cltv_expiry_delta_nonref = Clone::clone(cltv_expiry_delta);
				let mut payment_size_msat_nonref = Clone::clone(payment_size_msat);
				let mut local_payment_size_msat_nonref = if payment_size_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { payment_size_msat_nonref.unwrap() }) };
				LSPS2ClientEvent::InvoiceParametersReady {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					intercept_scid: intercept_scid_nonref,
					cltv_expiry_delta: cltv_expiry_delta_nonref,
					payment_size_msat: local_payment_size_msat_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS2ClientEvent) -> Self {
		match native {
			nativeLSPS2ClientEvent::OpeningParametersReady {mut request_id, mut counterparty_node_id, mut opening_fee_params_menu, } => {
				let mut local_opening_fee_params_menu = Vec::new(); for mut item in opening_fee_params_menu.drain(..) { local_opening_fee_params_menu.push( { crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				LSPS2ClientEvent::OpeningParametersReady {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					opening_fee_params_menu: local_opening_fee_params_menu.into(),
				}
			},
			nativeLSPS2ClientEvent::InvoiceParametersReady {mut request_id, mut counterparty_node_id, mut intercept_scid, mut cltv_expiry_delta, mut payment_size_msat, } => {
				let mut local_payment_size_msat = if payment_size_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { payment_size_msat.unwrap() }) };
				LSPS2ClientEvent::InvoiceParametersReady {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					intercept_scid: intercept_scid,
					cltv_expiry_delta: cltv_expiry_delta,
					payment_size_msat: local_payment_size_msat,
				}
			},
		}
	}
}
/// Frees any resources used by the LSPS2ClientEvent
#[no_mangle]
pub extern "C" fn LSPS2ClientEvent_free(this_ptr: LSPS2ClientEvent) { }
/// Creates a copy of the LSPS2ClientEvent
#[no_mangle]
pub extern "C" fn LSPS2ClientEvent_clone(orig: &LSPS2ClientEvent) -> LSPS2ClientEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ClientEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS2ClientEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ClientEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS2ClientEvent) };
}
#[no_mangle]
/// Utility method to constructs a new OpeningParametersReady-variant LSPS2ClientEvent
pub extern "C" fn LSPS2ClientEvent_opening_parameters_ready(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, opening_fee_params_menu: crate::c_types::derived::CVec_LSPS2OpeningFeeParamsZ) -> LSPS2ClientEvent {
	LSPS2ClientEvent::OpeningParametersReady {
		request_id,
		counterparty_node_id,
		opening_fee_params_menu,
	}
}
#[no_mangle]
/// Utility method to constructs a new InvoiceParametersReady-variant LSPS2ClientEvent
pub extern "C" fn LSPS2ClientEvent_invoice_parameters_ready(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, intercept_scid: u64, cltv_expiry_delta: u32, payment_size_msat: crate::c_types::derived::COption_u64Z) -> LSPS2ClientEvent {
	LSPS2ClientEvent::InvoiceParametersReady {
		request_id,
		counterparty_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
	}
}
/// Get a string which allows debug introspection of a LSPS2ClientEvent object
pub extern "C" fn LSPS2ClientEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::event::LSPS2ClientEvent }).into()}
/// Checks if two LSPS2ClientEvents contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS2ClientEvent_eq(a: &LSPS2ClientEvent, b: &LSPS2ClientEvent) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An event which an bLIP-52 / LSPS2 server should take some action in response to.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS2ServiceEvent {
	/// A request from a client for information about JIT Channel parameters.
	///
	/// You must calculate the parameters for this client and pass them to
	/// [`LSPS2ServiceHandler::opening_fee_params_generated`].
	///
	/// If an unrecognized or stale token is provided you can use
	/// `[LSPS2ServiceHandler::invalid_token_provided`] to error the request.
	///
	/// [`LSPS2ServiceHandler::opening_fee_params_generated`]: crate::lsps2::service::LSPS2ServiceHandler::opening_fee_params_generated
	/// [`LSPS2ServiceHandler::invalid_token_provided`]: crate::lsps2::service::LSPS2ServiceHandler::invalid_token_provided
	GetInfo {
		/// An identifier that must be passed to [`LSPS2ServiceHandler::opening_fee_params_generated`].
		///
		/// [`LSPS2ServiceHandler::opening_fee_params_generated`]: crate::lsps2::service::LSPS2ServiceHandler::opening_fee_params_generated
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The node id of the client making the information request.
		counterparty_node_id: crate::c_types::PublicKey,
		/// An optional token that can be used as an API key, coupon code, etc.
		token: crate::c_types::derived::COption_StrZ,
	},
	/// A client has selected a opening fee parameter to use and would like to
	/// purchase a channel with an optional initial payment size.
	///
	/// If `payment_size_msat` is [`Option::Some`] then the payer is allowed to use MPP.
	/// If `payment_size_msat` is [`Option::None`] then the payer cannot use MPP.
	///
	/// You must generate an intercept scid and `cltv_expiry_delta` for them to use
	/// and call [`LSPS2ServiceHandler::invoice_parameters_generated`].
	///
	/// [`LSPS2ServiceHandler::invoice_parameters_generated`]: crate::lsps2::service::LSPS2ServiceHandler::invoice_parameters_generated
	BuyRequest {
		/// An identifier that must be passed into [`LSPS2ServiceHandler::invoice_parameters_generated`].
		///
		/// [`LSPS2ServiceHandler::invoice_parameters_generated`]: crate::lsps2::service::LSPS2ServiceHandler::invoice_parameters_generated
		request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId,
		/// The client node id that is making this request.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The channel parameters they have selected.
		opening_fee_params: crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams,
		/// The size of the initial payment they would like to receive.
		payment_size_msat: crate::c_types::derived::COption_u64Z,
	},
	/// You should open a channel using [`ChannelManager::create_channel`].
	///
	/// [`ChannelManager::create_channel`]: lightning::ln::channelmanager::ChannelManager::create_channel
	OpenChannel {
		/// The node to open channel with.
		their_network_key: crate::c_types::PublicKey,
		/// The amount to forward after fees.
		amt_to_forward_msat: u64,
		/// The fee earned for opening the channel.
		opening_fee_msat: u64,
		/// A user specified id used to track channel open.
		user_channel_id: crate::c_types::U128,
		/// The intercept short channel id to use in the route hint.
		intercept_scid: u64,
	},
}
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent as LSPS2ServiceEventImport;
pub(crate) type nativeLSPS2ServiceEvent = LSPS2ServiceEventImport;

impl LSPS2ServiceEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS2ServiceEvent {
		match self {
			LSPS2ServiceEvent::GetInfo {ref request_id, ref counterparty_node_id, ref token, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut token_nonref = Clone::clone(token);
				let mut local_token_nonref = { /*token_nonref*/ let token_nonref_opt = token_nonref; if token_nonref_opt.is_none() { None } else { Some({ { { token_nonref_opt.take() }.into_string() }})} };
				nativeLSPS2ServiceEvent::GetInfo {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					token: local_token_nonref,
				}
			},
			LSPS2ServiceEvent::BuyRequest {ref request_id, ref counterparty_node_id, ref opening_fee_params, ref payment_size_msat, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut opening_fee_params_nonref = Clone::clone(opening_fee_params);
				let mut payment_size_msat_nonref = Clone::clone(payment_size_msat);
				let mut local_payment_size_msat_nonref = if payment_size_msat_nonref.is_some() { Some( { payment_size_msat_nonref.take() }) } else { None };
				nativeLSPS2ServiceEvent::BuyRequest {
					request_id: *unsafe { Box::from_raw(request_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					opening_fee_params: *unsafe { Box::from_raw(opening_fee_params_nonref.take_inner()) },
					payment_size_msat: local_payment_size_msat_nonref,
				}
			},
			LSPS2ServiceEvent::OpenChannel {ref their_network_key, ref amt_to_forward_msat, ref opening_fee_msat, ref user_channel_id, ref intercept_scid, } => {
				let mut their_network_key_nonref = Clone::clone(their_network_key);
				let mut amt_to_forward_msat_nonref = Clone::clone(amt_to_forward_msat);
				let mut opening_fee_msat_nonref = Clone::clone(opening_fee_msat);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut intercept_scid_nonref = Clone::clone(intercept_scid);
				nativeLSPS2ServiceEvent::OpenChannel {
					their_network_key: their_network_key_nonref.into_rust(),
					amt_to_forward_msat: amt_to_forward_msat_nonref,
					opening_fee_msat: opening_fee_msat_nonref,
					user_channel_id: user_channel_id_nonref.into(),
					intercept_scid: intercept_scid_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS2ServiceEvent {
		match self {
			LSPS2ServiceEvent::GetInfo {mut request_id, mut counterparty_node_id, mut token, } => {
				let mut local_token = { /*token*/ let token_opt = token; if token_opt.is_none() { None } else { Some({ { { token_opt.take() }.into_string() }})} };
				nativeLSPS2ServiceEvent::GetInfo {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					token: local_token,
				}
			},
			LSPS2ServiceEvent::BuyRequest {mut request_id, mut counterparty_node_id, mut opening_fee_params, mut payment_size_msat, } => {
				let mut local_payment_size_msat = if payment_size_msat.is_some() { Some( { payment_size_msat.take() }) } else { None };
				nativeLSPS2ServiceEvent::BuyRequest {
					request_id: *unsafe { Box::from_raw(request_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					opening_fee_params: *unsafe { Box::from_raw(opening_fee_params.take_inner()) },
					payment_size_msat: local_payment_size_msat,
				}
			},
			LSPS2ServiceEvent::OpenChannel {mut their_network_key, mut amt_to_forward_msat, mut opening_fee_msat, mut user_channel_id, mut intercept_scid, } => {
				nativeLSPS2ServiceEvent::OpenChannel {
					their_network_key: their_network_key.into_rust(),
					amt_to_forward_msat: amt_to_forward_msat,
					opening_fee_msat: opening_fee_msat,
					user_channel_id: user_channel_id.into(),
					intercept_scid: intercept_scid,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS2ServiceEventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS2ServiceEvent) };
		match native {
			nativeLSPS2ServiceEvent::GetInfo {ref request_id, ref counterparty_node_id, ref token, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut token_nonref = Clone::clone(token);
				let mut local_token_nonref = if token_nonref.is_none() { crate::c_types::derived::COption_StrZ::None } else { crate::c_types::derived::COption_StrZ::Some( { token_nonref.unwrap().into() }) };
				LSPS2ServiceEvent::GetInfo {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					token: local_token_nonref,
				}
			},
			nativeLSPS2ServiceEvent::BuyRequest {ref request_id, ref counterparty_node_id, ref opening_fee_params, ref payment_size_msat, } => {
				let mut request_id_nonref = Clone::clone(request_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut opening_fee_params_nonref = Clone::clone(opening_fee_params);
				let mut payment_size_msat_nonref = Clone::clone(payment_size_msat);
				let mut local_payment_size_msat_nonref = if payment_size_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { payment_size_msat_nonref.unwrap() }) };
				LSPS2ServiceEvent::BuyRequest {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					opening_fee_params: crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams { inner: ObjOps::heap_alloc(opening_fee_params_nonref), is_owned: true },
					payment_size_msat: local_payment_size_msat_nonref,
				}
			},
			nativeLSPS2ServiceEvent::OpenChannel {ref their_network_key, ref amt_to_forward_msat, ref opening_fee_msat, ref user_channel_id, ref intercept_scid, } => {
				let mut their_network_key_nonref = Clone::clone(their_network_key);
				let mut amt_to_forward_msat_nonref = Clone::clone(amt_to_forward_msat);
				let mut opening_fee_msat_nonref = Clone::clone(opening_fee_msat);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut intercept_scid_nonref = Clone::clone(intercept_scid);
				LSPS2ServiceEvent::OpenChannel {
					their_network_key: crate::c_types::PublicKey::from_rust(&their_network_key_nonref),
					amt_to_forward_msat: amt_to_forward_msat_nonref,
					opening_fee_msat: opening_fee_msat_nonref,
					user_channel_id: user_channel_id_nonref.into(),
					intercept_scid: intercept_scid_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS2ServiceEvent) -> Self {
		match native {
			nativeLSPS2ServiceEvent::GetInfo {mut request_id, mut counterparty_node_id, mut token, } => {
				let mut local_token = if token.is_none() { crate::c_types::derived::COption_StrZ::None } else { crate::c_types::derived::COption_StrZ::Some( { token.unwrap().into() }) };
				LSPS2ServiceEvent::GetInfo {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					token: local_token,
				}
			},
			nativeLSPS2ServiceEvent::BuyRequest {mut request_id, mut counterparty_node_id, mut opening_fee_params, mut payment_size_msat, } => {
				let mut local_payment_size_msat = if payment_size_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { payment_size_msat.unwrap() }) };
				LSPS2ServiceEvent::BuyRequest {
					request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(request_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					opening_fee_params: crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams { inner: ObjOps::heap_alloc(opening_fee_params), is_owned: true },
					payment_size_msat: local_payment_size_msat,
				}
			},
			nativeLSPS2ServiceEvent::OpenChannel {mut their_network_key, mut amt_to_forward_msat, mut opening_fee_msat, mut user_channel_id, mut intercept_scid, } => {
				LSPS2ServiceEvent::OpenChannel {
					their_network_key: crate::c_types::PublicKey::from_rust(&their_network_key),
					amt_to_forward_msat: amt_to_forward_msat,
					opening_fee_msat: opening_fee_msat,
					user_channel_id: user_channel_id.into(),
					intercept_scid: intercept_scid,
				}
			},
		}
	}
}
/// Frees any resources used by the LSPS2ServiceEvent
#[no_mangle]
pub extern "C" fn LSPS2ServiceEvent_free(this_ptr: LSPS2ServiceEvent) { }
/// Creates a copy of the LSPS2ServiceEvent
#[no_mangle]
pub extern "C" fn LSPS2ServiceEvent_clone(orig: &LSPS2ServiceEvent) -> LSPS2ServiceEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ServiceEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS2ServiceEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ServiceEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS2ServiceEvent) };
}
#[no_mangle]
/// Utility method to constructs a new GetInfo-variant LSPS2ServiceEvent
pub extern "C" fn LSPS2ServiceEvent_get_info(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, token: crate::c_types::derived::COption_StrZ) -> LSPS2ServiceEvent {
	LSPS2ServiceEvent::GetInfo {
		request_id,
		counterparty_node_id,
		token,
	}
}
#[no_mangle]
/// Utility method to constructs a new BuyRequest-variant LSPS2ServiceEvent
pub extern "C" fn LSPS2ServiceEvent_buy_request(request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, counterparty_node_id: crate::c_types::PublicKey, opening_fee_params: crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams, payment_size_msat: crate::c_types::derived::COption_u64Z) -> LSPS2ServiceEvent {
	LSPS2ServiceEvent::BuyRequest {
		request_id,
		counterparty_node_id,
		opening_fee_params,
		payment_size_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new OpenChannel-variant LSPS2ServiceEvent
pub extern "C" fn LSPS2ServiceEvent_open_channel(their_network_key: crate::c_types::PublicKey, amt_to_forward_msat: u64, opening_fee_msat: u64, user_channel_id: crate::c_types::U128, intercept_scid: u64) -> LSPS2ServiceEvent {
	LSPS2ServiceEvent::OpenChannel {
		their_network_key,
		amt_to_forward_msat,
		opening_fee_msat,
		user_channel_id,
		intercept_scid,
	}
}
/// Get a string which allows debug introspection of a LSPS2ServiceEvent object
pub extern "C" fn LSPS2ServiceEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::event::LSPS2ServiceEvent }).into()}
/// Checks if two LSPS2ServiceEvents contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS2ServiceEvent_eq(a: &LSPS2ServiceEvent, b: &LSPS2ServiceEvent) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
