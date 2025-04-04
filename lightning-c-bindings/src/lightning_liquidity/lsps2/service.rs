// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains the main bLIP-52 / LSPS2 server-side object, [`LSPS2ServiceHandler`].

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::lsps2::service::LSPS2ServiceConfig as nativeLSPS2ServiceConfigImport;
pub(crate) type nativeLSPS2ServiceConfig = nativeLSPS2ServiceConfigImport;

/// Server-side configuration options for JIT channels.
#[must_use]
#[repr(C)]
pub struct LSPS2ServiceConfig {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2ServiceConfig,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2ServiceConfig {
	type Target = nativeLSPS2ServiceConfig;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2ServiceConfig { }
unsafe impl core::marker::Sync for LSPS2ServiceConfig { }
impl Drop for LSPS2ServiceConfig {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2ServiceConfig>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2ServiceConfig, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2ServiceConfig_free(this_obj: LSPS2ServiceConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ServiceConfig_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2ServiceConfig) };
}
#[allow(unused)]
impl LSPS2ServiceConfig {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2ServiceConfig {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2ServiceConfig {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2ServiceConfig {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Used to calculate the promise for channel parameters supplied to clients.
///
/// Note: If this changes then old promises given out will be considered invalid.
#[no_mangle]
pub extern "C" fn LSPS2ServiceConfig_get_promise_secret(this_ptr: &LSPS2ServiceConfig) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().promise_secret;
	inner_val
}
/// Used to calculate the promise for channel parameters supplied to clients.
///
/// Note: If this changes then old promises given out will be considered invalid.
#[no_mangle]
pub extern "C" fn LSPS2ServiceConfig_set_promise_secret(this_ptr: &mut LSPS2ServiceConfig, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.promise_secret = val.data;
}
/// Constructs a new LSPS2ServiceConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceConfig_new(mut promise_secret_arg: crate::c_types::ThirtyTwoBytes) -> LSPS2ServiceConfig {
	LSPS2ServiceConfig { inner: ObjOps::heap_alloc(nativeLSPS2ServiceConfig {
		promise_secret: promise_secret_arg.data,
	}), is_owned: true }
}
impl Clone for LSPS2ServiceConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2ServiceConfig>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ServiceConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2ServiceConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2ServiceConfig
pub extern "C" fn LSPS2ServiceConfig_clone(orig: &LSPS2ServiceConfig) -> LSPS2ServiceConfig {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2ServiceConfig object
pub extern "C" fn LSPS2ServiceConfig_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::service::LSPS2ServiceConfig }).into()}

use lightning_liquidity::lsps2::service::LSPS2ServiceHandler as nativeLSPS2ServiceHandlerImport;
pub(crate) type nativeLSPS2ServiceHandler = nativeLSPS2ServiceHandlerImport<crate::lightning::ln::channelmanager::ChannelManager, >;

/// The main object allowing to send and receive bLIP-52 / LSPS2 messages.
#[must_use]
#[repr(C)]
pub struct LSPS2ServiceHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2ServiceHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2ServiceHandler {
	type Target = nativeLSPS2ServiceHandler;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2ServiceHandler { }
unsafe impl core::marker::Sync for LSPS2ServiceHandler { }
impl Drop for LSPS2ServiceHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2ServiceHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2ServiceHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_free(this_obj: LSPS2ServiceHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ServiceHandler_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2ServiceHandler) };
}
#[allow(unused)]
impl LSPS2ServiceHandler {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2ServiceHandler {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2ServiceHandler {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2ServiceHandler {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Used by LSP to inform a client requesting a JIT Channel the token they used is invalid.
///
/// Should be called in response to receiving a [`LSPS2ServiceEvent::GetInfo`] event.
///
/// [`LSPS2ServiceEvent::GetInfo`]: crate::lsps2::event::LSPS2ServiceEvent::GetInfo
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_invalid_token_provided(this_arg: &crate::lightning_liquidity::lsps2::service::LSPS2ServiceHandler, mut counterparty_node_id: crate::c_types::PublicKey, mut request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invalid_token_provided(&counterparty_node_id.into_rust(), *unsafe { Box::from_raw(request_id.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Used by LSP to provide fee parameters to a client requesting a JIT Channel.
///
/// Should be called in response to receiving a [`LSPS2ServiceEvent::GetInfo`] event.
///
/// [`LSPS2ServiceEvent::GetInfo`]: crate::lsps2::event::LSPS2ServiceEvent::GetInfo
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_opening_fee_params_generated(this_arg: &crate::lightning_liquidity::lsps2::service::LSPS2ServiceHandler, mut counterparty_node_id: crate::c_types::PublicKey, mut request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, mut opening_fee_params_menu: crate::c_types::derived::CVec_LSPS2RawOpeningFeeParamsZ) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut local_opening_fee_params_menu = Vec::new(); for mut item in opening_fee_params_menu.into_rust().drain(..) { local_opening_fee_params_menu.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.opening_fee_params_generated(&counterparty_node_id.into_rust(), *unsafe { Box::from_raw(request_id.take_inner()) }, local_opening_fee_params_menu);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Used by LSP to provide client with the intercept scid and cltv_expiry_delta to use in their invoice.
///
/// Should be called in response to receiving a [`LSPS2ServiceEvent::BuyRequest`] event.
///
/// [`LSPS2ServiceEvent::BuyRequest`]: crate::lsps2::event::LSPS2ServiceEvent::BuyRequest
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_invoice_parameters_generated(this_arg: &crate::lightning_liquidity::lsps2::service::LSPS2ServiceHandler, mut counterparty_node_id: crate::c_types::PublicKey, mut request_id: crate::lightning_liquidity::lsps0::ser::LSPSRequestId, mut intercept_scid: u64, mut cltv_expiry_delta: u32, mut client_trusts_lsp: bool, mut user_channel_id: crate::c_types::U128) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_parameters_generated(&counterparty_node_id.into_rust(), *unsafe { Box::from_raw(request_id.take_inner()) }, intercept_scid, cltv_expiry_delta, client_trusts_lsp, user_channel_id.into());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Forward [`Event::HTLCIntercepted`] event parameters into this function.
///
/// Will fail the intercepted HTLC if the intercept scid matches a payment we are expecting
/// but the payment amount is incorrect or the expiry has passed.
///
/// Will generate a [`LSPS2ServiceEvent::OpenChannel`] event if the intercept scid matches a payment we are expected
/// and the payment amount is correct and the offer has not expired.
///
/// Will do nothing if the intercept scid does not match any of the ones we gave out.
///
/// [`Event::HTLCIntercepted`]: lightning::events::Event::HTLCIntercepted
/// [`LSPS2ServiceEvent::OpenChannel`]: crate::lsps2::event::LSPS2ServiceEvent::OpenChannel
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_htlc_intercepted(this_arg: &crate::lightning_liquidity::lsps2::service::LSPS2ServiceHandler, mut intercept_scid: u64, mut intercept_id: crate::c_types::ThirtyTwoBytes, mut expected_outbound_amount_msat: u64, mut payment_hash: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.htlc_intercepted(intercept_scid, ::lightning::ln::channelmanager::InterceptId(intercept_id.data), expected_outbound_amount_msat, ::lightning::types::payment::PaymentHash(payment_hash.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Forward [`Event::HTLCHandlingFailed`] event parameter into this function.
///
/// Will attempt to forward the next payment in the queue if one is present.
/// Will do nothing if the intercept scid does not match any of the ones we gave out
/// or if the payment queue is empty
///
/// [`Event::HTLCHandlingFailed`]: lightning::events::Event::HTLCHandlingFailed
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_htlc_handling_failed(this_arg: &crate::lightning_liquidity::lsps2::service::LSPS2ServiceHandler, mut failed_next_destination: crate::lightning::events::HTLCDestination) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.htlc_handling_failed(failed_next_destination.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Forward [`Event::PaymentForwarded`] event parameter into this function.
///
/// Will register the forwarded payment as having paid the JIT channel fee, and forward any held
/// and future HTLCs for the SCID of the initial invoice. In the future, this will verify the
/// `skimmed_fee_msat` in [`Event::PaymentForwarded`].
///
/// Note that `next_channel_id` is required to be provided. Therefore, the corresponding
/// [`Event::PaymentForwarded`] events need to be generated and serialized by LDK versions
/// greater or equal to 0.0.107.
///
/// [`Event::PaymentForwarded`]: lightning::events::Event::PaymentForwarded
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_payment_forwarded(this_arg: &crate::lightning_liquidity::lsps2::service::LSPS2ServiceHandler, mut next_channel_id: crate::lightning::ln::types::ChannelId) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_forwarded(*unsafe { Box::from_raw(next_channel_id.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Forward [`Event::ChannelReady`] event parameters into this function.
///
/// Will forward the intercepted HTLC if it matches a channel
/// we need to forward a payment over otherwise it will be ignored.
///
/// [`Event::ChannelReady`]: lightning::events::Event::ChannelReady
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ServiceHandler_channel_ready(this_arg: &crate::lightning_liquidity::lsps2::service::LSPS2ServiceHandler, mut user_channel_id: crate::c_types::U128, channel_id: &crate::lightning::ln::types::ChannelId, mut counterparty_node_id: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel_ready(user_channel_id.into(), channel_id.get_native_ref(), &counterparty_node_id.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

