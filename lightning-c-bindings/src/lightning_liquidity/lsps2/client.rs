// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains the main bLIP-52 / LSPS2 client object, [`LSPS2ClientHandler`].

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::lsps2::client::LSPS2ClientConfig as nativeLSPS2ClientConfigImport;
pub(crate) type nativeLSPS2ClientConfig = nativeLSPS2ClientConfigImport;

/// Client-side configuration options for JIT channels.
#[must_use]
#[repr(C)]
pub struct LSPS2ClientConfig {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2ClientConfig,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2ClientConfig {
	type Target = nativeLSPS2ClientConfig;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2ClientConfig { }
unsafe impl core::marker::Sync for LSPS2ClientConfig { }
impl Drop for LSPS2ClientConfig {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2ClientConfig>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2ClientConfig, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2ClientConfig_free(this_obj: LSPS2ClientConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ClientConfig_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2ClientConfig) };
}
#[allow(unused)]
impl LSPS2ClientConfig {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2ClientConfig {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2ClientConfig {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2ClientConfig {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new LSPS2ClientConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ClientConfig_new() -> LSPS2ClientConfig {
	LSPS2ClientConfig { inner: ObjOps::heap_alloc(nativeLSPS2ClientConfig {
	}), is_owned: true }
}
impl Clone for LSPS2ClientConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS2ClientConfig>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ClientConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS2ClientConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS2ClientConfig
pub extern "C" fn LSPS2ClientConfig_clone(orig: &LSPS2ClientConfig) -> LSPS2ClientConfig {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS2ClientConfig object
pub extern "C" fn LSPS2ClientConfig_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps2::client::LSPS2ClientConfig }).into()}

use lightning_liquidity::lsps2::client::LSPS2ClientHandler as nativeLSPS2ClientHandlerImport;
pub(crate) type nativeLSPS2ClientHandler = nativeLSPS2ClientHandlerImport<crate::lightning::sign::EntropySource, >;

/// The main object allowing to send and receive bLIP-52 / LSPS2 messages.
///
/// Note that currently only the 'client-trusts-LSP' trust model is supported, i.e., we don't
/// provide any additional API guidance to allow withholding the preimage until the channel is
/// opened. Please refer to the [`bLIP-52 / LSPS2 specification`] for more information.
///
/// [`bLIP-52 / LSPS2 specification`]: https://github.com/lightning/blips/blob/master/blip-0052.md#trust-models
#[must_use]
#[repr(C)]
pub struct LSPS2ClientHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS2ClientHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS2ClientHandler {
	type Target = nativeLSPS2ClientHandler;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS2ClientHandler { }
unsafe impl core::marker::Sync for LSPS2ClientHandler { }
impl Drop for LSPS2ClientHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS2ClientHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS2ClientHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS2ClientHandler_free(this_obj: LSPS2ClientHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS2ClientHandler_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS2ClientHandler) };
}
#[allow(unused)]
impl LSPS2ClientHandler {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS2ClientHandler {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS2ClientHandler {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS2ClientHandler {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Request the channel opening parameters from the LSP.
///
/// This initiates the JIT-channel flow that, at the end of it, will have the LSP
/// open a channel with sufficient inbound liquidity to be able to receive the payment.
///
/// The user will receive the LSP's response via an [`OpeningParametersReady`] event.
///
/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
///
/// `token` is an optional `String` that will be provided to the LSP.
/// It can be used by the LSP as an API key, coupon code, or some other way to identify a user.
///
/// Returns the used [`LSPSRequestId`], which will be returned via [`OpeningParametersReady`].
///
/// [`OpeningParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::OpeningParametersReady
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ClientHandler_request_opening_params(this_arg: &crate::lightning_liquidity::lsps2::client::LSPS2ClientHandler, mut counterparty_node_id: crate::c_types::PublicKey, mut token: crate::c_types::derived::COption_StrZ) -> crate::lightning_liquidity::lsps0::ser::LSPSRequestId {
	let mut local_token = { /*token*/ let token_opt = token; if token_opt.is_none() { None } else { Some({ { { token_opt.take() }.into_string() }})} };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.request_opening_params(counterparty_node_id.into_rust(), local_token);
	crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Confirms a set of chosen channel opening parameters to use for the JIT channel and
/// requests the necessary invoice generation parameters from the LSP.
///
/// Should be called in response to receiving a [`OpeningParametersReady`] event.
///
/// The user will receive the LSP's response via an [`InvoiceParametersReady`] event.
///
/// If `payment_size_msat` is [`Option::Some`] then the invoice will be for a fixed amount
/// and MPP can be used to pay it.
///
/// If `payment_size_msat` is [`Option::None`] then the invoice can be for an arbitrary amount
/// but MPP can no longer be used to pay it.
///
/// The client agrees to paying an opening fee equal to
/// `max(min_fee_msat, proportional*(payment_size_msat/1_000_000))`.
///
/// [`OpeningParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::OpeningParametersReady
/// [`InvoiceParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::InvoiceParametersReady
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS2ClientHandler_select_opening_params(this_arg: &crate::lightning_liquidity::lsps2::client::LSPS2ClientHandler, mut counterparty_node_id: crate::c_types::PublicKey, mut payment_size_msat: crate::c_types::derived::COption_u64Z, mut opening_fee_params: crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams) -> crate::c_types::derived::CResult_LSPSRequestIdAPIErrorZ {
	let mut local_payment_size_msat = if payment_size_msat.is_some() { Some( { payment_size_msat.take() }) } else { None };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.select_opening_params(counterparty_node_id.into_rust(), local_payment_size_msat, *unsafe { Box::from_raw(opening_fee_params.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

