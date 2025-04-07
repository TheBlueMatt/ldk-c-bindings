// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains the main bLIP-51 / LSPS1 client object, [`LSPS1ClientHandler`].

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::lsps1::client::LSPS1ClientConfig as nativeLSPS1ClientConfigImport;
pub(crate) type nativeLSPS1ClientConfig = nativeLSPS1ClientConfigImport;

/// Client-side configuration options for bLIP-51 / LSPS1 channel requests.
#[must_use]
#[repr(C)]
pub struct LSPS1ClientConfig {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1ClientConfig,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1ClientConfig {
	type Target = nativeLSPS1ClientConfig;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1ClientConfig { }
unsafe impl core::marker::Sync for LSPS1ClientConfig { }
impl Drop for LSPS1ClientConfig {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1ClientConfig>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1ClientConfig, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1ClientConfig_free(this_obj: LSPS1ClientConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1ClientConfig_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1ClientConfig) };
}
#[allow(unused)]
impl LSPS1ClientConfig {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1ClientConfig {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1ClientConfig {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1ClientConfig {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The maximally allowed channel fees.
#[no_mangle]
pub extern "C" fn LSPS1ClientConfig_get_max_channel_fees_msat(this_ptr: &LSPS1ClientConfig) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_channel_fees_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The maximally allowed channel fees.
#[no_mangle]
pub extern "C" fn LSPS1ClientConfig_set_max_channel_fees_msat(this_ptr: &mut LSPS1ClientConfig, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_channel_fees_msat = local_val;
}
/// Constructs a new LSPS1ClientConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1ClientConfig_new(mut max_channel_fees_msat_arg: crate::c_types::derived::COption_u64Z) -> LSPS1ClientConfig {
	let mut local_max_channel_fees_msat_arg = if max_channel_fees_msat_arg.is_some() { Some( { max_channel_fees_msat_arg.take() }) } else { None };
	LSPS1ClientConfig { inner: ObjOps::heap_alloc(nativeLSPS1ClientConfig {
		max_channel_fees_msat: local_max_channel_fees_msat_arg,
	}), is_owned: true }
}
impl Clone for LSPS1ClientConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeLSPS1ClientConfig>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1ClientConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeLSPS1ClientConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the LSPS1ClientConfig
pub extern "C" fn LSPS1ClientConfig_clone(orig: &LSPS1ClientConfig) -> LSPS1ClientConfig {
	orig.clone()
}
/// Get a string which allows debug introspection of a LSPS1ClientConfig object
pub extern "C" fn LSPS1ClientConfig_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps1::client::LSPS1ClientConfig }).into()}

use lightning_liquidity::lsps1::client::LSPS1ClientHandler as nativeLSPS1ClientHandlerImport;
pub(crate) type nativeLSPS1ClientHandler = nativeLSPS1ClientHandlerImport<crate::lightning::sign::EntropySource, >;

/// The main object allowing to send and receive bLIP-51 / LSPS1 messages.
#[must_use]
#[repr(C)]
pub struct LSPS1ClientHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLSPS1ClientHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for LSPS1ClientHandler {
	type Target = nativeLSPS1ClientHandler;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for LSPS1ClientHandler { }
unsafe impl core::marker::Sync for LSPS1ClientHandler { }
impl Drop for LSPS1ClientHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLSPS1ClientHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LSPS1ClientHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LSPS1ClientHandler_free(this_obj: LSPS1ClientHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS1ClientHandler_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLSPS1ClientHandler) };
}
#[allow(unused)]
impl LSPS1ClientHandler {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLSPS1ClientHandler {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLSPS1ClientHandler {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLSPS1ClientHandler {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Request the supported options from the LSP.
///
/// The user will receive the LSP's response via an [`SupportedOptionsReady`] event.
///
/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
///
/// Returns the used [`LSPSRequestId`], which will be returned via [`SupportedOptionsReady`].
///
/// [`SupportedOptionsReady`]: crate::lsps1::event::LSPS1ClientEvent::SupportedOptionsReady
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1ClientHandler_request_supported_options(this_arg: &crate::lightning_liquidity::lsps1::client::LSPS1ClientHandler, mut counterparty_node_id: crate::c_types::PublicKey) -> crate::lightning_liquidity::lsps0::ser::LSPSRequestId {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.request_supported_options(counterparty_node_id.into_rust());
	crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Places an order with the connected LSP given its `counterparty_node_id`.
///
/// The client agrees to paying channel fees according to the provided parameters.
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1ClientHandler_create_order(this_arg: &crate::lightning_liquidity::lsps1::client::LSPS1ClientHandler, mut counterparty_node_id: crate::c_types::PublicKey, mut order: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderParams, mut refund_onchain_address: crate::c_types::derived::COption_AddressZ) -> crate::lightning_liquidity::lsps0::ser::LSPSRequestId {
	let mut local_refund_onchain_address = { /*refund_onchain_address*/ let refund_onchain_address_opt = refund_onchain_address; if refund_onchain_address_opt.is_none() { None } else { Some({ { { refund_onchain_address_opt.take() }.into_rust() }})} };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.create_order(&counterparty_node_id.into_rust(), *unsafe { Box::from_raw(order.take_inner()) }, local_refund_onchain_address);
	crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Queries the status of a pending payment, i.e., whether a payment has been received by the LSP.
///
/// Upon success an [`LSPS1ClientEvent::OrderStatus`] event will be emitted.
///
/// [`LSPS1ClientEvent::OrderStatus`]: crate::lsps1::event::LSPS1ClientEvent::OrderStatus
#[must_use]
#[no_mangle]
pub extern "C" fn LSPS1ClientHandler_check_order_status(this_arg: &crate::lightning_liquidity::lsps1::client::LSPS1ClientHandler, mut counterparty_node_id: crate::c_types::PublicKey, mut order_id: crate::lightning_liquidity::lsps1::msgs::LSPS1OrderId) -> crate::lightning_liquidity::lsps0::ser::LSPSRequestId {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.check_order_status(&counterparty_node_id.into_rust(), *unsafe { Box::from_raw(order_id.take_inner()) });
	crate::lightning_liquidity::lsps0::ser::LSPSRequestId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

