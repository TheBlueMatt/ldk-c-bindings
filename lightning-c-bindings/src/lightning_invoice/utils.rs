// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Convenient utilities to create an invoice.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager(channelmanager.get_native_ref(), keys_manager, network.into_native(), local_amt_msat, description.into_string());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}


use lightning_invoice::utils::DefaultRouter as nativeDefaultRouterImport;
pub(crate) type nativeDefaultRouter = nativeDefaultRouterImport<&'static lightning::routing::network_graph::NetworkGraph, crate::lightning::util::logger::Logger>;

/// A [`Router`] implemented using [`find_route`].
#[must_use]
#[repr(C)]
pub struct DefaultRouter {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDefaultRouter,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DefaultRouter {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDefaultRouter>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DefaultRouter, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DefaultRouter_free(this_obj: DefaultRouter) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DefaultRouter_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDefaultRouter); }
}
#[allow(unused)]
impl DefaultRouter {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDefaultRouter {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDefaultRouter {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDefaultRouter {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Creates a new router using the given [`NetworkGraph`] and  [`Logger`].
#[must_use]
#[no_mangle]
pub extern "C" fn DefaultRouter_new(network_graph: &crate::lightning::routing::network_graph::NetworkGraph, mut logger: crate::lightning::util::logger::Logger) -> DefaultRouter {
	let mut ret = lightning_invoice::utils::DefaultRouter::new(network_graph.get_native_ref(), logger);
	DefaultRouter { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeDefaultRouter> for crate::lightning_invoice::payment::Router {
	fn from(obj: nativeDefaultRouter) -> Self {
		let mut rust_obj = DefaultRouter { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = DefaultRouter_as_Router(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(DefaultRouter_free_void);
		ret
	}
}
/// Constructs a new Router which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Router must be freed before this_arg is
#[no_mangle]
pub extern "C" fn DefaultRouter_as_Router(this_arg: &DefaultRouter) -> crate::lightning_invoice::payment::Router {
	crate::lightning_invoice::payment::Router {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		find_route: DefaultRouter_Router_find_route,
	}
}

#[must_use]
extern "C" fn DefaultRouter_Router_find_route(this_arg: *const c_void, mut payer: crate::c_types::PublicKey, params: &crate::lightning::routing::router::RouteParameters, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, scorer: &crate::lightning::routing::Score) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_first_hops_base = if first_hops == std::ptr::null_mut() { None } else { Some( { let mut local_first_hops_0 = Vec::new(); for mut item in unsafe { &mut *first_hops }.as_slice().iter() { local_first_hops_0.push( { item.get_native_ref() }); }; local_first_hops_0 }) }; let mut local_first_hops = local_first_hops_base.as_ref().map(|a| &a[..]);
	let mut ret = <nativeDefaultRouter as lightning_invoice::payment::Router<_>>::find_route(unsafe { &mut *(this_arg as *mut nativeDefaultRouter) }, &payer.into_rust(), params.get_native_ref(), local_first_hops, scorer);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

use crate::lightning::ln::channelmanager::nativeChannelManager as nativeChannelManager;
use crate::lightning::ln::channelmanager::ChannelManager;
use crate::lightning::ln::channelmanager::ChannelManager_free_void;
impl From<nativeChannelManager> for crate::lightning_invoice::payment::Payer {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChannelManager_as_Payer(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new Payer which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Payer must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_Payer(this_arg: &ChannelManager) -> crate::lightning_invoice::payment::Payer {
	crate::lightning_invoice::payment::Payer {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		node_id: ChannelManager_Payer_node_id,
		first_hops: ChannelManager_Payer_first_hops,
		send_payment: ChannelManager_Payer_send_payment,
		retry_payment: ChannelManager_Payer_retry_payment,
	}
}

#[must_use]
extern "C" fn ChannelManager_Payer_node_id(this_arg: *const c_void) -> crate::c_types::PublicKey {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::node_id(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, );
	crate::c_types::PublicKey::from_rust(&ret)
}
#[must_use]
extern "C" fn ChannelManager_Payer_first_hops(this_arg: *const c_void) -> crate::c_types::derived::CVec_ChannelDetailsZ {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::first_hops(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}
#[must_use]
extern "C" fn ChannelManager_Payer_send_payment(this_arg: *const c_void, route: &crate::lightning::routing::router::Route, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut payment_secret: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_PaymentIdPaymentSendFailureZ {
	let mut local_payment_secret = if payment_secret.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentSecret(payment_secret.data) }) };
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::send_payment(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, route.get_native_ref(), ::lightning::ln::PaymentHash(payment_hash.data), &local_payment_secret);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn ChannelManager_Payer_retry_payment(this_arg: *const c_void, route: &crate::lightning::routing::router::Route, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::retry_payment(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, route.get_native_ref(), ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}

