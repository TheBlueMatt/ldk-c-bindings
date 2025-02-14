// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities to generate inbound payment information in service of invoice creation.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::ln::inbound_payment::ExpandedKey as nativeExpandedKeyImport;
pub(crate) type nativeExpandedKey = nativeExpandedKeyImport;

/// A set of keys that were HKDF-expanded. Returned by [`NodeSigner::get_inbound_payment_key`].
///
/// [`NodeSigner::get_inbound_payment_key`]: crate::sign::NodeSigner::get_inbound_payment_key
#[must_use]
#[repr(C)]
pub struct ExpandedKey {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeExpandedKey,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ExpandedKey {
	type Target = nativeExpandedKey;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ExpandedKey { }
unsafe impl core::marker::Sync for ExpandedKey { }
impl Drop for ExpandedKey {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeExpandedKey>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ExpandedKey, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ExpandedKey_free(this_obj: ExpandedKey) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ExpandedKey_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeExpandedKey) };
}
#[allow(unused)]
impl ExpandedKey {
	pub(crate) fn get_native_ref(&self) -> &'static nativeExpandedKey {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeExpandedKey {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeExpandedKey {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Generates a non-cryptographic 64-bit hash of the ExpandedKey.
#[no_mangle]
pub extern "C" fn ExpandedKey_hash(o: &ExpandedKey) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
impl Clone for ExpandedKey {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeExpandedKey>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ExpandedKey_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeExpandedKey)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ExpandedKey
pub extern "C" fn ExpandedKey_clone(orig: &ExpandedKey) -> ExpandedKey {
	orig.clone()
}
/// Checks if two ExpandedKeys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ExpandedKey_eq(a: &ExpandedKey, b: &ExpandedKey) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Get a string which allows debug introspection of a ExpandedKey object
pub extern "C" fn ExpandedKey_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::inbound_payment::ExpandedKey }).into()}
/// Create a  new [`ExpandedKey`] for generating an inbound payment hash and secret.
///
/// It is recommended to cache this value and not regenerate it for each new inbound payment.
#[must_use]
#[no_mangle]
pub extern "C" fn ExpandedKey_new(mut key_material: crate::c_types::ThirtyTwoBytes) -> crate::lightning::ln::inbound_payment::ExpandedKey {
	let mut ret = lightning::ln::inbound_payment::ExpandedKey::new(key_material.data);
	crate::lightning::ln::inbound_payment::ExpandedKey { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Equivalent to [`crate::ln::channelmanager::ChannelManager::create_inbound_payment`], but no
/// `ChannelManager` is required. Useful for generating invoices for [phantom node payments] without
/// a `ChannelManager`.
///
/// `keys` is generated by calling [`NodeSigner::get_inbound_payment_key`]. It is recommended to
/// cache this value and not regenerate it for each new inbound payment.
///
/// `current_time` is a Unix timestamp representing the current time.
///
/// Note that if `min_final_cltv_expiry_delta` is set to some value, then the payment will not be receivable
/// on versions of LDK prior to 0.0.114.
///
/// [phantom node payments]: crate::sign::PhantomKeysManager
/// [`NodeSigner::get_inbound_payment_key`]: crate::sign::NodeSigner::get_inbound_payment_key
#[no_mangle]
pub extern "C" fn create(keys: &crate::lightning::ln::inbound_payment::ExpandedKey, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut invoice_expiry_delta_secs: u32, entropy_source: &crate::lightning::sign::EntropySource, mut current_time: u64, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z) -> crate::c_types::derived::CResult_C2Tuple_ThirtyTwoBytesThirtyTwoBytesZNoneZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning::ln::inbound_payment::create::<crate::lightning::sign::EntropySource, >(keys.get_native_ref(), local_min_value_msat, invoice_expiry_delta_secs, entropy_source, current_time, local_min_final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.0 }, crate::c_types::ThirtyTwoBytes { data: orig_ret_0_1.0 }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Equivalent to [`crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash`],
/// but no `ChannelManager` is required. Useful for generating invoices for [phantom node payments]
/// without a `ChannelManager`.
///
/// See [`create`] for information on the `keys` and `current_time` parameters.
///
/// Note that if `min_final_cltv_expiry_delta` is set to some value, then the payment will not be receivable
/// on versions of LDK prior to 0.0.114.
///
/// [phantom node payments]: crate::sign::PhantomKeysManager
#[no_mangle]
pub extern "C" fn create_from_hash(keys: &crate::lightning::ln::inbound_payment::ExpandedKey, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut invoice_expiry_delta_secs: u32, mut current_time: u64, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z) -> crate::c_types::derived::CResult_ThirtyTwoBytesNoneZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning::ln::inbound_payment::create_from_hash(keys.get_native_ref(), local_min_value_msat, ::lightning::types::payment::PaymentHash(payment_hash.data), invoice_expiry_delta_secs, current_time, local_min_final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

