// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and methods for caching offers that we interactively build with a static invoice
//! server as an async recipient. The static invoice server will serve the resulting invoices to
//! payers on our behalf when we're offline.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache as nativeAsyncReceiveOfferCacheImport;
pub(crate) type nativeAsyncReceiveOfferCache = nativeAsyncReceiveOfferCacheImport;

/// If we are an often-offline recipient, we'll want to interactively build offers and static
/// invoices with an always-online node that will serve those static invoices to payers on our
/// behalf when we are offline.
///
/// This struct is used to cache those interactively built offers, and should be passed into
/// [`OffersMessageFlow`] on startup as well as persisted whenever an offer or invoice is updated.
///
/// ## Lifecycle of a cached offer
///
/// 1. On initial startup, recipients will request offer paths from the static invoice server
/// 2. Once a set of offer paths is received, recipients will build an offer and corresponding
///    static invoice, cache the offer as pending, and send the invoice to the server for
///    persistence
/// 3. Once the invoice is confirmed as persisted by the server, the recipient will mark the
///    corresponding offer as ready to receive payments
/// 4. If the offer is later returned to the user, it will be kept cached and its invoice will be
///    kept up-to-date until the offer expires
/// 5. If the offer does not get returned to the user within a certain timeframe, it will be
///    replaced with a new one using fresh offer paths requested from the static invoice server
///
/// ## Staying in sync with the Static Invoice Server
///
/// * Pending offers: for a given cached offer where a corresponding invoice is not yet confirmed as
/// persisted by the static invoice server, we will retry persisting an invoice for that offer until
/// it succeeds, once per timer tick
/// * Confirmed offers that have not yet been returned to the user: we will periodically replace an
/// unused confirmed offer with a new one, to try to always have a fresh offer available. We wait
/// several hours in between replacements to ensure the new offer replacement doesn't conflict with
/// the old one
/// * Confirmed offers that have been returned to the user: we will send the server a fresh invoice
/// corresponding to each used offer once per timer tick until the offer expires
///
/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
#[must_use]
#[repr(C)]
pub struct AsyncReceiveOfferCache {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAsyncReceiveOfferCache,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for AsyncReceiveOfferCache {
	type Target = nativeAsyncReceiveOfferCache;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for AsyncReceiveOfferCache { }
unsafe impl core::marker::Sync for AsyncReceiveOfferCache { }
impl Drop for AsyncReceiveOfferCache {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeAsyncReceiveOfferCache>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the AsyncReceiveOfferCache, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn AsyncReceiveOfferCache_free(this_obj: AsyncReceiveOfferCache) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AsyncReceiveOfferCache_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeAsyncReceiveOfferCache) };
}
#[allow(unused)]
impl AsyncReceiveOfferCache {
	pub(crate) fn get_native_ref(&self) -> &'static nativeAsyncReceiveOfferCache {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeAsyncReceiveOfferCache {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeAsyncReceiveOfferCache {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Creates an empty [`AsyncReceiveOfferCache`] to be passed into [`OffersMessageFlow`].
///
/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
#[must_use]
#[no_mangle]
pub extern "C" fn AsyncReceiveOfferCache_new() -> crate::lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache {
	let mut ret = lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache::new();
	crate::lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Serialize the AsyncReceiveOfferCache object into a byte array which can be read by AsyncReceiveOfferCache_read
pub extern "C" fn AsyncReceiveOfferCache_write(obj: &crate::lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn AsyncReceiveOfferCache_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::async_receive_offer_cache::nativeAsyncReceiveOfferCache) })
}
#[no_mangle]
/// Read a AsyncReceiveOfferCache from a byte array, created by AsyncReceiveOfferCache_write
pub extern "C" fn AsyncReceiveOfferCache_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_AsyncReceiveOfferCacheDecodeErrorZ {
	let res: Result<lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::async_receive_offer_cache::AsyncReceiveOfferCache { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
