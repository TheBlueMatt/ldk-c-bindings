// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for static BOLT 12 invoices.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::static_invoice::StaticInvoice as nativeStaticInvoiceImport;
pub(crate) type nativeStaticInvoice = nativeStaticInvoiceImport;

/// A `StaticInvoice` is a reusable payment request corresponding to an [`Offer`].
///
/// A static invoice may be sent in response to an [`InvoiceRequest`] and includes all the
/// information needed to pay the recipient. However, unlike [`Bolt12Invoice`]s, static invoices do
/// not provide proof-of-payment. Therefore, [`Bolt12Invoice`]s should be preferred when the
/// recipient is online to provide one.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[repr(C)]
pub struct StaticInvoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeStaticInvoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for StaticInvoice {
	type Target = nativeStaticInvoice;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for StaticInvoice { }
unsafe impl core::marker::Sync for StaticInvoice { }
impl Drop for StaticInvoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeStaticInvoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the StaticInvoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn StaticInvoice_free(this_obj: StaticInvoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn StaticInvoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeStaticInvoice) };
}
#[allow(unused)]
impl StaticInvoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeStaticInvoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeStaticInvoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeStaticInvoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for StaticInvoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeStaticInvoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn StaticInvoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeStaticInvoice) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the StaticInvoice
pub extern "C" fn StaticInvoice_clone(orig: &StaticInvoice) -> StaticInvoice {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a StaticInvoice object
pub extern "C" fn StaticInvoice_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::static_invoice::StaticInvoice }).into()}
/// Generates a non-cryptographic 64-bit hash of the StaticInvoice.
#[no_mangle]
pub extern "C" fn StaticInvoice_hash(o: &StaticInvoice) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning::offers::static_invoice::UnsignedStaticInvoice as nativeUnsignedStaticInvoiceImport;
pub(crate) type nativeUnsignedStaticInvoice = nativeUnsignedStaticInvoiceImport;

/// A semantically valid [`StaticInvoice`] that hasn't been signed.
#[must_use]
#[repr(C)]
pub struct UnsignedStaticInvoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedStaticInvoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for UnsignedStaticInvoice {
	type Target = nativeUnsignedStaticInvoice;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for UnsignedStaticInvoice { }
unsafe impl core::marker::Sync for UnsignedStaticInvoice { }
impl Drop for UnsignedStaticInvoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUnsignedStaticInvoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UnsignedStaticInvoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_free(this_obj: UnsignedStaticInvoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnsignedStaticInvoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUnsignedStaticInvoice) };
}
#[allow(unused)]
impl UnsignedStaticInvoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUnsignedStaticInvoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUnsignedStaticInvoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedStaticInvoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Signs the [`TaggedHash`] of the invoice using the given function.
///
/// Note: The hash computation may have included unknown, odd TLV records.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_sign(mut this_arg: crate::lightning::offers::static_invoice::UnsignedStaticInvoice, mut sign: crate::lightning::offers::static_invoice::SignStaticInvoiceFn) -> crate::c_types::derived::CResult_StaticInvoiceSignErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).sign(sign);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::static_invoice::StaticInvoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::merkle::SignError::native_into(e) }).into() };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes, including information
/// needed for routing payments across them.
///
/// Blinded paths provide recipient privacy by obfuscating its node id. Note, however, that this
/// privacy is lost if a public node id is used for
///[`UnsignedStaticInvoice::signing_pubkey`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_payment_paths(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::CVec_BlindedPaymentPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::payment::BlindedPaymentPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Duration since the Unix epoch when the invoice was created.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_created_at(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.created_at();
	ret.as_secs()
}

/// Duration since
///[`UnsignedStaticInvoice::created_at`]
/// when the invoice has expired and therefore should no longer be paid.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_relative_expiry(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.relative_expiry();
	ret.as_secs()
}

/// Whether the invoice has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_is_expired(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// Whether the invoice has expired given the current time as duration since the Unix epoch.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_is_expired_no_std(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice, mut duration_since_epoch: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired_no_std(core::time::Duration::from_secs(duration_since_epoch));
	ret
}

/// Fallback addresses for paying the invoice on-chain, in order of most-preferred to
/// least-preferred.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_fallbacks(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::CVec_AddressZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fallbacks();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::Address::from_rust(&item) }); };
	local_ret.into()
}

/// Features pertaining to paying an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_invoice_features(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::lightning_types::features::Bolt12InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_features();
	crate::lightning_types::features::Bolt12InvoiceFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::Bolt12InvoiceFeatures<>) as *mut _) }, is_owned: false }
}

/// The public key corresponding to the key used to sign the invoice.
///
/// This will be:
/// - [`Offer::issuer_signing_pubkey`] if it's `Some`, otherwise
/// - the final blinded node id from a [`BlindedMessagePath`] in [`Offer::paths`] if `None`.
///
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_signing_pubkey(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// The chain that must be used when paying the invoice. [`StaticInvoice`]s currently can only be
/// created from offers that support a single chain.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_chain(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// Opaque bytes set by the originating [`Offer::metadata`].
///
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_metadata(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
///
/// From [`Offer::amount`].
///
/// [`Offer::amount`]: crate::offers::offer::Offer::amount
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_amount(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::COption_AmountZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_AmountZ::None } else { crate::c_types::derived::COption_AmountZ::Some( { crate::lightning::offers::offer::Amount::native_into(ret.unwrap()) }) };
	local_ret
}

/// Features pertaining to the originating [`Offer`], from [`Offer::offer_features`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_offer_features(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::lightning_types::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	crate::lightning_types::features::OfferFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::OfferFeatures<>) as *mut _) }, is_owned: false }
}

/// A complete description of the purpose of the originating offer, from [`Offer::description`].
///
/// [`Offer::description`]: crate::offers::offer::Offer::description
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_description(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Duration since the Unix epoch when an invoice should no longer be requested, from
/// [`Offer::absolute_expiry`].
///
/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_absolute_expiry(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// The issuer of the offer, from [`Offer::issuer`].
///
/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_issuer(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the node that may supply the invoice on the recipient's behalf, originating from
/// publicly reachable nodes. Taken from [`Offer::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_offer_message_paths(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Paths to the recipient for indicating that a held HTLC is available to claim when they next
/// come online.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_message_paths(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported, from [`Offer::supported_quantity`].
///
/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_supported_quantity(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	crate::lightning::offers::offer::Quantity::native_into(ret)
}

/// The public key used by the recipient to sign invoices, from
/// [`Offer::issuer_signing_pubkey`].
///
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedStaticInvoice_issuer_signing_pubkey(this_arg: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer_signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// A function for signing an [`UnsignedStaticInvoice`].
#[repr(C)]
pub struct SignStaticInvoiceFn {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	pub sign_invoice: extern "C" fn (this_arg: *const c_void, message: &crate::lightning::offers::static_invoice::UnsignedStaticInvoice) -> crate::c_types::derived::CResult_SchnorrSignatureNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for SignStaticInvoiceFn {}
unsafe impl Sync for SignStaticInvoiceFn {}
#[allow(unused)]
pub(crate) fn SignStaticInvoiceFn_clone_fields(orig: &SignStaticInvoiceFn) -> SignStaticInvoiceFn {
	SignStaticInvoiceFn {
		this_arg: orig.this_arg,
		sign_invoice: Clone::clone(&orig.sign_invoice),
		free: Clone::clone(&orig.free),
	}
}

use lightning::offers::static_invoice::SignStaticInvoiceFn as rustSignStaticInvoiceFn;
impl rustSignStaticInvoiceFn for SignStaticInvoiceFn {
	fn sign_invoice(&self, mut message: &lightning::offers::static_invoice::UnsignedStaticInvoice) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
		let mut ret = (self.sign_invoice)(self.this_arg, &crate::lightning::offers::static_invoice::UnsignedStaticInvoice { inner: unsafe { ObjOps::nonnull_ptr_to_inner((message as *const lightning::offers::static_invoice::UnsignedStaticInvoice<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

pub struct SignStaticInvoiceFnRef(SignStaticInvoiceFn);
impl rustSignStaticInvoiceFn for SignStaticInvoiceFnRef {
	fn sign_invoice(&self, mut message: &lightning::offers::static_invoice::UnsignedStaticInvoice) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
		let mut ret = (self.0.sign_invoice)(self.0.this_arg, &crate::lightning::offers::static_invoice::UnsignedStaticInvoice { inner: unsafe { ObjOps::nonnull_ptr_to_inner((message as *const lightning::offers::static_invoice::UnsignedStaticInvoice<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for SignStaticInvoiceFn {
	type Target = SignStaticInvoiceFnRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const SignStaticInvoiceFnRef) }
	}
}
impl core::ops::DerefMut for SignStaticInvoiceFn {
	fn deref_mut(&mut self) -> &mut SignStaticInvoiceFnRef {
		unsafe { &mut *(self as *mut _ as *mut SignStaticInvoiceFnRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn SignStaticInvoiceFn_free(this_ptr: SignStaticInvoiceFn) { }
impl Drop for SignStaticInvoiceFn {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Paths to the recipient originating from publicly reachable nodes, including information
/// needed for routing payments across them.
///
/// Blinded paths provide recipient privacy by obfuscating its node id. Note, however, that this
/// privacy is lost if a public node id is used for
///[`StaticInvoice::signing_pubkey`].
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_payment_paths(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::CVec_BlindedPaymentPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::payment::BlindedPaymentPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Duration since the Unix epoch when the invoice was created.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_created_at(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.created_at();
	ret.as_secs()
}

/// Duration since
///[`StaticInvoice::created_at`]
/// when the invoice has expired and therefore should no longer be paid.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_relative_expiry(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.relative_expiry();
	ret.as_secs()
}

/// Whether the invoice has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_is_expired(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// Whether the invoice has expired given the current time as duration since the Unix epoch.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_is_expired_no_std(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice, mut duration_since_epoch: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired_no_std(core::time::Duration::from_secs(duration_since_epoch));
	ret
}

/// Fallback addresses for paying the invoice on-chain, in order of most-preferred to
/// least-preferred.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_fallbacks(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::CVec_AddressZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fallbacks();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::Address::from_rust(&item) }); };
	local_ret.into()
}

/// Features pertaining to paying an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_invoice_features(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::lightning_types::features::Bolt12InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_features();
	crate::lightning_types::features::Bolt12InvoiceFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::Bolt12InvoiceFeatures<>) as *mut _) }, is_owned: false }
}

/// The public key corresponding to the key used to sign the invoice.
///
/// This will be:
/// - [`Offer::issuer_signing_pubkey`] if it's `Some`, otherwise
/// - the final blinded node id from a [`BlindedMessagePath`] in [`Offer::paths`] if `None`.
///
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_signing_pubkey(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// The chain that must be used when paying the invoice. [`StaticInvoice`]s currently can only be
/// created from offers that support a single chain.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_chain(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// Opaque bytes set by the originating [`Offer::metadata`].
///
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_metadata(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
///
/// From [`Offer::amount`].
///
/// [`Offer::amount`]: crate::offers::offer::Offer::amount
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_amount(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::COption_AmountZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_AmountZ::None } else { crate::c_types::derived::COption_AmountZ::Some( { crate::lightning::offers::offer::Amount::native_into(ret.unwrap()) }) };
	local_ret
}

/// Features pertaining to the originating [`Offer`], from [`Offer::offer_features`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_offer_features(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::lightning_types::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	crate::lightning_types::features::OfferFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::OfferFeatures<>) as *mut _) }, is_owned: false }
}

/// A complete description of the purpose of the originating offer, from [`Offer::description`].
///
/// [`Offer::description`]: crate::offers::offer::Offer::description
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_description(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Duration since the Unix epoch when an invoice should no longer be requested, from
/// [`Offer::absolute_expiry`].
///
/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_absolute_expiry(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// The issuer of the offer, from [`Offer::issuer`].
///
/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_issuer(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the node that may supply the invoice on the recipient's behalf, originating from
/// publicly reachable nodes. Taken from [`Offer::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_offer_message_paths(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Paths to the recipient for indicating that a held HTLC is available to claim when they next
/// come online.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_message_paths(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported, from [`Offer::supported_quantity`].
///
/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_supported_quantity(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	crate::lightning::offers::offer::Quantity::native_into(ret)
}

/// The public key used by the recipient to sign invoices, from
/// [`Offer::issuer_signing_pubkey`].
///
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_issuer_signing_pubkey(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer_signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// Signature of the invoice verified using [`StaticInvoice::signing_pubkey`].
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_signature(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::SchnorrSignature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signature();
	crate::c_types::SchnorrSignature::from_rust(&ret)
}

/// Whether the [`Offer`] that this invoice is based on is expired.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_is_offer_expired(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_offer_expired();
	ret
}

/// Whether the [`Offer`] that this invoice is based on is expired, given the current time as
/// duration since the Unix epoch.
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_is_offer_expired_no_std(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice, mut duration_since_epoch: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_offer_expired_no_std(core::time::Duration::from_secs(duration_since_epoch));
	ret
}

/// Returns the [`OfferId`] corresponding to the originating [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[no_mangle]
pub extern "C" fn StaticInvoice_offer_id(this_arg: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::lightning::offers::offer::OfferId {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_id();
	crate::lightning::offers::offer::OfferId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Serialize the StaticInvoice object into a byte array which can be read by StaticInvoice_read
pub extern "C" fn StaticInvoice_write(obj: &crate::lightning::offers::static_invoice::StaticInvoice) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn StaticInvoice_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::static_invoice::nativeStaticInvoice) })
}
#[no_mangle]
/// Read a StaticInvoice from a byte array, created by StaticInvoice_write
pub extern "C" fn StaticInvoice_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_StaticInvoiceDecodeErrorZ {
	let res: Result<lightning::offers::static_invoice::StaticInvoice, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::static_invoice::StaticInvoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
