// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for refunds.
//!
//! A [`Refund`] is an \"offer for money\" and is typically constructed by a merchant and presented
//! directly to the customer. The recipient responds with a [`Bolt12Invoice`] to be paid.
//!
//! This is an [`InvoiceRequest`] produced *not* in response to an [`Offer`].
//!
//! [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
//! [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
//! [`Offer`]: crate::offers::offer::Offer
//!
//! # Example
//!
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::convert::TryFrom;
//! use core::time::Duration;
//!
//! use bitcoin::network::Network;
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::parse::Bolt12ParseError;
//! use lightning::offers::refund::{Refund, RefundBuilder};
//! use lightning::util::ser::{Readable, Writeable};
//!
//! # use lightning::blinded_path::message::BlindedMessagePath;
//! # #[cfg(feature = \"std\")]
//! # use std::time::SystemTime;
//! #
//! # fn create_blinded_path() -> BlindedMessagePath { unimplemented!() }
//! # fn create_another_blinded_path() -> BlindedMessagePath { unimplemented!() }
//! #
//! # #[cfg(feature = \"std\")]
//! # fn build() -> Result<(), Bolt12ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
//! let pubkey = PublicKey::from(keys);
//!
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let refund = RefundBuilder::new(vec![1; 32], pubkey, 20_000)?
//!     .description(\"coffee, large\".to_string())
//!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
//!     .issuer(\"Foo Bar\".to_string())
//!     .path(create_blinded_path())
//!     .path(create_another_blinded_path())
//!     .chain(Network::Bitcoin)
//!     .payer_note(\"refund for order #12345\".to_string())
//!     .build()?;
//!
//! // Encode as a bech32 string for use in a QR code.
//! let encoded_refund = refund.to_string();
//!
//! // Parse from a bech32 string after scanning from a QR code.
//! let refund = encoded_refund.parse::<Refund>()?;
//!
//! // Encode refund as raw bytes.
//! let mut bytes = Vec::new();
//! refund.write(&mut bytes).unwrap();
//!
//! // Decode raw bytes into an refund.
//! let refund = Refund::try_from(bytes)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Note
//!
//! If constructing a [`Refund`] for use with a [`ChannelManager`], use
//! [`ChannelManager::create_refund_builder`] instead of [`RefundBuilder::new`].
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelManager::create_refund_builder`]: crate::ln::channelmanager::ChannelManager::create_refund_builder

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder as nativeRefundMaybeWithDerivedMetadataBuilderImport;
pub(crate) type nativeRefundMaybeWithDerivedMetadataBuilder = nativeRefundMaybeWithDerivedMetadataBuilderImport<'static, >;

/// Builds a [`Refund`] for the \"offer for money\" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[must_use]
#[repr(C)]
pub struct RefundMaybeWithDerivedMetadataBuilder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRefundMaybeWithDerivedMetadataBuilder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for RefundMaybeWithDerivedMetadataBuilder {
	type Target = nativeRefundMaybeWithDerivedMetadataBuilder;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for RefundMaybeWithDerivedMetadataBuilder { }
unsafe impl core::marker::Sync for RefundMaybeWithDerivedMetadataBuilder { }
impl Drop for RefundMaybeWithDerivedMetadataBuilder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRefundMaybeWithDerivedMetadataBuilder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RefundMaybeWithDerivedMetadataBuilder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_free(this_obj: RefundMaybeWithDerivedMetadataBuilder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RefundMaybeWithDerivedMetadataBuilder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRefundMaybeWithDerivedMetadataBuilder) };
}
#[allow(unused)]
impl RefundMaybeWithDerivedMetadataBuilder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRefundMaybeWithDerivedMetadataBuilder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRefundMaybeWithDerivedMetadataBuilder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRefundMaybeWithDerivedMetadataBuilder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for RefundMaybeWithDerivedMetadataBuilder {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRefundMaybeWithDerivedMetadataBuilder>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RefundMaybeWithDerivedMetadataBuilder_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRefundMaybeWithDerivedMetadataBuilder)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RefundMaybeWithDerivedMetadataBuilder
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_clone(orig: &RefundMaybeWithDerivedMetadataBuilder) -> RefundMaybeWithDerivedMetadataBuilder {
	orig.clone()
}
/// Creates a new builder for a refund using the `signing_pubkey` for the public node id to send
/// to if no [`Refund::paths`] are set. Otherwise, `signing_pubkey` may be a transient pubkey.
///
/// Additionally, sets the required (empty) [`Refund::description`], [`Refund::payer_metadata`],
/// and [`Refund::amount_msats`].
///
/// # Note
///
/// If constructing a [`Refund`] for use with a [`ChannelManager`], use
/// [`ChannelManager::create_refund_builder`] instead of [`RefundBuilder::new`].
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`ChannelManager::create_refund_builder`]: crate::ln::channelmanager::ChannelManager::create_refund_builder
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_new(mut metadata: crate::c_types::derived::CVec_u8Z, mut signing_pubkey: crate::c_types::PublicKey, mut amount_msats: u64) -> crate::c_types::derived::CResult_RefundMaybeWithDerivedMetadataBuilderBolt12SemanticErrorZ {
	let mut local_metadata = Vec::new(); for mut item in metadata.into_rust().drain(..) { local_metadata.push( { item }); };
	let mut ret = lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder::new(local_metadata, signing_pubkey.into_rust(), amount_msats);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Similar to [`RefundBuilder::new`] except, if [`RefundBuilder::path`] is called, the payer id
/// is derived from the given [`ExpandedKey`] and nonce. This provides sender privacy by using a
/// different payer id for each refund, assuming a different nonce is used.  Otherwise, the
/// provided `node_id` is used for the payer id.
///
/// Also, sets the metadata when [`RefundBuilder::build`] is called such that it can be used by
/// [`Bolt12Invoice::verify_using_metadata`] to determine if the invoice was produced for the
/// refund given an [`ExpandedKey`]. However, if [`RefundBuilder::path`] is called, then the
/// metadata must be included in each [`BlindedMessagePath`] instead. In this case, use
/// [`Bolt12Invoice::verify_using_payer_data`].
///
/// The `payment_id` is encrypted in the metadata and should be unique. This ensures that only
/// one invoice will be paid for the refund and that payments can be uniquely identified.
///
/// [`Bolt12Invoice::verify_using_metadata`]: crate::offers::invoice::Bolt12Invoice::verify_using_metadata
/// [`Bolt12Invoice::verify_using_payer_data`]: crate::offers::invoice::Bolt12Invoice::verify_using_payer_data
/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_deriving_signing_pubkey(mut node_id: crate::c_types::PublicKey, expanded_key: &crate::lightning::ln::inbound_payment::ExpandedKey, mut nonce: crate::lightning::offers::nonce::Nonce, mut amount_msats: u64, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_RefundMaybeWithDerivedMetadataBuilderBolt12SemanticErrorZ {
	let mut ret = lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder::deriving_signing_pubkey(node_id.into_rust(), expanded_key.get_native_ref(), *unsafe { Box::from_raw(nonce.take_inner()) }, secp256k1::global::SECP256K1, amount_msats, ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets the [`Refund::description`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_description(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder, mut description: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).description(description.into_string());
	() /*ret*/
}

/// Sets the [`Refund::absolute_expiry`] as seconds since the Unix epoch.
///Any expiry that has already passed is valid and can be checked for using [`Refund::is_expired`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_absolute_expiry(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder, mut absolute_expiry: u64) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).absolute_expiry(core::time::Duration::from_secs(absolute_expiry));
	() /*ret*/
}

/// Sets the [`Refund::issuer`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_issuer(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder, mut issuer: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).issuer(issuer.into_string());
	() /*ret*/
}

/// Adds a blinded path to [`Refund::paths`]. Must include at least one path if only connected
/// by private channels or if [`Refund::payer_signing_pubkey`] is not a public node id.
///
/// Successive calls to this method will add another blinded path. Caller is responsible for not
/// adding duplicate paths.
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_path(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder, mut path: crate::lightning::blinded_path::message::BlindedMessagePath) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).path(*unsafe { Box::from_raw(path.take_inner()) });
	() /*ret*/
}

/// Sets the [`Refund::chain`] of the given [`Network`] for paying an invoice. If not
/// called, [`Network::Bitcoin`] is assumed.
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_chain(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder, mut network: crate::bitcoin::network::Network) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).chain(network.into_bitcoin());
	() /*ret*/
}

/// Sets [`Refund::quantity`] of items. This is purely for informational purposes. It is useful
/// when the refund pertains to a [`Bolt12Invoice`] that paid for more than one item from an
/// [`Offer`] as specified by [`InvoiceRequest::quantity`].
///
/// Successive calls to this method will override the previous setting.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`InvoiceRequest::quantity`]: crate::offers::invoice_request::InvoiceRequest::quantity
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_quantity(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder, mut quantity: u64) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).quantity(quantity);
	() /*ret*/
}

/// Sets the [`Refund::payer_note`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_payer_note(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder, mut payer_note: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).payer_note(payer_note.into_string());
	() /*ret*/
}

/// Builds a [`Refund`] after checking for valid semantics.
#[must_use]
#[no_mangle]
pub extern "C" fn RefundMaybeWithDerivedMetadataBuilder_build(mut this_arg: crate::lightning::offers::refund::RefundMaybeWithDerivedMetadataBuilder) -> crate::c_types::derived::CResult_RefundBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).build();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::refund::Refund { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}


use lightning::offers::refund::Refund as nativeRefundImport;
pub(crate) type nativeRefund = nativeRefundImport;

/// A `Refund` is a request to send an [`Bolt12Invoice`] without a preceding [`Offer`].
///
/// Typically, after an invoice is paid, the recipient may publish a refund allowing the sender to
/// recoup their funds. A refund may be used more generally as an \"offer for money\", such as with a
/// bitcoin ATM.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[repr(C)]
pub struct Refund {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRefund,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Refund {
	type Target = nativeRefund;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Refund { }
unsafe impl core::marker::Sync for Refund { }
impl Drop for Refund {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRefund>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Refund, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Refund_free(this_obj: Refund) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Refund_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRefund) };
}
#[allow(unused)]
impl Refund {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRefund {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRefund {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRefund {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for Refund {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRefund>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Refund_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRefund)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Refund
pub extern "C" fn Refund_clone(orig: &Refund) -> Refund {
	orig.clone()
}
/// Get a string which allows debug introspection of a Refund object
pub extern "C" fn Refund_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::refund::Refund }).into()}
/// A complete description of the purpose of the refund. Intended to be displayed to the user
/// but with the caveat that it has not been verified in any way.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_description(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	crate::lightning_types::string::PrintableString { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Duration since the Unix epoch when an invoice should no longer be sent.
///
/// If `None`, the refund does not expire.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_absolute_expiry(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// Whether the refund has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_is_expired(this_arg: &crate::lightning::offers::refund::Refund) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// Whether the refund has expired given the duration since the Unix epoch.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_is_expired_no_std(this_arg: &crate::lightning::offers::refund::Refund, mut duration_since_epoch: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired_no_std(core::time::Duration::from_secs(duration_since_epoch));
	ret
}

/// The issuer of the refund, possibly beginning with `user@domain` or `domain`. Intended to be
/// displayed to the user but with the caveat that it has not been verified in any way.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_issuer(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the sender originating from publicly reachable nodes. Blinded paths provide sender
/// privacy by obfuscating its node id.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_paths(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// An unpredictable series of bytes, typically containing information about the derivation of
/// [`payer_signing_pubkey`].
///
/// [`payer_signing_pubkey`]: Self::payer_signing_pubkey
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_payer_metadata(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// A chain that the refund is valid for.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_chain(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// The amount to refund in msats (i.e., the minimum lightning-payable unit for [`chain`]).
///
/// [`chain`]: Self::chain
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_amount_msats(this_arg: &crate::lightning::offers::refund::Refund) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	ret
}

/// Features pertaining to requesting an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_features(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning_types::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.features();
	crate::lightning_types::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of an item that refund is for.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_quantity(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A public node id to send to in the case where there are no [`paths`]. Otherwise, a possibly
/// transient pubkey.
///
/// [`paths`]: Self::paths
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_payer_signing_pubkey(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Payer provided note to include in the invoice.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_payer_note(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Generates a non-cryptographic 64-bit hash of the Refund.
#[no_mangle]
pub extern "C" fn Refund_hash(o: &Refund) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Read a Refund from a byte array, created by Refund_write
pub extern "C" fn Refund_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RefundDecodeErrorZ {
	let res: Result<lightning::offers::refund::Refund, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::refund::Refund { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the Refund object into a byte array which can be read by Refund_read
pub extern "C" fn Refund_write(obj: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Refund_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::refund::nativeRefund) })
}
#[no_mangle]
/// Read a Refund object from a string
pub extern "C" fn Refund_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_RefundBolt12ParseErrorZ {
	match lightning::offers::refund::Refund::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning::offers::refund::Refund { inner: ObjOps::heap_alloc(r), is_owned: true }
			)
		},
		Err(e) => {
			crate::c_types::CResultTempl::err(
				crate::lightning::offers::parse::Bolt12ParseError { inner: ObjOps::heap_alloc(e), is_owned: true }
			)
		},
	}.into()
}
#[no_mangle]
/// Get the string representation of a Refund object
pub extern "C" fn Refund_to_str(o: &crate::lightning::offers::refund::Refund) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}
