// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for `offer` messages.
//!
//! An [`Offer`] represents an \"offer to be paid.\" It is typically constructed by a merchant and
//! published as a QR code to be scanned by a customer. The customer uses the offer to request an
//! invoice from the merchant to be paid.
//!
//! # Example
//!
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::convert::TryFrom;
//! use core::num::NonZeroU64;
//! use core::time::Duration;
//!
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::offer::{Offer, OfferBuilder, Quantity};
//! use lightning::offers::parse::Bolt12ParseError;
//! use lightning::util::ser::{Readable, Writeable};
//!
//! # use lightning::blinded_path::BlindedPath;
//! # #[cfg(feature = \"std\")]
//! # use std::time::SystemTime;
//! #
//! # fn create_blinded_path() -> BlindedPath { unimplemented!() }
//! # fn create_another_blinded_path() -> BlindedPath { unimplemented!() }
//! #
//! # #[cfg(feature = \"std\")]
//! # fn build() -> Result<(), Bolt12ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
//! let pubkey = PublicKey::from(keys);
//!
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let offer = OfferBuilder::new(pubkey)
//!     .description(\"coffee, large\".to_string())
//!     .amount_msats(20_000)
//!     .supported_quantity(Quantity::Unbounded)
//!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
//!     .issuer(\"Foo Bar\".to_string())
//!     .path(create_blinded_path())
//!     .path(create_another_blinded_path())
//!     .build()?;
//!
//! // Encode as a bech32 string for use in a QR code.
//! let encoded_offer = offer.to_string();
//!
//! // Parse from a bech32 string after scanning from a QR code.
//! let offer = encoded_offer.parse::<Offer>()?;
//!
//! // Encode offer as raw bytes.
//! let mut bytes = Vec::new();
//! offer.write(&mut bytes).unwrap();
//!
//! // Decode raw bytes into an offer.
//! let offer = Offer::try_from(bytes)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Note
//!
//! If constructing an [`Offer`] for use with a [`ChannelManager`], use
//! [`ChannelManager::create_offer_builder`] instead of [`OfferBuilder::new`].
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelManager::create_offer_builder`]: crate::ln::channelmanager::ChannelManager::create_offer_builder

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::offer::OfferId as nativeOfferIdImport;
pub(crate) type nativeOfferId = nativeOfferIdImport;

/// An identifier for an [`Offer`] built using [`DerivedMetadata`].
#[must_use]
#[repr(C)]
pub struct OfferId {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOfferId,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OfferId {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOfferId>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OfferId, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OfferId_free(this_obj: OfferId) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferId_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOfferId) };
}
#[allow(unused)]
impl OfferId {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOfferId {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOfferId {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOfferId {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn OfferId_get_a(this_ptr: &OfferId) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val
}
#[no_mangle]
pub extern "C" fn OfferId_set_a(this_ptr: &mut OfferId, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.data;
}
/// Constructs a new OfferId given each field
#[must_use]
#[no_mangle]
pub extern "C" fn OfferId_new(mut a_arg: crate::c_types::ThirtyTwoBytes) -> OfferId {
	OfferId { inner: ObjOps::heap_alloc(lightning::offers::offer::OfferId (
		a_arg.data,
	)), is_owned: true }
}
impl Clone for OfferId {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOfferId>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferId_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOfferId)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OfferId
pub extern "C" fn OfferId_clone(orig: &OfferId) -> OfferId {
	orig.clone()
}
/// Get a string which allows debug introspection of a OfferId object
pub extern "C" fn OfferId_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::offer::OfferId }).into()}
/// Checks if two OfferIds contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn OfferId_eq(a: &OfferId, b: &OfferId) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the OfferId object into a byte array which can be read by OfferId_read
pub extern "C" fn OfferId_write(obj: &crate::lightning::offers::offer::OfferId) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn OfferId_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeOfferId) })
}
#[no_mangle]
/// Read a OfferId from a byte array, created by OfferId_write
pub extern "C" fn OfferId_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OfferIdDecodeErrorZ {
	let res: Result<lightning::offers::offer::OfferId, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::offer::OfferId { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::offers::offer::OfferWithExplicitMetadataBuilder as nativeOfferWithExplicitMetadataBuilderImport;
pub(crate) type nativeOfferWithExplicitMetadataBuilder = nativeOfferWithExplicitMetadataBuilderImport<'static, >;

/// Builds an [`Offer`] for the \"offer to be paid\" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[must_use]
#[repr(C)]
pub struct OfferWithExplicitMetadataBuilder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOfferWithExplicitMetadataBuilder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OfferWithExplicitMetadataBuilder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOfferWithExplicitMetadataBuilder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OfferWithExplicitMetadataBuilder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_free(this_obj: OfferWithExplicitMetadataBuilder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferWithExplicitMetadataBuilder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOfferWithExplicitMetadataBuilder) };
}
#[allow(unused)]
impl OfferWithExplicitMetadataBuilder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOfferWithExplicitMetadataBuilder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOfferWithExplicitMetadataBuilder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOfferWithExplicitMetadataBuilder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for OfferWithExplicitMetadataBuilder {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOfferWithExplicitMetadataBuilder>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferWithExplicitMetadataBuilder_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOfferWithExplicitMetadataBuilder)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OfferWithExplicitMetadataBuilder
pub extern "C" fn OfferWithExplicitMetadataBuilder_clone(orig: &OfferWithExplicitMetadataBuilder) -> OfferWithExplicitMetadataBuilder {
	orig.clone()
}

use lightning::offers::offer::OfferWithDerivedMetadataBuilder as nativeOfferWithDerivedMetadataBuilderImport;
pub(crate) type nativeOfferWithDerivedMetadataBuilder = nativeOfferWithDerivedMetadataBuilderImport<'static, >;

/// Builds an [`Offer`] for the \"offer to be paid\" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[must_use]
#[repr(C)]
pub struct OfferWithDerivedMetadataBuilder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOfferWithDerivedMetadataBuilder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OfferWithDerivedMetadataBuilder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOfferWithDerivedMetadataBuilder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OfferWithDerivedMetadataBuilder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_free(this_obj: OfferWithDerivedMetadataBuilder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferWithDerivedMetadataBuilder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOfferWithDerivedMetadataBuilder) };
}
#[allow(unused)]
impl OfferWithDerivedMetadataBuilder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOfferWithDerivedMetadataBuilder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOfferWithDerivedMetadataBuilder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOfferWithDerivedMetadataBuilder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for OfferWithDerivedMetadataBuilder {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOfferWithDerivedMetadataBuilder>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferWithDerivedMetadataBuilder_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOfferWithDerivedMetadataBuilder)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OfferWithDerivedMetadataBuilder
pub extern "C" fn OfferWithDerivedMetadataBuilder_clone(orig: &OfferWithDerivedMetadataBuilder) -> OfferWithDerivedMetadataBuilder {
	orig.clone()
}
/// Creates a new builder for an offer using the [`Offer::signing_pubkey`] for signing invoices.
/// The associated secret key must be remembered while the offer is valid.
///
/// Use a different pubkey per offer to avoid correlating offers.
///
/// # Note
///
/// If constructing an [`Offer`] for use with a [`ChannelManager`], use
/// [`ChannelManager::create_offer_builder`] instead of [`OfferBuilder::new`].
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`ChannelManager::create_offer_builder`]: crate::ln::channelmanager::ChannelManager::create_offer_builder
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_new(mut signing_pubkey: crate::c_types::PublicKey) -> crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder {
	let mut ret = lightning::offers::offer::OfferWithExplicitMetadataBuilder::new(signing_pubkey.into_rust());
	crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Sets the [`Offer::metadata`] to the given bytes.
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_metadata(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut metadata: crate::c_types::derived::CVec_u8Z) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut local_metadata = Vec::new(); for mut item in metadata.into_rust().drain(..) { local_metadata.push( { item }); };
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).metadata(local_metadata);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Adds the chain hash of the given [`Network`] to [`Offer::chains`]. If not called,
/// the chain hash of [`Network::Bitcoin`] is assumed to be the only one supported.
///
/// See [`Offer::chains`] on how this relates to the payment currency.
///
/// Successive calls to this method will add another chain hash.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_chain(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut network: crate::bitcoin::network::Network) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).chain(network.into_bitcoin());
	() /*ret*/
}

/// Sets the [`Offer::amount`] as an [`Amount::Bitcoin`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_amount_msats(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut amount_msats: u64) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).amount_msats(amount_msats);
	() /*ret*/
}

/// Sets the [`Offer::absolute_expiry`] as seconds since the Unix epoch. Any expiry that has
/// already passed is valid and can be checked for using [`Offer::is_expired`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_absolute_expiry(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut absolute_expiry: u64) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).absolute_expiry(core::time::Duration::from_secs(absolute_expiry));
	() /*ret*/
}

/// Sets the [`Offer::description`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_description(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut description: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).description(description.into_string());
	() /*ret*/
}

/// Sets the [`Offer::issuer`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_issuer(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut issuer: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).issuer(issuer.into_string());
	() /*ret*/
}

/// Adds a blinded path to [`Offer::paths`]. Must include at least one path if only connected by
/// private channels or if [`Offer::signing_pubkey`] is not a public node id.
///
/// Successive calls to this method will add another blinded path. Caller is responsible for not
/// adding duplicate paths.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_path(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut path: crate::lightning::blinded_path::BlindedPath) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).path(*unsafe { Box::from_raw(path.take_inner()) });
	() /*ret*/
}

/// Sets the quantity of items for [`Offer::supported_quantity`]. If not called, defaults to
/// [`Quantity::One`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_supported_quantity(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder, mut quantity: crate::lightning::offers::offer::Quantity) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).supported_quantity(quantity.into_native());
	() /*ret*/
}

/// Builds an [`Offer`] from the builder's settings.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithExplicitMetadataBuilder_build(mut this_arg: crate::lightning::offers::offer::OfferWithExplicitMetadataBuilder) -> crate::c_types::derived::CResult_OfferBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).build();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::offer::Offer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Similar to [`OfferBuilder::new`] except, if [`OfferBuilder::path`] is called, the signing
/// pubkey is derived from the given [`ExpandedKey`] and [`EntropySource`]. This provides
/// recipient privacy by using a different signing pubkey for each offer. Otherwise, the
/// provided `node_id` is used for the signing pubkey.
///
/// Also, sets the metadata when [`OfferBuilder::build`] is called such that it can be used by
/// [`InvoiceRequest::verify`] to determine if the request was produced for the offer given an
/// [`ExpandedKey`].
///
/// [`InvoiceRequest::verify`]: crate::offers::invoice_request::InvoiceRequest::verify
/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_deriving_signing_pubkey(mut node_id: crate::c_types::PublicKey, expanded_key: &crate::lightning::ln::inbound_payment::ExpandedKey, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder {
	let mut ret = lightning::offers::offer::OfferWithDerivedMetadataBuilder::deriving_signing_pubkey(node_id.into_rust(), expanded_key.get_native_ref(), entropy_source, secp256k1::global::SECP256K1);
	crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Adds the chain hash of the given [`Network`] to [`Offer::chains`]. If not called,
/// the chain hash of [`Network::Bitcoin`] is assumed to be the only one supported.
///
/// See [`Offer::chains`] on how this relates to the payment currency.
///
/// Successive calls to this method will add another chain hash.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_chain(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder, mut network: crate::bitcoin::network::Network) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).chain(network.into_bitcoin());
	() /*ret*/
}

/// Sets the [`Offer::amount`] as an [`Amount::Bitcoin`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_amount_msats(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder, mut amount_msats: u64) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).amount_msats(amount_msats);
	() /*ret*/
}

/// Sets the [`Offer::absolute_expiry`] as seconds since the Unix epoch. Any expiry that has
/// already passed is valid and can be checked for using [`Offer::is_expired`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_absolute_expiry(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder, mut absolute_expiry: u64) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).absolute_expiry(core::time::Duration::from_secs(absolute_expiry));
	() /*ret*/
}

/// Sets the [`Offer::description`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_description(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder, mut description: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).description(description.into_string());
	() /*ret*/
}

/// Sets the [`Offer::issuer`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_issuer(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder, mut issuer: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).issuer(issuer.into_string());
	() /*ret*/
}

/// Adds a blinded path to [`Offer::paths`]. Must include at least one path if only connected by
/// private channels or if [`Offer::signing_pubkey`] is not a public node id.
///
/// Successive calls to this method will add another blinded path. Caller is responsible for not
/// adding duplicate paths.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_path(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder, mut path: crate::lightning::blinded_path::BlindedPath) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).path(*unsafe { Box::from_raw(path.take_inner()) });
	() /*ret*/
}

/// Sets the quantity of items for [`Offer::supported_quantity`]. If not called, defaults to
/// [`Quantity::One`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_supported_quantity(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder, mut quantity: crate::lightning::offers::offer::Quantity) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).supported_quantity(quantity.into_native());
	() /*ret*/
}

/// Builds an [`Offer`] from the builder's settings.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferWithDerivedMetadataBuilder_build(mut this_arg: crate::lightning::offers::offer::OfferWithDerivedMetadataBuilder) -> crate::c_types::derived::CResult_OfferBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).build();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::offer::Offer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}


use lightning::offers::offer::Offer as nativeOfferImport;
pub(crate) type nativeOffer = nativeOfferImport;

/// An `Offer` is a potentially long-lived proposal for payment of a good or service.
///
/// An offer is a precursor to an [`InvoiceRequest`]. A merchant publishes an offer from which a
/// customer may request an [`Bolt12Invoice`] for a specific quantity and using an amount sufficient
/// to cover that quantity (i.e., at least `quantity * amount`). See [`Offer::amount`].
///
/// Offers may be denominated in currency other than bitcoin but are ultimately paid using the
/// latter.
///
/// Through the use of [`BlindedPath`]s, offers provide recipient privacy.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[repr(C)]
pub struct Offer {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOffer,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Offer {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOffer>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Offer, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Offer_free(this_obj: Offer) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Offer_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOffer) };
}
#[allow(unused)]
impl Offer {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOffer {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOffer {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOffer {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Offer {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOffer>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Offer_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOffer)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Offer
pub extern "C" fn Offer_clone(orig: &Offer) -> Offer {
	orig.clone()
}
/// Get a string which allows debug introspection of a Offer object
pub extern "C" fn Offer_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::offer::Offer }).into()}
/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
/// for the selected chain.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_chains(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::CVec_ThirtyTwoBytesZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chains();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); };
	local_ret.into()
}

/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_metadata(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_amount(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::COption_AmountZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_AmountZ::None } else { crate::c_types::derived::COption_AmountZ::Some( { crate::lightning::offers::offer::Amount::native_into(ret.unwrap()) }) };
	local_ret
}

/// A complete description of the purpose of the payment. Intended to be displayed to the user
/// but with the caveat that it has not been verified in any way.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_description(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Features pertaining to the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_offer_features(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::ln::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	crate::lightning::ln::features::OfferFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::OfferFeatures<>) as *mut _) }, is_owned: false }
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// If `None`, the offer does not expire.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_absolute_expiry(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// The issuer of the offer, possibly beginning with `user@domain` or `domain`. Intended to be
/// displayed to the user but with the caveat that it has not been verified in any way.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_issuer(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
/// recipient privacy by obfuscating its node id.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_paths(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::CVec_BlindedPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_supported_quantity(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	crate::lightning::offers::offer::Quantity::native_into(ret)
}

/// The public key used by the recipient to sign invoices.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_signing_pubkey(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// Returns the id of the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_id(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::offers::offer::OfferId {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.id();
	crate::lightning::offers::offer::OfferId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns whether the given chain is supported by the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_supports_chain(this_arg: &crate::lightning::offers::offer::Offer, mut chain: crate::c_types::ThirtyTwoBytes) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_chain(::bitcoin::blockdata::constants::ChainHash::from(&chain.data));
	ret
}

/// Whether the offer has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_is_expired(this_arg: &crate::lightning::offers::offer::Offer) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// Whether the offer has expired given the duration since the Unix epoch.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_is_expired_no_std(this_arg: &crate::lightning::offers::offer::Offer, mut duration_since_epoch: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired_no_std(core::time::Duration::from_secs(duration_since_epoch));
	ret
}

/// Returns whether the given quantity is valid for the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_is_valid_quantity(this_arg: &crate::lightning::offers::offer::Offer, mut quantity: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_valid_quantity(quantity);
	ret
}

/// Returns whether a quantity is expected in an [`InvoiceRequest`] for the offer.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_expects_quantity(this_arg: &crate::lightning::offers::offer::Offer) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.expects_quantity();
	ret
}

/// Similar to [`Offer::request_invoice`] except it:
/// - derives the [`InvoiceRequest::payer_id`] such that a different key can be used for each
///   request,
/// - sets [`InvoiceRequest::payer_metadata`] when [`InvoiceRequestBuilder::build`] is called
///   such that it can be used by [`Bolt12Invoice::verify`] to determine if the invoice was
///   requested using a base [`ExpandedKey`] from which the payer id was derived, and
/// - includes the [`PaymentId`] encrypted in [`InvoiceRequest::payer_metadata`] so that it can
///   be used when sending the payment for the requested invoice.
///
/// Useful to protect the sender's privacy.
///
/// [`InvoiceRequest::payer_id`]: crate::offers::invoice_request::InvoiceRequest::payer_id
/// [`InvoiceRequest::payer_metadata`]: crate::offers::invoice_request::InvoiceRequest::payer_metadata
/// [`Bolt12Invoice::verify`]: crate::offers::invoice::Bolt12Invoice::verify
/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_request_invoice_deriving_payer_id(this_arg: &crate::lightning::offers::offer::Offer, expanded_key: &crate::lightning::ln::inbound_payment::ExpandedKey, mut entropy_source: crate::lightning::sign::EntropySource, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_InvoiceRequestWithDerivedPayerIdBuilderBolt12SemanticErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.request_invoice_deriving_payer_id(expanded_key.get_native_ref(), entropy_source, secp256k1::global::SECP256K1, ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::InvoiceRequestWithDerivedPayerIdBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Similar to [`Offer::request_invoice_deriving_payer_id`] except uses `payer_id` for the
/// [`InvoiceRequest::payer_id`] instead of deriving a different key for each request.
///
/// Useful for recurring payments using the same `payer_id` with different invoices.
///
/// [`InvoiceRequest::payer_id`]: crate::offers::invoice_request::InvoiceRequest::payer_id
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_request_invoice_deriving_metadata(this_arg: &crate::lightning::offers::offer::Offer, mut payer_id: crate::c_types::PublicKey, expanded_key: &crate::lightning::ln::inbound_payment::ExpandedKey, mut entropy_source: crate::lightning::sign::EntropySource, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_InvoiceRequestWithExplicitPayerIdBuilderBolt12SemanticErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.request_invoice_deriving_metadata(payer_id.into_rust(), expanded_key.get_native_ref(), entropy_source, ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Creates an [`InvoiceRequestBuilder`] for the offer with the given `metadata` and `payer_id`,
/// which will be reflected in the `Bolt12Invoice` response.
///
/// The `metadata` is useful for including information about the derivation of `payer_id` such
/// that invoice response handling can be stateless. Also serves as payer-provided entropy while
/// hashing in the signature calculation.
///
/// This should not leak any information such as by using a simple BIP-32 derivation path.
/// Otherwise, payments may be correlated.
///
/// Errors if the offer contains unknown required features.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_request_invoice(this_arg: &crate::lightning::offers::offer::Offer, mut metadata: crate::c_types::derived::CVec_u8Z, mut payer_id: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_InvoiceRequestWithExplicitPayerIdBuilderBolt12SemanticErrorZ {
	let mut local_metadata = Vec::new(); for mut item in metadata.into_rust().drain(..) { local_metadata.push( { item }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.request_invoice(local_metadata, payer_id.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Generates a non-cryptographic 64-bit hash of the Offer.
#[no_mangle]
pub extern "C" fn Offer_hash(o: &Offer) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Serialize the Offer object into a byte array which can be read by Offer_read
pub extern "C" fn Offer_write(obj: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Offer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeOffer) })
}
/// The minimum amount required for an item in an [`Offer`], denominated in either bitcoin or
/// another currency.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Amount {
	/// An amount of bitcoin.
	Bitcoin {
		/// The amount in millisatoshi.
		amount_msats: u64,
	},
	/// An amount of currency specified using ISO 4712.
	Currency {
		/// The currency that the amount is denominated in.
		iso4217_code: crate::c_types::ThreeBytes,
		/// The amount in the currency unit adjusted by the ISO 4712 exponent (e.g., USD cents).
		amount: u64,
	},
}
use lightning::offers::offer::Amount as AmountImport;
pub(crate) type nativeAmount = AmountImport;

impl Amount {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeAmount {
		match self {
			Amount::Bitcoin {ref amount_msats, } => {
				let mut amount_msats_nonref = Clone::clone(amount_msats);
				nativeAmount::Bitcoin {
					amount_msats: amount_msats_nonref,
				}
			},
			Amount::Currency {ref iso4217_code, ref amount, } => {
				let mut iso4217_code_nonref = Clone::clone(iso4217_code);
				let mut amount_nonref = Clone::clone(amount);
				nativeAmount::Currency {
					iso4217_code: iso4217_code_nonref.data,
					amount: amount_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeAmount {
		match self {
			Amount::Bitcoin {mut amount_msats, } => {
				nativeAmount::Bitcoin {
					amount_msats: amount_msats,
				}
			},
			Amount::Currency {mut iso4217_code, mut amount, } => {
				nativeAmount::Currency {
					iso4217_code: iso4217_code.data,
					amount: amount,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &AmountImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeAmount) };
		match native {
			nativeAmount::Bitcoin {ref amount_msats, } => {
				let mut amount_msats_nonref = Clone::clone(amount_msats);
				Amount::Bitcoin {
					amount_msats: amount_msats_nonref,
				}
			},
			nativeAmount::Currency {ref iso4217_code, ref amount, } => {
				let mut iso4217_code_nonref = Clone::clone(iso4217_code);
				let mut amount_nonref = Clone::clone(amount);
				Amount::Currency {
					iso4217_code: crate::c_types::ThreeBytes { data: iso4217_code_nonref },
					amount: amount_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeAmount) -> Self {
		match native {
			nativeAmount::Bitcoin {mut amount_msats, } => {
				Amount::Bitcoin {
					amount_msats: amount_msats,
				}
			},
			nativeAmount::Currency {mut iso4217_code, mut amount, } => {
				Amount::Currency {
					iso4217_code: crate::c_types::ThreeBytes { data: iso4217_code },
					amount: amount,
				}
			},
		}
	}
}
/// Frees any resources used by the Amount
#[no_mangle]
pub extern "C" fn Amount_free(this_ptr: Amount) { }
/// Creates a copy of the Amount
#[no_mangle]
pub extern "C" fn Amount_clone(orig: &Amount) -> Amount {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Amount_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Amount)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Amount_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Amount) };
}
#[no_mangle]
/// Utility method to constructs a new Bitcoin-variant Amount
pub extern "C" fn Amount_bitcoin(amount_msats: u64) -> Amount {
	Amount::Bitcoin {
		amount_msats,
	}
}
#[no_mangle]
/// Utility method to constructs a new Currency-variant Amount
pub extern "C" fn Amount_currency(iso4217_code: crate::c_types::ThreeBytes, amount: u64) -> Amount {
	Amount::Currency {
		iso4217_code,
		amount,
	}
}
/// Get a string which allows debug introspection of a Amount object
pub extern "C" fn Amount_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::offer::Amount }).into()}
/// Quantity of items supported by an [`Offer`].
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Quantity {
	/// Up to a specific number of items (inclusive). Use when more than one item can be requested
	/// but is limited (e.g., because of per customer or inventory limits).
	///
	/// May be used with `NonZeroU64::new(1)` but prefer to use [`Quantity::One`] if only one item
	/// is supported.
	Bounded(
		u64),
	/// One or more items. Use when more than one item can be requested without any limit.
	Unbounded,
	/// Only one item. Use when only a single item can be requested.
	One,
}
use lightning::offers::offer::Quantity as QuantityImport;
pub(crate) type nativeQuantity = QuantityImport;

impl Quantity {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeQuantity {
		match self {
			Quantity::Bounded (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeQuantity::Bounded (
					core::num::NonZeroU64::new(a_nonref).expect("Value must be non-zero"),
				)
			},
			Quantity::Unbounded => nativeQuantity::Unbounded,
			Quantity::One => nativeQuantity::One,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeQuantity {
		match self {
			Quantity::Bounded (mut a, ) => {
				nativeQuantity::Bounded (
					core::num::NonZeroU64::new(a).expect("Value must be non-zero"),
				)
			},
			Quantity::Unbounded => nativeQuantity::Unbounded,
			Quantity::One => nativeQuantity::One,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &QuantityImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeQuantity) };
		match native {
			nativeQuantity::Bounded (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Quantity::Bounded (
					a_nonref.into(),
				)
			},
			nativeQuantity::Unbounded => Quantity::Unbounded,
			nativeQuantity::One => Quantity::One,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeQuantity) -> Self {
		match native {
			nativeQuantity::Bounded (mut a, ) => {
				Quantity::Bounded (
					a.into(),
				)
			},
			nativeQuantity::Unbounded => Quantity::Unbounded,
			nativeQuantity::One => Quantity::One,
		}
	}
}
/// Frees any resources used by the Quantity
#[no_mangle]
pub extern "C" fn Quantity_free(this_ptr: Quantity) { }
/// Creates a copy of the Quantity
#[no_mangle]
pub extern "C" fn Quantity_clone(orig: &Quantity) -> Quantity {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Quantity_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Quantity)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Quantity_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Quantity) };
}
#[no_mangle]
/// Utility method to constructs a new Bounded-variant Quantity
pub extern "C" fn Quantity_bounded(a: u64) -> Quantity {
	Quantity::Bounded(a, )
}
#[no_mangle]
/// Utility method to constructs a new Unbounded-variant Quantity
pub extern "C" fn Quantity_unbounded() -> Quantity {
	Quantity::Unbounded}
#[no_mangle]
/// Utility method to constructs a new One-variant Quantity
pub extern "C" fn Quantity_one() -> Quantity {
	Quantity::One}
/// Get a string which allows debug introspection of a Quantity object
pub extern "C" fn Quantity_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::offer::Quantity }).into()}
#[no_mangle]
/// Read a Offer object from a string
pub extern "C" fn Offer_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_OfferBolt12ParseErrorZ {
	match lightning::offers::offer::Offer::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning::offers::offer::Offer { inner: ObjOps::heap_alloc(r), is_owned: true }
			)
		},
		Err(e) => {
			crate::c_types::CResultTempl::err(
				crate::lightning::offers::parse::Bolt12ParseError { inner: ObjOps::heap_alloc(e), is_owned: true }
			)
		},
	}.into()
}
