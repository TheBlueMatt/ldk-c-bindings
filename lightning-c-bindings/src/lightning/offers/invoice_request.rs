// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for `invoice_request` messages.
//!
//! An [`InvoiceRequest`] can be built from a parsed [`Offer`] as an \"offer to be paid\". It is
//! typically constructed by a customer and sent to the merchant who had published the corresponding
//! offer. The recipient of the request responds with a [`Bolt12Invoice`].
//!
//! For an \"offer for money\" (e.g., refund, ATM withdrawal), where an offer doesn't exist as a
//! precursor, see [`Refund`].
//!
//! [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
//! [`Refund`]: crate::offers::refund::Refund
//!
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::network::Network;
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use lightning::ln::features::OfferFeatures;
//! use lightning::offers::invoice_request::UnsignedInvoiceRequest;
//! use lightning::offers::offer::Offer;
//! use lightning::util::ser::Writeable;
//!
//! # fn parse() -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//! let mut buffer = Vec::new();
//!
//! # use lightning::offers::invoice_request::{ExplicitPayerId, InvoiceRequestBuilder};
//! # <InvoiceRequestBuilder<ExplicitPayerId, _>>::from(
//! \"lno1qcp4256ypq\"
//!     .parse::<Offer>()?
//!     .request_invoice(vec![42; 64], pubkey)?
//! # )
//!     .chain(Network::Testnet)?
//!     .amount_msats(1000)?
//!     .quantity(5)?
//!     .payer_note(\"foo\".to_string())
//!     .build()?
//!     .sign(|message: &UnsignedInvoiceRequest|
//!         Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect(\"failed verifying signature\")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder as nativeInvoiceRequestWithExplicitPayerIdBuilderImport;
pub(crate) type nativeInvoiceRequestWithExplicitPayerIdBuilder = nativeInvoiceRequestWithExplicitPayerIdBuilderImport<'static, 'static, >;

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the \"offer to be paid\" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[must_use]
#[repr(C)]
pub struct InvoiceRequestWithExplicitPayerIdBuilder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceRequestWithExplicitPayerIdBuilder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InvoiceRequestWithExplicitPayerIdBuilder {
	type Target = nativeInvoiceRequestWithExplicitPayerIdBuilder;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InvoiceRequestWithExplicitPayerIdBuilder { }
unsafe impl core::marker::Sync for InvoiceRequestWithExplicitPayerIdBuilder { }
impl Drop for InvoiceRequestWithExplicitPayerIdBuilder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceRequestWithExplicitPayerIdBuilder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceRequestWithExplicitPayerIdBuilder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceRequestWithExplicitPayerIdBuilder_free(this_obj: InvoiceRequestWithExplicitPayerIdBuilder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequestWithExplicitPayerIdBuilder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceRequestWithExplicitPayerIdBuilder) };
}
#[allow(unused)]
impl InvoiceRequestWithExplicitPayerIdBuilder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceRequestWithExplicitPayerIdBuilder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceRequestWithExplicitPayerIdBuilder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceRequestWithExplicitPayerIdBuilder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}

use lightning::offers::invoice_request::InvoiceRequestWithDerivedPayerIdBuilder as nativeInvoiceRequestWithDerivedPayerIdBuilderImport;
pub(crate) type nativeInvoiceRequestWithDerivedPayerIdBuilder = nativeInvoiceRequestWithDerivedPayerIdBuilderImport<'static, 'static, >;

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the \"offer to be paid\" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[must_use]
#[repr(C)]
pub struct InvoiceRequestWithDerivedPayerIdBuilder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceRequestWithDerivedPayerIdBuilder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InvoiceRequestWithDerivedPayerIdBuilder {
	type Target = nativeInvoiceRequestWithDerivedPayerIdBuilder;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InvoiceRequestWithDerivedPayerIdBuilder { }
unsafe impl core::marker::Sync for InvoiceRequestWithDerivedPayerIdBuilder { }
impl Drop for InvoiceRequestWithDerivedPayerIdBuilder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceRequestWithDerivedPayerIdBuilder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceRequestWithDerivedPayerIdBuilder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceRequestWithDerivedPayerIdBuilder_free(this_obj: InvoiceRequestWithDerivedPayerIdBuilder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequestWithDerivedPayerIdBuilder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceRequestWithDerivedPayerIdBuilder) };
}
#[allow(unused)]
impl InvoiceRequestWithDerivedPayerIdBuilder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceRequestWithDerivedPayerIdBuilder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceRequestWithDerivedPayerIdBuilder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceRequestWithDerivedPayerIdBuilder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Builds an unsigned [`InvoiceRequest`] after checking for valid semantics. It can be signed
/// by [`UnsignedInvoiceRequest::sign`].
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithExplicitPayerIdBuilder_build(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder) -> crate::c_types::derived::CResult_UnsignedInvoiceRequestBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).build();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::UnsignedInvoiceRequest { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets the [`InvoiceRequest::chain`] of the given [`Network`] for paying an invoice. If not
/// called, [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported
/// by the offer.
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithExplicitPayerIdBuilder_chain(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder, mut network: crate::bitcoin::network::Network) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).chain(network.into_bitcoin());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets the [`InvoiceRequest::amount_msats`] for paying an invoice. Errors if `amount_msats` is
/// not at least the expected invoice amount (i.e., [`Offer::amount`] times [`quantity`]).
///
/// Successive calls to this method will override the previous setting.
///
/// [`quantity`]: Self::quantity
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithExplicitPayerIdBuilder_amount_msats(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder, mut amount_msats: u64) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).amount_msats(amount_msats);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets [`InvoiceRequest::quantity`] of items. If not set, `1` is assumed. Errors if `quantity`
/// does not conform to [`Offer::is_valid_quantity`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithExplicitPayerIdBuilder_quantity(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder, mut quantity: u64) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).quantity(quantity);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets the [`InvoiceRequest::payer_note`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithExplicitPayerIdBuilder_payer_note(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithExplicitPayerIdBuilder, mut payer_note: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).payer_note(payer_note.into_string());
	() /*ret*/
}

/// Builds a signed [`InvoiceRequest`] after checking for valid semantics.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithDerivedPayerIdBuilder_build_and_sign(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithDerivedPayerIdBuilder) -> crate::c_types::derived::CResult_InvoiceRequestBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).build_and_sign();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::InvoiceRequest { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets the [`InvoiceRequest::chain`] of the given [`Network`] for paying an invoice. If not
/// called, [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported
/// by the offer.
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithDerivedPayerIdBuilder_chain(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithDerivedPayerIdBuilder, mut network: crate::bitcoin::network::Network) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).chain(network.into_bitcoin());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets the [`InvoiceRequest::amount_msats`] for paying an invoice. Errors if `amount_msats` is
/// not at least the expected invoice amount (i.e., [`Offer::amount`] times [`quantity`]).
///
/// Successive calls to this method will override the previous setting.
///
/// [`quantity`]: Self::quantity
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithDerivedPayerIdBuilder_amount_msats(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithDerivedPayerIdBuilder, mut amount_msats: u64) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).amount_msats(amount_msats);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets [`InvoiceRequest::quantity`] of items. If not set, `1` is assumed. Errors if `quantity`
/// does not conform to [`Offer::is_valid_quantity`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithDerivedPayerIdBuilder_quantity(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithDerivedPayerIdBuilder, mut quantity: u64) -> crate::c_types::derived::CResult_NoneBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).quantity(quantity);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Sets the [`InvoiceRequest::payer_note`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestWithDerivedPayerIdBuilder_payer_note(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequestWithDerivedPayerIdBuilder, mut payer_note: crate::c_types::Str) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).payer_note(payer_note.into_string());
	() /*ret*/
}


use lightning::offers::invoice_request::UnsignedInvoiceRequest as nativeUnsignedInvoiceRequestImport;
pub(crate) type nativeUnsignedInvoiceRequest = nativeUnsignedInvoiceRequestImport;

/// A semantically valid [`InvoiceRequest`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
#[must_use]
#[repr(C)]
pub struct UnsignedInvoiceRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedInvoiceRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for UnsignedInvoiceRequest {
	type Target = nativeUnsignedInvoiceRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for UnsignedInvoiceRequest { }
unsafe impl core::marker::Sync for UnsignedInvoiceRequest { }
impl Drop for UnsignedInvoiceRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUnsignedInvoiceRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UnsignedInvoiceRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_free(this_obj: UnsignedInvoiceRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnsignedInvoiceRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUnsignedInvoiceRequest) };
}
#[allow(unused)]
impl UnsignedInvoiceRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUnsignedInvoiceRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUnsignedInvoiceRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedInvoiceRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for UnsignedInvoiceRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUnsignedInvoiceRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnsignedInvoiceRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUnsignedInvoiceRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UnsignedInvoiceRequest
pub extern "C" fn UnsignedInvoiceRequest_clone(orig: &UnsignedInvoiceRequest) -> UnsignedInvoiceRequest {
	orig.clone()
}
/// A function for signing an [`UnsignedInvoiceRequest`].
#[repr(C)]
pub struct SignInvoiceRequestFn {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	pub sign_invoice_request: extern "C" fn (this_arg: *const c_void, message: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::CResult_SchnorrSignatureNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for SignInvoiceRequestFn {}
unsafe impl Sync for SignInvoiceRequestFn {}
#[allow(unused)]
pub(crate) fn SignInvoiceRequestFn_clone_fields(orig: &SignInvoiceRequestFn) -> SignInvoiceRequestFn {
	SignInvoiceRequestFn {
		this_arg: orig.this_arg,
		sign_invoice_request: Clone::clone(&orig.sign_invoice_request),
		free: Clone::clone(&orig.free),
	}
}

use lightning::offers::invoice_request::SignInvoiceRequestFn as rustSignInvoiceRequestFn;
impl rustSignInvoiceRequestFn for SignInvoiceRequestFn {
	fn sign_invoice_request(&self, mut message: &lightning::offers::invoice_request::UnsignedInvoiceRequest) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
		let mut ret = (self.sign_invoice_request)(self.this_arg, &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest { inner: unsafe { ObjOps::nonnull_ptr_to_inner((message as *const lightning::offers::invoice_request::UnsignedInvoiceRequest<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

pub struct SignInvoiceRequestFnRef(SignInvoiceRequestFn);
impl rustSignInvoiceRequestFn for SignInvoiceRequestFnRef {
	fn sign_invoice_request(&self, mut message: &lightning::offers::invoice_request::UnsignedInvoiceRequest) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
		let mut ret = (self.0.sign_invoice_request)(self.0.this_arg, &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest { inner: unsafe { ObjOps::nonnull_ptr_to_inner((message as *const lightning::offers::invoice_request::UnsignedInvoiceRequest<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for SignInvoiceRequestFn {
	type Target = SignInvoiceRequestFnRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const SignInvoiceRequestFnRef) }
	}
}
impl core::ops::DerefMut for SignInvoiceRequestFn {
	fn deref_mut(&mut self) -> &mut SignInvoiceRequestFnRef {
		unsafe { &mut *(self as *mut _ as *mut SignInvoiceRequestFnRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn SignInvoiceRequestFn_free(this_ptr: SignInvoiceRequestFn) { }
impl Drop for SignInvoiceRequestFn {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Returns the [`TaggedHash`] of the invoice to sign.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_tagged_hash(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::lightning::offers::merkle::TaggedHash {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tagged_hash();
	crate::lightning::offers::merkle::TaggedHash { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::offers::merkle::TaggedHash<>) as *mut _) }, is_owned: false }
}


use lightning::offers::invoice_request::InvoiceRequest as nativeInvoiceRequestImport;
pub(crate) type nativeInvoiceRequest = nativeInvoiceRequestImport;

/// An `InvoiceRequest` is a request for a [`Bolt12Invoice`] formulated from an [`Offer`].
///
/// An offer may provide choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that its recipient can send an invoice for payment.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[repr(C)]
pub struct InvoiceRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InvoiceRequest {
	type Target = nativeInvoiceRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InvoiceRequest { }
unsafe impl core::marker::Sync for InvoiceRequest { }
impl Drop for InvoiceRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceRequest_free(this_obj: InvoiceRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceRequest) };
}
#[allow(unused)]
impl InvoiceRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for InvoiceRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoiceRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInvoiceRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvoiceRequest
pub extern "C" fn InvoiceRequest_clone(orig: &InvoiceRequest) -> InvoiceRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a InvoiceRequest object
pub extern "C" fn InvoiceRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice_request::InvoiceRequest }).into()}

use lightning::offers::invoice_request::VerifiedInvoiceRequest as nativeVerifiedInvoiceRequestImport;
pub(crate) type nativeVerifiedInvoiceRequest = nativeVerifiedInvoiceRequestImport;

/// An [`InvoiceRequest`] that has been verified by [`InvoiceRequest::verify_using_metadata`] or
/// [`InvoiceRequest::verify_using_recipient_data`] and exposes different ways to respond depending
/// on whether the signing keys were derived.
#[must_use]
#[repr(C)]
pub struct VerifiedInvoiceRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeVerifiedInvoiceRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for VerifiedInvoiceRequest {
	type Target = nativeVerifiedInvoiceRequest;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for VerifiedInvoiceRequest { }
unsafe impl core::marker::Sync for VerifiedInvoiceRequest { }
impl Drop for VerifiedInvoiceRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeVerifiedInvoiceRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the VerifiedInvoiceRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_free(this_obj: VerifiedInvoiceRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn VerifiedInvoiceRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeVerifiedInvoiceRequest) };
}
#[allow(unused)]
impl VerifiedInvoiceRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeVerifiedInvoiceRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeVerifiedInvoiceRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeVerifiedInvoiceRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The identifier of the [`Offer`] for which the [`InvoiceRequest`] was made.
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_get_offer_id(this_ptr: &VerifiedInvoiceRequest) -> crate::lightning::offers::offer::OfferId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().offer_id;
	crate::lightning::offers::offer::OfferId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::offers::offer::OfferId<>) as *mut _) }, is_owned: false }
}
/// The identifier of the [`Offer`] for which the [`InvoiceRequest`] was made.
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_set_offer_id(this_ptr: &mut VerifiedInvoiceRequest, mut val: crate::lightning::offers::offer::OfferId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.offer_id = *unsafe { Box::from_raw(val.take_inner()) };
}
impl Clone for VerifiedInvoiceRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeVerifiedInvoiceRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn VerifiedInvoiceRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeVerifiedInvoiceRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the VerifiedInvoiceRequest
pub extern "C" fn VerifiedInvoiceRequest_clone(orig: &VerifiedInvoiceRequest) -> VerifiedInvoiceRequest {
	orig.clone()
}
/// Get a string which allows debug introspection of a VerifiedInvoiceRequest object
pub extern "C" fn VerifiedInvoiceRequest_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice_request::VerifiedInvoiceRequest }).into()}
/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
/// for the selected chain.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_chains(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::CVec_ThirtyTwoBytesZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chains();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); };
	local_ret.into()
}

/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_metadata(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_amount(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::COption_AmountZ {
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
pub extern "C" fn UnsignedInvoiceRequest_description(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Features pertaining to the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_offer_features(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::lightning_types::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	crate::lightning_types::features::OfferFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::OfferFeatures<>) as *mut _) }, is_owned: false }
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// If `None`, the offer does not expire.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_absolute_expiry(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::COption_u64Z {
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
pub extern "C" fn UnsignedInvoiceRequest_issuer(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
/// recipient privacy by obfuscating its node id.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_paths(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_supported_quantity(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	crate::lightning::offers::offer::Quantity::native_into(ret)
}

/// The public key used by the recipient to sign invoices.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_signing_pubkey(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// An unpredictable series of bytes, typically containing information about the derivation of
/// [`payer_id`].
///
/// [`payer_id`]: Self::payer_id
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_payer_metadata(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// A chain from [`Offer::chains`] that the offer is valid for.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_chain(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
/// must be greater than or equal to [`Offer::amount`], converted if necessary.
///
/// [`chain`]: Self::chain
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_amount_msats(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Features pertaining to requesting an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_invoice_request_features(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::lightning_types::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_request_features();
	crate::lightning_types::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_quantity(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_payer_id(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
/// response.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_payer_note(this_arg: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
/// for the selected chain.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_chains(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::CVec_ThirtyTwoBytesZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chains();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); };
	local_ret.into()
}

/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_metadata(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_amount(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::COption_AmountZ {
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
pub extern "C" fn InvoiceRequest_description(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Features pertaining to the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_offer_features(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning_types::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	crate::lightning_types::features::OfferFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::OfferFeatures<>) as *mut _) }, is_owned: false }
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// If `None`, the offer does not expire.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_absolute_expiry(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::COption_u64Z {
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
pub extern "C" fn InvoiceRequest_issuer(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
/// recipient privacy by obfuscating its node id.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_paths(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_supported_quantity(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	crate::lightning::offers::offer::Quantity::native_into(ret)
}

/// The public key used by the recipient to sign invoices.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_signing_pubkey(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// An unpredictable series of bytes, typically containing information about the derivation of
/// [`payer_id`].
///
/// [`payer_id`]: Self::payer_id
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_payer_metadata(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// A chain from [`Offer::chains`] that the offer is valid for.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_chain(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
/// must be greater than or equal to [`Offer::amount`], converted if necessary.
///
/// [`chain`]: Self::chain
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_amount_msats(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Features pertaining to requesting an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_invoice_request_features(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning_types::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_request_features();
	crate::lightning_types::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_quantity(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_payer_id(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
/// response.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_payer_note(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Creates an [`InvoiceBuilder`] for the request with the given required fields and using the
/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
///
/// See [`InvoiceRequest::respond_with_no_std`] for further details where the aforementioned
/// creation time is used for the `created_at` parameter.
///
/// [`Duration`]: core::time::Duration
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_respond_with(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest, mut payment_paths: crate::c_types::derived::CVec_BlindedPaymentPathZ, mut payment_hash: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_InvoiceWithExplicitSigningPubkeyBuilderBolt12SemanticErrorZ {
	let mut local_payment_paths = Vec::new(); for mut item in payment_paths.into_rust().drain(..) { local_payment_paths.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.respond_with(local_payment_paths, ::lightning::ln::types::PaymentHash(payment_hash.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Creates an [`InvoiceBuilder`] for the request with the given required fields.
///
/// Unless [`InvoiceBuilder::relative_expiry`] is set, the invoice will expire two hours after
/// `created_at`, which is used to set [`Bolt12Invoice::created_at`]. Useful for `no-std` builds
/// where [`std::time::SystemTime`] is not available.
///
/// The caller is expected to remember the preimage of `payment_hash` in order to claim a payment
/// for the invoice.
///
/// The `payment_paths` parameter is useful for maintaining the payment recipient's privacy. It
/// must contain one or more elements ordered from most-preferred to least-preferred, if there's
/// a preference. Note, however, that any privacy is lost if a public node id was used for
/// [`Offer::signing_pubkey`].
///
/// Errors if the request contains unknown required features.
///
/// # Note
///
/// If the originating [`Offer`] was created using [`OfferBuilder::deriving_signing_pubkey`],
/// then first use [`InvoiceRequest::verify_using_metadata`] or
/// [`InvoiceRequest::verify_using_recipient_data`] and then [`VerifiedInvoiceRequest`] methods
/// instead.
///
/// [`Bolt12Invoice::created_at`]: crate::offers::invoice::Bolt12Invoice::created_at
/// [`OfferBuilder::deriving_signing_pubkey`]: crate::offers::offer::OfferBuilder::deriving_signing_pubkey
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_respond_with_no_std(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest, mut payment_paths: crate::c_types::derived::CVec_BlindedPaymentPathZ, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut created_at: u64) -> crate::c_types::derived::CResult_InvoiceWithExplicitSigningPubkeyBuilderBolt12SemanticErrorZ {
	let mut local_payment_paths = Vec::new(); for mut item in payment_paths.into_rust().drain(..) { local_payment_paths.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.respond_with_no_std(local_payment_paths, ::lightning::ln::types::PaymentHash(payment_hash.data), core::time::Duration::from_secs(created_at));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Verifies that the request was for an offer created using the given key by checking the
/// metadata from the offer.
///
/// Returns the verified request which contains the derived keys needed to sign a
/// [`Bolt12Invoice`] for the request if they could be extracted from the metadata.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_verify_using_metadata(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequest, key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> crate::c_types::derived::CResult_VerifiedInvoiceRequestNoneZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).verify_using_metadata(key.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::VerifiedInvoiceRequest { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Verifies that the request was for an offer created using the given key by checking a nonce
/// included with the [`BlindedMessagePath`] for which the request was sent through.
///
/// Returns the verified request which contains the derived keys needed to sign a
/// [`Bolt12Invoice`] for the request if they could be extracted from the metadata.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_verify_using_recipient_data(mut this_arg: crate::lightning::offers::invoice_request::InvoiceRequest, mut nonce: crate::lightning::offers::nonce::Nonce, key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> crate::c_types::derived::CResult_VerifiedInvoiceRequestNoneZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).verify_using_recipient_data(*unsafe { Box::from_raw(nonce.take_inner()) }, key.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::VerifiedInvoiceRequest { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Signature of the invoice request using [`payer_id`].
///
/// [`payer_id`]: Self::payer_id
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_signature(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::SchnorrSignature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signature();
	crate::c_types::SchnorrSignature::from_rust(&ret)
}

/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
/// for the selected chain.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_chains(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::derived::CVec_ThirtyTwoBytesZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chains();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); };
	local_ret.into()
}

/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_metadata(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_amount(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::derived::COption_AmountZ {
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
pub extern "C" fn VerifiedInvoiceRequest_description(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Features pertaining to the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_offer_features(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::lightning_types::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	crate::lightning_types::features::OfferFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::OfferFeatures<>) as *mut _) }, is_owned: false }
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// If `None`, the offer does not expire.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_absolute_expiry(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::derived::COption_u64Z {
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
pub extern "C" fn VerifiedInvoiceRequest_issuer(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
/// recipient privacy by obfuscating its node id.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_paths(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_supported_quantity(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	crate::lightning::offers::offer::Quantity::native_into(ret)
}

/// The public key used by the recipient to sign invoices.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_signing_pubkey(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// An unpredictable series of bytes, typically containing information about the derivation of
/// [`payer_id`].
///
/// [`payer_id`]: Self::payer_id
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_payer_metadata(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// A chain from [`Offer::chains`] that the offer is valid for.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_chain(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
/// must be greater than or equal to [`Offer::amount`], converted if necessary.
///
/// [`chain`]: Self::chain
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_amount_msats(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Features pertaining to requesting an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_invoice_request_features(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::lightning_types::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_request_features();
	crate::lightning_types::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_quantity(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request.
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_payer_id(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
/// response.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_payer_note(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Creates an [`InvoiceBuilder`] for the request with the given required fields and using the
/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
///
/// See [`InvoiceRequest::respond_with_no_std`] for further details where the aforementioned
/// creation time is used for the `created_at` parameter.
///
/// [`Duration`]: core::time::Duration
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_respond_with(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest, mut payment_paths: crate::c_types::derived::CVec_BlindedPaymentPathZ, mut payment_hash: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_InvoiceWithExplicitSigningPubkeyBuilderBolt12SemanticErrorZ {
	let mut local_payment_paths = Vec::new(); for mut item in payment_paths.into_rust().drain(..) { local_payment_paths.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.respond_with(local_payment_paths, ::lightning::ln::types::PaymentHash(payment_hash.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Creates an [`InvoiceBuilder`] for the request with the given required fields.
///
/// Unless [`InvoiceBuilder::relative_expiry`] is set, the invoice will expire two hours after
/// `created_at`, which is used to set [`Bolt12Invoice::created_at`]. Useful for `no-std` builds
/// where [`std::time::SystemTime`] is not available.
///
/// The caller is expected to remember the preimage of `payment_hash` in order to claim a payment
/// for the invoice.
///
/// The `payment_paths` parameter is useful for maintaining the payment recipient's privacy. It
/// must contain one or more elements ordered from most-preferred to least-preferred, if there's
/// a preference. Note, however, that any privacy is lost if a public node id was used for
/// [`Offer::signing_pubkey`].
///
/// Errors if the request contains unknown required features.
///
/// # Note
///
/// If the originating [`Offer`] was created using [`OfferBuilder::deriving_signing_pubkey`],
/// then first use [`InvoiceRequest::verify_using_metadata`] or
/// [`InvoiceRequest::verify_using_recipient_data`] and then [`VerifiedInvoiceRequest`] methods
/// instead.
///
/// [`Bolt12Invoice::created_at`]: crate::offers::invoice::Bolt12Invoice::created_at
/// [`OfferBuilder::deriving_signing_pubkey`]: crate::offers::offer::OfferBuilder::deriving_signing_pubkey
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_respond_with_no_std(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest, mut payment_paths: crate::c_types::derived::CVec_BlindedPaymentPathZ, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut created_at: u64) -> crate::c_types::derived::CResult_InvoiceWithExplicitSigningPubkeyBuilderBolt12SemanticErrorZ {
	let mut local_payment_paths = Vec::new(); for mut item in payment_paths.into_rust().drain(..) { local_payment_paths.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.respond_with_no_std(local_payment_paths, ::lightning::ln::types::PaymentHash(payment_hash.data), core::time::Duration::from_secs(created_at));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
/// the same [`ExpandedKey`] as the one used to create the offer.
///
/// See [`InvoiceRequest::respond_with`] for further details.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_respond_using_derived_keys(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest, mut payment_paths: crate::c_types::derived::CVec_BlindedPaymentPathZ, mut payment_hash: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_InvoiceWithDerivedSigningPubkeyBuilderBolt12SemanticErrorZ {
	let mut local_payment_paths = Vec::new(); for mut item in payment_paths.into_rust().drain(..) { local_payment_paths.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.respond_using_derived_keys(local_payment_paths, ::lightning::ln::types::PaymentHash(payment_hash.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
/// the same [`ExpandedKey`] as the one used to create the offer.
///
/// See [`InvoiceRequest::respond_with_no_std`] for further details.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[no_mangle]
pub extern "C" fn VerifiedInvoiceRequest_respond_using_derived_keys_no_std(this_arg: &crate::lightning::offers::invoice_request::VerifiedInvoiceRequest, mut payment_paths: crate::c_types::derived::CVec_BlindedPaymentPathZ, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut created_at: u64) -> crate::c_types::derived::CResult_InvoiceWithDerivedSigningPubkeyBuilderBolt12SemanticErrorZ {
	let mut local_payment_paths = Vec::new(); for mut item in payment_paths.into_rust().drain(..) { local_payment_paths.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.respond_using_derived_keys_no_std(local_payment_paths, ::lightning::ln::types::PaymentHash(payment_hash.data), core::time::Duration::from_secs(created_at));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

#[no_mangle]
/// Serialize the UnsignedInvoiceRequest object into a byte array which can be read by UnsignedInvoiceRequest_read
pub extern "C" fn UnsignedInvoiceRequest_write(obj: &crate::lightning::offers::invoice_request::UnsignedInvoiceRequest) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn UnsignedInvoiceRequest_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::invoice_request::nativeUnsignedInvoiceRequest) })
}
#[no_mangle]
/// Serialize the InvoiceRequest object into a byte array which can be read by InvoiceRequest_read
pub extern "C" fn InvoiceRequest_write(obj: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn InvoiceRequest_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::invoice_request::nativeInvoiceRequest) })
}

use lightning::offers::invoice_request::InvoiceRequestFields as nativeInvoiceRequestFieldsImport;
pub(crate) type nativeInvoiceRequestFields = nativeInvoiceRequestFieldsImport;

/// Fields sent in an [`InvoiceRequest`] message to include in [`PaymentContext::Bolt12Offer`].
///
/// [`PaymentContext::Bolt12Offer`]: crate::blinded_path::payment::PaymentContext::Bolt12Offer
#[must_use]
#[repr(C)]
pub struct InvoiceRequestFields {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceRequestFields,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InvoiceRequestFields {
	type Target = nativeInvoiceRequestFields;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InvoiceRequestFields { }
unsafe impl core::marker::Sync for InvoiceRequestFields { }
impl Drop for InvoiceRequestFields {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceRequestFields>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceRequestFields, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_free(this_obj: InvoiceRequestFields) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequestFields_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceRequestFields) };
}
#[allow(unused)]
impl InvoiceRequestFields {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceRequestFields {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceRequestFields {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceRequestFields {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// A possibly transient pubkey used to sign the invoice request.
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_get_payer_id(this_ptr: &InvoiceRequestFields) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payer_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// A possibly transient pubkey used to sign the invoice request.
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_set_payer_id(this_ptr: &mut InvoiceRequestFields, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payer_id = val.into_rust();
}
/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_get_quantity(this_ptr: &InvoiceRequestFields) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().quantity;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_set_quantity(this_ptr: &mut InvoiceRequestFields, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.quantity = local_val;
}
/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
/// response. Truncated to [`PAYER_NOTE_LIMIT`] characters.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_get_payer_note_truncated(this_ptr: &InvoiceRequestFields) -> crate::lightning_types::string::UntrustedString {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payer_note_truncated;
	let mut local_inner_val = crate::lightning_types::string::UntrustedString { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning_types::string::UntrustedString<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
/// response. Truncated to [`PAYER_NOTE_LIMIT`] characters.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_set_payer_note_truncated(this_ptr: &mut InvoiceRequestFields, mut val: crate::lightning_types::string::UntrustedString) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payer_note_truncated = local_val;
}
/// Constructs a new InvoiceRequestFields given each field
///
/// Note that payer_note_truncated_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_new(mut payer_id_arg: crate::c_types::PublicKey, mut quantity_arg: crate::c_types::derived::COption_u64Z, mut payer_note_truncated_arg: crate::lightning_types::string::UntrustedString) -> InvoiceRequestFields {
	let mut local_quantity_arg = if quantity_arg.is_some() { Some( { quantity_arg.take() }) } else { None };
	let mut local_payer_note_truncated_arg = if payer_note_truncated_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(payer_note_truncated_arg.take_inner()) } }) };
	InvoiceRequestFields { inner: ObjOps::heap_alloc(nativeInvoiceRequestFields {
		payer_id: payer_id_arg.into_rust(),
		quantity: local_quantity_arg,
		payer_note_truncated: local_payer_note_truncated_arg,
	}), is_owned: true }
}
impl Clone for InvoiceRequestFields {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoiceRequestFields>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequestFields_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInvoiceRequestFields)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvoiceRequestFields
pub extern "C" fn InvoiceRequestFields_clone(orig: &InvoiceRequestFields) -> InvoiceRequestFields {
	orig.clone()
}
/// Get a string which allows debug introspection of a InvoiceRequestFields object
pub extern "C" fn InvoiceRequestFields_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice_request::InvoiceRequestFields }).into()}
/// Checks if two InvoiceRequestFieldss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InvoiceRequestFields_eq(a: &InvoiceRequestFields, b: &InvoiceRequestFields) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// The maximum number of characters included in [`InvoiceRequestFields::payer_note_truncated`].

#[no_mangle]
pub static PAYER_NOTE_LIMIT: usize = lightning::offers::invoice_request::PAYER_NOTE_LIMIT;
#[no_mangle]
/// Serialize the InvoiceRequestFields object into a byte array which can be read by InvoiceRequestFields_read
pub extern "C" fn InvoiceRequestFields_write(obj: &crate::lightning::offers::invoice_request::InvoiceRequestFields) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn InvoiceRequestFields_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::invoice_request::nativeInvoiceRequestFields) })
}
#[no_mangle]
/// Read a InvoiceRequestFields from a byte array, created by InvoiceRequestFields_write
pub extern "C" fn InvoiceRequestFields_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InvoiceRequestFieldsDecodeErrorZ {
	let res: Result<lightning::offers::invoice_request::InvoiceRequestFields, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_request::InvoiceRequestFields { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
