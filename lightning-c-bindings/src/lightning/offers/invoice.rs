// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for `invoice` messages.
//!
//! A [`Bolt12Invoice`] can be built from a parsed [`InvoiceRequest`] for the \"offer to be paid\"
//! flow or from a [`Refund`] as an \"offer for money\" flow. The expected recipient of the payment
//! then sends the invoice to the intended payer, who will then pay it.
//!
//! The payment recipient must include a [`PaymentHash`], so as to reveal the preimage upon payment
//! receipt, and one or more [`BlindedPaymentPath`]s for the payer to use when sending the payment.
//!
//! ```ignore
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::hashes::Hash;
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use core::convert::TryFrom;
//! use lightning::offers::invoice::UnsignedBolt12Invoice;
//! use lightning::offers::invoice_request::InvoiceRequest;
//! use lightning::offers::refund::Refund;
//! use lightning::util::ser::Writeable;
//!
//! # use lightning::types::payment::PaymentHash;
//! # use lightning::offers::invoice::{ExplicitSigningPubkey, InvoiceBuilder};
//! # use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
//! #
//! # fn create_payment_paths() -> Vec<BlindedPaymentPath> { unimplemented!() }
//! # fn create_payment_hash() -> PaymentHash { unimplemented!() }
//! #
//! # fn parse_invoice_request(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let payment_paths = create_payment_paths();
//! let payment_hash = create_payment_hash();
//! let secp_ctx = Secp256k1::new();
//! let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//! let wpubkey_hash = bitcoin::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! let mut buffer = Vec::new();
//!
//! // Invoice for the \"offer to be paid\" flow.
//! # <InvoiceBuilder<ExplicitSigningPubkey>>::from(
//! InvoiceRequest::try_from(bytes)?
//!
//!    .respond_with(payment_paths, payment_hash)?
//!
//! # )
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign(|message: &UnsignedBolt12Invoice|
//!         Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect(\"failed verifying signature\")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! # fn parse_refund(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! # let payment_paths = create_payment_paths();
//! # let payment_hash = create_payment_hash();
//! # let secp_ctx = Secp256k1::new();
//! # let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! # let pubkey = PublicKey::from(keys);
//! # let wpubkey_hash = bitcoin::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! # let mut buffer = Vec::new();
//!
//! // Invoice for the \"offer for money\" flow.
//! # <InvoiceBuilder<ExplicitSigningPubkey>>::from(
//! \"lnr1qcp4256ypq\"
//!     .parse::<Refund>()?
//!
//!    .respond_with(payment_paths, payment_hash, pubkey)?
//!
//! # )
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign(|message: &UnsignedBolt12Invoice|
//!         Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect(\"failed verifying signature\")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! ```

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder as nativeInvoiceWithExplicitSigningPubkeyBuilderImport;
pub(crate) type nativeInvoiceWithExplicitSigningPubkeyBuilder = nativeInvoiceWithExplicitSigningPubkeyBuilderImport<'static, >;

/// Builds a [`Bolt12Invoice`] from either:
/// - an [`InvoiceRequest`] for the \"offer to be paid\" flow or
/// - a [`Refund`] for the \"offer for money\" flow.
///
/// See [module-level documentation] for usage.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Refund`]: crate::offers::refund::Refund
/// [module-level documentation]: self
#[must_use]
#[repr(C)]
pub struct InvoiceWithExplicitSigningPubkeyBuilder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceWithExplicitSigningPubkeyBuilder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InvoiceWithExplicitSigningPubkeyBuilder {
	type Target = nativeInvoiceWithExplicitSigningPubkeyBuilder;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InvoiceWithExplicitSigningPubkeyBuilder { }
unsafe impl core::marker::Sync for InvoiceWithExplicitSigningPubkeyBuilder { }
impl Drop for InvoiceWithExplicitSigningPubkeyBuilder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceWithExplicitSigningPubkeyBuilder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceWithExplicitSigningPubkeyBuilder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_free(this_obj: InvoiceWithExplicitSigningPubkeyBuilder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceWithExplicitSigningPubkeyBuilder) };
}
#[allow(unused)]
impl InvoiceWithExplicitSigningPubkeyBuilder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceWithExplicitSigningPubkeyBuilder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceWithExplicitSigningPubkeyBuilder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceWithExplicitSigningPubkeyBuilder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}

use lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder as nativeInvoiceWithDerivedSigningPubkeyBuilderImport;
pub(crate) type nativeInvoiceWithDerivedSigningPubkeyBuilder = nativeInvoiceWithDerivedSigningPubkeyBuilderImport<'static, >;

/// Builds a [`Bolt12Invoice`] from either:
/// - an [`InvoiceRequest`] for the \"offer to be paid\" flow or
/// - a [`Refund`] for the \"offer for money\" flow.
///
/// See [module-level documentation] for usage.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Refund`]: crate::offers::refund::Refund
/// [module-level documentation]: self
#[must_use]
#[repr(C)]
pub struct InvoiceWithDerivedSigningPubkeyBuilder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceWithDerivedSigningPubkeyBuilder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InvoiceWithDerivedSigningPubkeyBuilder {
	type Target = nativeInvoiceWithDerivedSigningPubkeyBuilder;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InvoiceWithDerivedSigningPubkeyBuilder { }
unsafe impl core::marker::Sync for InvoiceWithDerivedSigningPubkeyBuilder { }
impl Drop for InvoiceWithDerivedSigningPubkeyBuilder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceWithDerivedSigningPubkeyBuilder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceWithDerivedSigningPubkeyBuilder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_free(this_obj: InvoiceWithDerivedSigningPubkeyBuilder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceWithDerivedSigningPubkeyBuilder) };
}
#[allow(unused)]
impl InvoiceWithDerivedSigningPubkeyBuilder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceWithDerivedSigningPubkeyBuilder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceWithDerivedSigningPubkeyBuilder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceWithDerivedSigningPubkeyBuilder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Builds an unsigned [`Bolt12Invoice`] after checking for valid semantics.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_build(mut this_arg: crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder) -> crate::c_types::derived::CResult_UnsignedBolt12InvoiceBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).build();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::UnsignedBolt12Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

///Sets the [`Bolt12Invoice::relative_expiry`]
///as seconds since [`Bolt12Invoice::created_at`].
///Any expiry that has already passed is valid and can be checked for using
///[`Bolt12Invoice::is_expired`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_relative_expiry(mut this_arg: crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder, mut relative_expiry_secs: u32) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).relative_expiry(relative_expiry_secs);
	() /*ret*/
}

///Adds a P2WSH address to [`Bolt12Invoice::fallbacks`].
///
/// Successive calls to this method will add another address. Caller is responsible for not
/// adding duplicate addresses and only calling if capable of receiving to P2WSH addresses.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_fallback_v0_p2wsh(mut this_arg: crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder, script_hash: *const [u8; 32]) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).fallback_v0_p2wsh(&bitcoin::WScriptHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(unsafe { *script_hash }.clone())));
	() /*ret*/
}

///Adds a P2WPKH address to [`Bolt12Invoice::fallbacks`].
///
/// Successive calls to this method will add another address. Caller is responsible for not
/// adding duplicate addresses and only calling if capable of receiving to P2WPKH addresses.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_fallback_v0_p2wpkh(mut this_arg: crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder, pubkey_hash: *const [u8; 20]) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).fallback_v0_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(unsafe { *pubkey_hash }.clone())));
	() /*ret*/
}

///Adds a P2TR address to [`Bolt12Invoice::fallbacks`].
///
/// Successive calls to this method will add another address. Caller is responsible for not
/// adding duplicate addresses and only calling if capable of receiving to P2TR addresses.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_fallback_v1_p2tr_tweaked(mut this_arg: crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder, mut output_key: crate::c_types::TweakedPublicKey) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).fallback_v1_p2tr_tweaked(&output_key.into_rust());
	() /*ret*/
}

///Sets [`Bolt12Invoice::invoice_features`]
///to indicate MPP may be used. Otherwise, MPP is disallowed.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithExplicitSigningPubkeyBuilder_allow_mpp(mut this_arg: crate::lightning::offers::invoice::InvoiceWithExplicitSigningPubkeyBuilder) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).allow_mpp();
	() /*ret*/
}

/// Builds a signed [`Bolt12Invoice`] after checking for valid semantics.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_build_and_sign(mut this_arg: crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder) -> crate::c_types::derived::CResult_Bolt12InvoiceBolt12SemanticErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).build_and_sign(secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::Bolt12Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::offers::parse::Bolt12SemanticError::native_into(e) }).into() };
	local_ret
}

///Sets the [`Bolt12Invoice::relative_expiry`]
///as seconds since [`Bolt12Invoice::created_at`].
///Any expiry that has already passed is valid and can be checked for using
///[`Bolt12Invoice::is_expired`].
///
/// Successive calls to this method will override the previous setting.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_relative_expiry(mut this_arg: crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder, mut relative_expiry_secs: u32) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).relative_expiry(relative_expiry_secs);
	() /*ret*/
}

///Adds a P2WSH address to [`Bolt12Invoice::fallbacks`].
///
/// Successive calls to this method will add another address. Caller is responsible for not
/// adding duplicate addresses and only calling if capable of receiving to P2WSH addresses.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_fallback_v0_p2wsh(mut this_arg: crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder, script_hash: *const [u8; 32]) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).fallback_v0_p2wsh(&bitcoin::WScriptHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(unsafe { *script_hash }.clone())));
	() /*ret*/
}

///Adds a P2WPKH address to [`Bolt12Invoice::fallbacks`].
///
/// Successive calls to this method will add another address. Caller is responsible for not
/// adding duplicate addresses and only calling if capable of receiving to P2WPKH addresses.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_fallback_v0_p2wpkh(mut this_arg: crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder, pubkey_hash: *const [u8; 20]) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).fallback_v0_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(unsafe { *pubkey_hash }.clone())));
	() /*ret*/
}

///Adds a P2TR address to [`Bolt12Invoice::fallbacks`].
///
/// Successive calls to this method will add another address. Caller is responsible for not
/// adding duplicate addresses and only calling if capable of receiving to P2TR addresses.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_fallback_v1_p2tr_tweaked(mut this_arg: crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder, mut output_key: crate::c_types::TweakedPublicKey) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).fallback_v1_p2tr_tweaked(&output_key.into_rust());
	() /*ret*/
}

///Sets [`Bolt12Invoice::invoice_features`]
///to indicate MPP may be used. Otherwise, MPP is disallowed.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceWithDerivedSigningPubkeyBuilder_allow_mpp(mut this_arg: crate::lightning::offers::invoice::InvoiceWithDerivedSigningPubkeyBuilder) {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).allow_mpp();
	() /*ret*/
}


use lightning::offers::invoice::UnsignedBolt12Invoice as nativeUnsignedBolt12InvoiceImport;
pub(crate) type nativeUnsignedBolt12Invoice = nativeUnsignedBolt12InvoiceImport;

/// A semantically valid [`Bolt12Invoice`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
#[must_use]
#[repr(C)]
pub struct UnsignedBolt12Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedBolt12Invoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for UnsignedBolt12Invoice {
	type Target = nativeUnsignedBolt12Invoice;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for UnsignedBolt12Invoice { }
unsafe impl core::marker::Sync for UnsignedBolt12Invoice { }
impl Drop for UnsignedBolt12Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUnsignedBolt12Invoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UnsignedBolt12Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_free(this_obj: UnsignedBolt12Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnsignedBolt12Invoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUnsignedBolt12Invoice) };
}
#[allow(unused)]
impl UnsignedBolt12Invoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUnsignedBolt12Invoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUnsignedBolt12Invoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedBolt12Invoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for UnsignedBolt12Invoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUnsignedBolt12Invoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnsignedBolt12Invoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUnsignedBolt12Invoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UnsignedBolt12Invoice
pub extern "C" fn UnsignedBolt12Invoice_clone(orig: &UnsignedBolt12Invoice) -> UnsignedBolt12Invoice {
	orig.clone()
}
/// A function for signing an [`UnsignedBolt12Invoice`].
#[repr(C)]
pub struct SignBolt12InvoiceFn {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	pub sign_invoice: extern "C" fn (this_arg: *const c_void, message: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::CResult_SchnorrSignatureNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for SignBolt12InvoiceFn {}
unsafe impl Sync for SignBolt12InvoiceFn {}
#[allow(unused)]
pub(crate) fn SignBolt12InvoiceFn_clone_fields(orig: &SignBolt12InvoiceFn) -> SignBolt12InvoiceFn {
	SignBolt12InvoiceFn {
		this_arg: orig.this_arg,
		sign_invoice: Clone::clone(&orig.sign_invoice),
		free: Clone::clone(&orig.free),
	}
}

use lightning::offers::invoice::SignBolt12InvoiceFn as rustSignBolt12InvoiceFn;
impl rustSignBolt12InvoiceFn for SignBolt12InvoiceFn {
	fn sign_invoice(&self, mut message: &lightning::offers::invoice::UnsignedBolt12Invoice) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
		let mut ret = (self.sign_invoice)(self.this_arg, &crate::lightning::offers::invoice::UnsignedBolt12Invoice { inner: unsafe { ObjOps::nonnull_ptr_to_inner((message as *const lightning::offers::invoice::UnsignedBolt12Invoice<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

pub struct SignBolt12InvoiceFnRef(SignBolt12InvoiceFn);
impl rustSignBolt12InvoiceFn for SignBolt12InvoiceFnRef {
	fn sign_invoice(&self, mut message: &lightning::offers::invoice::UnsignedBolt12Invoice) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
		let mut ret = (self.0.sign_invoice)(self.0.this_arg, &crate::lightning::offers::invoice::UnsignedBolt12Invoice { inner: unsafe { ObjOps::nonnull_ptr_to_inner((message as *const lightning::offers::invoice::UnsignedBolt12Invoice<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for SignBolt12InvoiceFn {
	type Target = SignBolt12InvoiceFnRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const SignBolt12InvoiceFnRef) }
	}
}
impl core::ops::DerefMut for SignBolt12InvoiceFn {
	fn deref_mut(&mut self) -> &mut SignBolt12InvoiceFnRef {
		unsafe { &mut *(self as *mut _ as *mut SignBolt12InvoiceFnRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn SignBolt12InvoiceFn_free(this_ptr: SignBolt12InvoiceFn) { }
impl Drop for SignBolt12InvoiceFn {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Returns the [`TaggedHash`] of the invoice to sign.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_tagged_hash(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::offers::merkle::TaggedHash {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tagged_hash();
	crate::lightning::offers::merkle::TaggedHash { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::offers::merkle::TaggedHash<>) as *mut _) }, is_owned: false }
}


use lightning::offers::invoice::Bolt12Invoice as nativeBolt12InvoiceImport;
pub(crate) type nativeBolt12Invoice = nativeBolt12InvoiceImport;

/// A `Bolt12Invoice` is a payment request, typically corresponding to an [`Offer`] or a [`Refund`].
///
/// An invoice may be sent in response to an [`InvoiceRequest`] in the case of an offer or sent
/// directly after scanning a refund. It includes all the information needed to pay a recipient.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Refund`]: crate::offers::refund::Refund
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[must_use]
#[repr(C)]
pub struct Bolt12Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt12Invoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Bolt12Invoice {
	type Target = nativeBolt12Invoice;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Bolt12Invoice { }
unsafe impl core::marker::Sync for Bolt12Invoice { }
impl Drop for Bolt12Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt12Invoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt12Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt12Invoice_free(this_obj: Bolt12Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12Invoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt12Invoice) };
}
#[allow(unused)]
impl Bolt12Invoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt12Invoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt12Invoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt12Invoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for Bolt12Invoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt12Invoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12Invoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBolt12Invoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt12Invoice
pub extern "C" fn Bolt12Invoice_clone(orig: &Bolt12Invoice) -> Bolt12Invoice {
	orig.clone()
}
/// Get a string which allows debug introspection of a Bolt12Invoice object
pub extern "C" fn Bolt12Invoice_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice::Bolt12Invoice }).into()}
/// Paths to the recipient originating from publicly reachable nodes, including information
/// needed for routing payments across them.
///
/// Blinded paths provide recipient privacy by obfuscating its node id. Note, however, that this
/// privacy is lost if a public node id is used for
///[`UnsignedBolt12Invoice::signing_pubkey`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payment_paths(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::CVec_BlindedPaymentPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::payment::BlindedPaymentPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Duration since the Unix epoch when the invoice was created.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_created_at(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.created_at();
	ret.as_secs()
}

/// Duration since
///[`UnsignedBolt12Invoice::created_at`]
/// when the invoice has expired and therefore should no longer be paid.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_relative_expiry(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.relative_expiry();
	ret.as_secs()
}

/// Whether the invoice has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_is_expired(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// Fallback addresses for paying the invoice on-chain, in order of most-preferred to
/// least-preferred.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_fallbacks(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::CVec_StrZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fallbacks();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { alloc::string::ToString::to_string(&item).into() }); };
	local_ret.into()
}

/// Features pertaining to paying an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_invoice_features(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning_types::features::Bolt12InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_features();
	crate::lightning_types::features::Bolt12InvoiceFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::Bolt12InvoiceFeatures<>) as *mut _) }, is_owned: false }
}

/// A typically transient public key corresponding to the key used to sign the invoice.
///
/// If the invoices was created in response to an [`Offer`], then this will be:
/// - [`Offer::issuer_signing_pubkey`] if it's `Some`, otherwise
/// - the final blinded node id from a [`BlindedMessagePath`] in [`Offer::paths`] if `None`.
///
/// If the invoice was created in response to a [`Refund`], then it is a valid pubkey chosen by
/// the recipient.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
/// [`Refund`]: crate::offers::refund::Refund
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_signing_pubkey(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// The chains that may be used when paying a requested invoice.
///
/// From [`Offer::chains`]; `None` if the invoice was created in response to a [`Refund`].
///
/// [`Offer::chains`]: crate::offers::offer::Offer::chains
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_offer_chains(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_chains();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::None } else { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::Some( { let mut local_ret_0 = Vec::new(); for mut item in ret.unwrap().drain(..) { local_ret_0.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); }; local_ret_0.into() }) };
	local_ret
}

/// The chain that must be used when paying the invoice; selected from [`offer_chains`] if the
/// invoice originated from an offer.
///
/// From [`InvoiceRequest::chain`] or [`Refund::chain`].
///
/// [`offer_chains`]: Self::offer_chains
/// [`InvoiceRequest::chain`]: crate::offers::invoice_request::InvoiceRequest::chain
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_chain(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// Opaque bytes set by the originating [`Offer`].
///
/// From [`Offer::metadata`]; `None` if the invoice was created in response to a [`Refund`] or
/// if the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_metadata(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
///
/// From [`Offer::amount`]; `None` if the invoice was created in response to a [`Refund`] or if
/// the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::amount`]: crate::offers::offer::Offer::amount
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_amount(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_AmountZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_AmountZ::None } else { crate::c_types::derived::COption_AmountZ::Some( { crate::lightning::offers::offer::Amount::native_into(ret.unwrap()) }) };
	local_ret
}

/// Features pertaining to the originating [`Offer`].
///
/// From [`Offer::offer_features`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_offer_features(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning_types::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	let mut local_ret = crate::lightning_types::features::OfferFeatures { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_types::features::OfferFeatures<>) as *mut _ }, is_owned: false };
	local_ret
}

/// A complete description of the purpose of the originating offer or refund.
///
/// From [`Offer::description`] or [`Refund::description`].
///
/// [`Offer::description`]: crate::offers::offer::Offer::description
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_description(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// From [`Offer::absolute_expiry`] or [`Refund::absolute_expiry`].
///
/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_absolute_expiry(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// The issuer of the offer or refund.
///
/// From [`Offer::issuer`] or [`Refund::issuer`].
///
/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_issuer(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes.
///
/// From [`Offer::paths`] or [`Refund::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_message_paths(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
///
/// From [`Offer::supported_quantity`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_supported_quantity(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_QuantityZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_QuantityZ::None } else { crate::c_types::derived::COption_QuantityZ::Some( { crate::lightning::offers::offer::Quantity::native_into(ret.unwrap()) }) };
	local_ret
}

/// The public key used by the recipient to sign invoices.
///
/// From [`Offer::issuer_signing_pubkey`] and may be `None`; also `None` if the invoice was
/// created in response to a [`Refund`].
///
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_issuer_signing_pubkey(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer_signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// An unpredictable series of bytes from the payer.
///
/// From [`InvoiceRequest::payer_metadata`] or [`Refund::payer_metadata`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payer_metadata(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// Features pertaining to requesting an invoice.
///
/// From [`InvoiceRequest::invoice_request_features`] or [`Refund::features`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_invoice_request_features(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning_types::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_request_features();
	crate::lightning_types::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of items requested or refunded for.
///
/// From [`InvoiceRequest::quantity`] or [`Refund::quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_quantity(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request or to send an invoice for a
/// refund in case there are no [`message_paths`].
///
/// [`message_paths`]: Self::message_paths
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payer_signing_pubkey(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note reflected back in the invoice.
///
/// From [`InvoiceRequest::payer_note`] or [`Refund::payer_note`].
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payer_note(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// SHA256 hash of the payment preimage that will be given in return for paying the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payment_hash(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_hash();
	crate::c_types::ThirtyTwoBytes { data: ret.0 }
}

/// The minimum amount required for a successful payment of the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_amount_msats(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	ret
}

/// Paths to the recipient originating from publicly reachable nodes, including information
/// needed for routing payments across them.
///
/// Blinded paths provide recipient privacy by obfuscating its node id. Note, however, that this
/// privacy is lost if a public node id is used for
///[`Bolt12Invoice::signing_pubkey`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payment_paths(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::CVec_BlindedPaymentPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::payment::BlindedPaymentPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Duration since the Unix epoch when the invoice was created.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_created_at(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.created_at();
	ret.as_secs()
}

/// Duration since
///[`Bolt12Invoice::created_at`]
/// when the invoice has expired and therefore should no longer be paid.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_relative_expiry(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.relative_expiry();
	ret.as_secs()
}

/// Whether the invoice has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_is_expired(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// Fallback addresses for paying the invoice on-chain, in order of most-preferred to
/// least-preferred.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_fallbacks(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::CVec_StrZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fallbacks();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { alloc::string::ToString::to_string(&item).into() }); };
	local_ret.into()
}

/// Features pertaining to paying an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_invoice_features(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning_types::features::Bolt12InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_features();
	crate::lightning_types::features::Bolt12InvoiceFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::Bolt12InvoiceFeatures<>) as *mut _) }, is_owned: false }
}

/// A typically transient public key corresponding to the key used to sign the invoice.
///
/// If the invoices was created in response to an [`Offer`], then this will be:
/// - [`Offer::issuer_signing_pubkey`] if it's `Some`, otherwise
/// - the final blinded node id from a [`BlindedMessagePath`] in [`Offer::paths`] if `None`.
///
/// If the invoice was created in response to a [`Refund`], then it is a valid pubkey chosen by
/// the recipient.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
/// [`Refund`]: crate::offers::refund::Refund
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signing_pubkey(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// The chains that may be used when paying a requested invoice.
///
/// From [`Offer::chains`]; `None` if the invoice was created in response to a [`Refund`].
///
/// [`Offer::chains`]: crate::offers::offer::Offer::chains
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_offer_chains(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_chains();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::None } else { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::Some( { let mut local_ret_0 = Vec::new(); for mut item in ret.unwrap().drain(..) { local_ret_0.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); }; local_ret_0.into() }) };
	local_ret
}

/// The chain that must be used when paying the invoice; selected from [`offer_chains`] if the
/// invoice originated from an offer.
///
/// From [`InvoiceRequest::chain`] or [`Refund::chain`].
///
/// [`offer_chains`]: Self::offer_chains
/// [`InvoiceRequest::chain`]: crate::offers::invoice_request::InvoiceRequest::chain
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_chain(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// Opaque bytes set by the originating [`Offer`].
///
/// From [`Offer::metadata`]; `None` if the invoice was created in response to a [`Refund`] or
/// if the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_metadata(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
///
/// From [`Offer::amount`]; `None` if the invoice was created in response to a [`Refund`] or if
/// the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::amount`]: crate::offers::offer::Offer::amount
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_amount(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_AmountZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_AmountZ::None } else { crate::c_types::derived::COption_AmountZ::Some( { crate::lightning::offers::offer::Amount::native_into(ret.unwrap()) }) };
	local_ret
}

/// Features pertaining to the originating [`Offer`].
///
/// From [`Offer::offer_features`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_offer_features(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning_types::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	let mut local_ret = crate::lightning_types::features::OfferFeatures { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_types::features::OfferFeatures<>) as *mut _ }, is_owned: false };
	local_ret
}

/// A complete description of the purpose of the originating offer or refund.
///
/// From [`Offer::description`] or [`Refund::description`].
///
/// [`Offer::description`]: crate::offers::offer::Offer::description
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_description(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// From [`Offer::absolute_expiry`] or [`Refund::absolute_expiry`].
///
/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_absolute_expiry(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// The issuer of the offer or refund.
///
/// From [`Offer::issuer`] or [`Refund::issuer`].
///
/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_issuer(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes.
///
/// From [`Offer::paths`] or [`Refund::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_message_paths(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::CVec_BlindedMessagePathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
///
/// From [`Offer::supported_quantity`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_supported_quantity(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_QuantityZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_QuantityZ::None } else { crate::c_types::derived::COption_QuantityZ::Some( { crate::lightning::offers::offer::Quantity::native_into(ret.unwrap()) }) };
	local_ret
}

/// The public key used by the recipient to sign invoices.
///
/// From [`Offer::issuer_signing_pubkey`] and may be `None`; also `None` if the invoice was
/// created in response to a [`Refund`].
///
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_issuer_signing_pubkey(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer_signing_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// An unpredictable series of bytes from the payer.
///
/// From [`InvoiceRequest::payer_metadata`] or [`Refund::payer_metadata`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payer_metadata(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// Features pertaining to requesting an invoice.
///
/// From [`InvoiceRequest::invoice_request_features`] or [`Refund::features`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_invoice_request_features(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning_types::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_request_features();
	crate::lightning_types::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_types::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of items requested or refunded for.
///
/// From [`InvoiceRequest::quantity`] or [`Refund::quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_quantity(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request or to send an invoice for a
/// refund in case there are no [`message_paths`].
///
/// [`message_paths`]: Self::message_paths
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payer_signing_pubkey(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note reflected back in the invoice.
///
/// From [`InvoiceRequest::payer_note`] or [`Refund::payer_note`].
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payer_note(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning_types::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning_types::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// SHA256 hash of the payment preimage that will be given in return for paying the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payment_hash(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_hash();
	crate::c_types::ThirtyTwoBytes { data: ret.0 }
}

/// The minimum amount required for a successful payment of the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_amount_msats(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	ret
}

/// Signature of the invoice verified using [`Bolt12Invoice::signing_pubkey`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signature(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::SchnorrSignature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signature();
	crate::c_types::SchnorrSignature::from_rust(&ret)
}

/// Hash that was used for signing the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signable_hash(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signable_hash();
	crate::c_types::ThirtyTwoBytes { data: ret }
}

/// Verifies that the invoice was for a request or refund created using the given key by
/// checking the payer metadata from the invoice request.
///
/// Returns the associated [`PaymentId`] to use when sending the payment.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_verify_using_metadata(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice, key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> crate::c_types::derived::CResult_ThirtyTwoBytesNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify_using_metadata(key.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Verifies that the invoice was for a request or refund created using the given key by
/// checking a payment id and nonce included with the [`BlindedMessagePath`] for which the invoice was
/// sent through.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_verify_using_payer_data(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice, mut payment_id: crate::c_types::ThirtyTwoBytes, mut nonce: crate::lightning::offers::nonce::Nonce, key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> crate::c_types::derived::CResult_ThirtyTwoBytesNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify_using_payer_data(::lightning::ln::channelmanager::PaymentId(payment_id.data), *unsafe { Box::from_raw(nonce.take_inner()) }, key.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Generates a non-cryptographic 64-bit hash of the Bolt12Invoice.
#[no_mangle]
pub extern "C" fn Bolt12Invoice_hash(o: &Bolt12Invoice) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Serialize the UnsignedBolt12Invoice object into a byte array which can be read by UnsignedBolt12Invoice_read
pub extern "C" fn UnsignedBolt12Invoice_write(obj: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn UnsignedBolt12Invoice_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::invoice::nativeUnsignedBolt12Invoice) })
}
#[no_mangle]
/// Serialize the Bolt12Invoice object into a byte array which can be read by Bolt12Invoice_read
pub extern "C" fn Bolt12Invoice_write(obj: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt12Invoice_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::invoice::nativeBolt12Invoice) })
}
#[no_mangle]
/// Read a Bolt12Invoice from a byte array, created by Bolt12Invoice_write
pub extern "C" fn Bolt12Invoice_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_Bolt12InvoiceDecodeErrorZ {
	let res: Result<lightning::offers::invoice::Bolt12Invoice, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::Bolt12Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
