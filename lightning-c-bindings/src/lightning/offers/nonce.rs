// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! A number used only once.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::nonce::Nonce as nativeNonceImport;
pub(crate) type nativeNonce = nativeNonceImport;

/// A 128-bit number used only once.
///
/// Needed when constructing [`Offer::metadata`] and deriving [`Offer::issuer_signing_pubkey`] from
/// [`ExpandedKey`]. Must not be reused for any other derivation without first hashing.
///
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
#[must_use]
#[repr(C)]
pub struct Nonce {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNonce,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Nonce {
	type Target = nativeNonce;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Nonce { }
unsafe impl core::marker::Sync for Nonce { }
impl Drop for Nonce {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNonce>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Nonce, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Nonce_free(this_obj: Nonce) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Nonce_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeNonce) };
}
#[allow(unused)]
impl Nonce {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNonce {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNonce {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNonce {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for Nonce {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNonce>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Nonce_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeNonce)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Nonce
pub extern "C" fn Nonce_clone(orig: &Nonce) -> Nonce {
	orig.clone()
}
/// Get a string which allows debug introspection of a Nonce object
pub extern "C" fn Nonce_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::nonce::Nonce }).into()}
/// Checks if two Nonces contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Nonce_eq(a: &Nonce, b: &Nonce) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Creates a `Nonce` from the given [`EntropySource`].
#[must_use]
#[no_mangle]
pub extern "C" fn Nonce_from_entropy_source(mut entropy_source: crate::lightning::sign::EntropySource) -> crate::lightning::offers::nonce::Nonce {
	let mut ret = lightning::offers::nonce::Nonce::from_entropy_source(entropy_source);
	crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns a slice of the underlying bytes of size [`Nonce::LENGTH`].
#[must_use]
#[no_mangle]
pub extern "C" fn Nonce_as_slice(this_arg: &crate::lightning::offers::nonce::Nonce) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_slice();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

#[no_mangle]
/// Serialize the Nonce object into a byte array which can be read by Nonce_read
pub extern "C" fn Nonce_write(obj: &crate::lightning::offers::nonce::Nonce) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Nonce_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::offers::nonce::nativeNonce) })
}
#[no_mangle]
/// Read a Nonce from a byte array, created by Nonce_write
pub extern "C" fn Nonce_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NonceDecodeErrorZ {
	let res: Result<lightning::offers::nonce::Nonce, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
