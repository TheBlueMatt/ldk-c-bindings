// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Various wrapper types (most around 32-byte arrays) for use in lightning.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::ln::types::ChannelId as nativeChannelIdImport;
pub(crate) type nativeChannelId = nativeChannelIdImport;

/// A unique 32-byte identifier for a channel.
/// Depending on how the ID is generated, several varieties are distinguished
/// (but all are stored as 32 bytes):
///   _v1_ and _temporary_.
/// A _v1_ channel ID is generated based on funding tx outpoint (txid & index).
/// A _temporary_ ID is generated randomly.
/// (Later revocation-point-based _v2_ is a possibility.)
/// The variety (context) is not stored, it is relevant only at creation.
#[must_use]
#[repr(C)]
pub struct ChannelId {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelId,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelId {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelId>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelId, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelId_free(this_obj: ChannelId) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelId_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelId) };
}
#[allow(unused)]
impl ChannelId {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelId {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelId {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelId {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn ChannelId_get_a(this_ptr: &ChannelId) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val
}
#[no_mangle]
pub extern "C" fn ChannelId_set_a(this_ptr: &mut ChannelId, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.data;
}
/// Constructs a new ChannelId given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_new(mut a_arg: crate::c_types::ThirtyTwoBytes) -> ChannelId {
	ChannelId { inner: ObjOps::heap_alloc(lightning::ln::types::ChannelId (
		a_arg.data,
	)), is_owned: true }
}
impl Clone for ChannelId {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelId>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelId_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelId)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelId
pub extern "C" fn ChannelId_clone(orig: &ChannelId) -> ChannelId {
	orig.clone()
}
/// Get a string which allows debug introspection of a ChannelId object
pub extern "C" fn ChannelId_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::types::ChannelId }).into()}
/// Checks if two ChannelIds contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelId_eq(a: &ChannelId, b: &ChannelId) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Generates a non-cryptographic 64-bit hash of the ChannelId.
#[no_mangle]
pub extern "C" fn ChannelId_hash(o: &ChannelId) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Create _v1_ channel ID based on a funding TX ID and output index
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_v1_from_funding_txid(txid: *const [u8; 32], mut output_index: u16) -> crate::lightning::ln::types::ChannelId {
	let mut ret = lightning::ln::types::ChannelId::v1_from_funding_txid(unsafe { &*txid}, output_index);
	crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Create _v1_ channel ID from a funding tx outpoint
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_v1_from_funding_outpoint(mut outpoint: crate::lightning::chain::transaction::OutPoint) -> crate::lightning::ln::types::ChannelId {
	let mut ret = lightning::ln::types::ChannelId::v1_from_funding_outpoint(*unsafe { Box::from_raw(outpoint.take_inner()) });
	crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Create a _temporary_ channel ID randomly, based on an entropy source.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_temporary_from_entropy_source(entropy_source: &crate::lightning::sign::EntropySource) -> crate::lightning::ln::types::ChannelId {
	let mut ret = lightning::ln::types::ChannelId::temporary_from_entropy_source(entropy_source);
	crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Generic constructor; create a new channel ID from the provided data.
/// Use a more specific `*_from_*` constructor when possible.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_from_bytes(mut data: crate::c_types::ThirtyTwoBytes) -> crate::lightning::ln::types::ChannelId {
	let mut ret = lightning::ln::types::ChannelId::from_bytes(data.data);
	crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Create a channel ID consisting of all-zeros data (e.g. when uninitialized or a placeholder).
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_new_zero() -> crate::lightning::ln::types::ChannelId {
	let mut ret = lightning::ln::types::ChannelId::new_zero();
	crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Check whether ID is consisting of all zeros (uninitialized)
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_is_zero(this_arg: &crate::lightning::ln::types::ChannelId) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_zero();
	ret
}

/// Create _v2_ channel ID by concatenating the holder revocation basepoint with the counterparty
/// revocation basepoint and hashing the result. The basepoints will be concatenated in increasing
/// sorted order.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_v2_from_revocation_basepoints(ours: &crate::lightning::ln::channel_keys::RevocationBasepoint, theirs: &crate::lightning::ln::channel_keys::RevocationBasepoint) -> crate::lightning::ln::types::ChannelId {
	let mut ret = lightning::ln::types::ChannelId::v2_from_revocation_basepoints(ours.get_native_ref(), theirs.get_native_ref());
	crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Create temporary _v2_ channel ID by concatenating a zeroed out basepoint with the holder
/// revocation basepoint and hashing the result.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelId_temporary_v2_from_revocation_basepoint(our_revocation_basepoint: &crate::lightning::ln::channel_keys::RevocationBasepoint) -> crate::lightning::ln::types::ChannelId {
	let mut ret = lightning::ln::types::ChannelId::temporary_v2_from_revocation_basepoint(our_revocation_basepoint.get_native_ref());
	crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Serialize the ChannelId object into a byte array which can be read by ChannelId_read
pub extern "C" fn ChannelId_write(obj: &crate::lightning::ln::types::ChannelId) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelId_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelId) })
}
#[no_mangle]
/// Read a ChannelId from a byte array, created by ChannelId_write
pub extern "C" fn ChannelId_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelIdDecodeErrorZ {
	let res: Result<lightning::ln::types::ChannelId, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
