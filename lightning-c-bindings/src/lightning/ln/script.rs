// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Abstractions for scripts used in the Lightning Network.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::ln::script::ShutdownScript as nativeShutdownScriptImport;
pub(crate) type nativeShutdownScript = nativeShutdownScriptImport;

/// A script pubkey for shutting down a channel as defined by [BOLT #2].
///
/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
#[must_use]
#[repr(C)]
pub struct ShutdownScript {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeShutdownScript,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ShutdownScript {
	type Target = nativeShutdownScript;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ShutdownScript { }
unsafe impl core::marker::Sync for ShutdownScript { }
impl Drop for ShutdownScript {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeShutdownScript>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ShutdownScript, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ShutdownScript_free(this_obj: ShutdownScript) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ShutdownScript_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeShutdownScript) };
}
#[allow(unused)]
impl ShutdownScript {
	pub(crate) fn get_native_ref(&self) -> &'static nativeShutdownScript {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeShutdownScript {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeShutdownScript {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for ShutdownScript {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeShutdownScript>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ShutdownScript_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeShutdownScript)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ShutdownScript
pub extern "C" fn ShutdownScript_clone(orig: &ShutdownScript) -> ShutdownScript {
	orig.clone()
}
/// Checks if two ShutdownScripts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ShutdownScript_eq(a: &ShutdownScript, b: &ShutdownScript) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::ln::script::InvalidShutdownScript as nativeInvalidShutdownScriptImport;
pub(crate) type nativeInvalidShutdownScript = nativeInvalidShutdownScriptImport;

/// An error occurring when converting from [`ScriptBuf`] to [`ShutdownScript`].
#[must_use]
#[repr(C)]
pub struct InvalidShutdownScript {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvalidShutdownScript,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InvalidShutdownScript {
	type Target = nativeInvalidShutdownScript;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InvalidShutdownScript { }
unsafe impl core::marker::Sync for InvalidShutdownScript { }
impl Drop for InvalidShutdownScript {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvalidShutdownScript>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvalidShutdownScript, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvalidShutdownScript_free(this_obj: InvalidShutdownScript) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvalidShutdownScript_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvalidShutdownScript) };
}
#[allow(unused)]
impl InvalidShutdownScript {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvalidShutdownScript {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvalidShutdownScript {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvalidShutdownScript {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The script that did not meet the requirements from [BOLT #2].
///
/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
#[no_mangle]
pub extern "C" fn InvalidShutdownScript_get_script(this_ptr: &InvalidShutdownScript) -> crate::c_types::derived::CVec_u8Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().script;
	inner_val.as_bytes().to_vec().into()
}
/// The script that did not meet the requirements from [BOLT #2].
///
/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
#[no_mangle]
pub extern "C" fn InvalidShutdownScript_set_script(this_ptr: &mut InvalidShutdownScript, mut val: crate::c_types::derived::CVec_u8Z) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.script = ::bitcoin::script::ScriptBuf::from(val.into_rust());
}
/// Constructs a new InvalidShutdownScript given each field
#[must_use]
#[no_mangle]
pub extern "C" fn InvalidShutdownScript_new(mut script_arg: crate::c_types::derived::CVec_u8Z) -> InvalidShutdownScript {
	InvalidShutdownScript { inner: ObjOps::heap_alloc(nativeInvalidShutdownScript {
		script: ::bitcoin::script::ScriptBuf::from(script_arg.into_rust()),
	}), is_owned: true }
}
impl Clone for InvalidShutdownScript {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvalidShutdownScript>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvalidShutdownScript_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInvalidShutdownScript)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvalidShutdownScript
pub extern "C" fn InvalidShutdownScript_clone(orig: &InvalidShutdownScript) -> InvalidShutdownScript {
	orig.clone()
}
/// Get a string which allows debug introspection of a InvalidShutdownScript object
pub extern "C" fn InvalidShutdownScript_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::script::InvalidShutdownScript }).into()}
#[no_mangle]
/// Serialize the ShutdownScript object into a byte array which can be read by ShutdownScript_read
pub extern "C" fn ShutdownScript_write(obj: &crate::lightning::ln::script::ShutdownScript) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ShutdownScript_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::script::nativeShutdownScript) })
}
#[no_mangle]
/// Read a ShutdownScript from a byte array, created by ShutdownScript_write
pub extern "C" fn ShutdownScript_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ShutdownScriptDecodeErrorZ {
	let res: Result<lightning::ln::script::ShutdownScript, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Generates a P2WPKH script pubkey from the given [`WPubkeyHash`].
#[must_use]
#[no_mangle]
pub extern "C" fn ShutdownScript_new_p2wpkh(pubkey_hash: *const [u8; 20]) -> crate::lightning::ln::script::ShutdownScript {
	let mut ret = lightning::ln::script::ShutdownScript::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(unsafe { *pubkey_hash }.clone())));
	crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Generates a P2WSH script pubkey from the given [`WScriptHash`].
#[must_use]
#[no_mangle]
pub extern "C" fn ShutdownScript_new_p2wsh(script_hash: *const [u8; 32]) -> crate::lightning::ln::script::ShutdownScript {
	let mut ret = lightning::ln::script::ShutdownScript::new_p2wsh(&bitcoin::WScriptHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(unsafe { *script_hash }.clone())));
	crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Generates a witness script pubkey from the given segwit version and program.
///
/// Note for version-zero witness scripts you must use [`ShutdownScript::new_p2wpkh`] or
/// [`ShutdownScript::new_p2wsh`] instead.
///
/// # Errors
///
/// This function may return an error if `program` is invalid for the segwit `version`.
#[must_use]
#[no_mangle]
pub extern "C" fn ShutdownScript_new_witness_program(mut witness_program: crate::c_types::WitnessProgram) -> crate::c_types::derived::CResult_ShutdownScriptInvalidShutdownScriptZ {
	let mut ret = lightning::ln::script::ShutdownScript::new_witness_program(&witness_program.into_bitcoin());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::script::InvalidShutdownScript { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Converts the shutdown script into the underlying [`ScriptBuf`].
#[must_use]
#[no_mangle]
pub extern "C" fn ShutdownScript_into_inner(mut this_arg: crate::lightning::ln::script::ShutdownScript) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_inner();
	ret.to_bytes().into()
}

/// Returns the [`PublicKey`] used for a P2WPKH shutdown script if constructed directly from it.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ShutdownScript_as_legacy_pubkey(this_arg: &crate::lightning::ln::script::ShutdownScript) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_legacy_pubkey();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// Returns whether the shutdown script is compatible with the features as defined by BOLT #2.
///
/// Specifically, checks for compliance with feature `option_shutdown_anysegwit`.
#[must_use]
#[no_mangle]
pub extern "C" fn ShutdownScript_is_compatible(this_arg: &crate::lightning::ln::script::ShutdownScript, features: &crate::lightning_types::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_compatible(features.get_native_ref());
	ret
}

#[no_mangle]
/// Get the string representation of a ShutdownScript object
pub extern "C" fn ShutdownScript_to_str(o: &crate::lightning::ln::script::ShutdownScript) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}
