// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for strings.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_types::string::UntrustedString as nativeUntrustedStringImport;
pub(crate) type nativeUntrustedString = nativeUntrustedStringImport;

/// Struct to `Display` fields in a safe way using `PrintableString`
#[must_use]
#[repr(C)]
pub struct UntrustedString {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUntrustedString,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for UntrustedString {
	type Target = nativeUntrustedString;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for UntrustedString { }
unsafe impl core::marker::Sync for UntrustedString { }
impl Drop for UntrustedString {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUntrustedString>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UntrustedString, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UntrustedString_free(this_obj: UntrustedString) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UntrustedString_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUntrustedString) };
}
#[allow(unused)]
impl UntrustedString {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUntrustedString {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUntrustedString {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUntrustedString {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
#[no_mangle]
pub extern "C" fn UntrustedString_get_a(this_ptr: &UntrustedString) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val.as_str().into()
}
#[no_mangle]
pub extern "C" fn UntrustedString_set_a(this_ptr: &mut UntrustedString, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_string();
}
/// Constructs a new UntrustedString given each field
#[must_use]
#[no_mangle]
pub extern "C" fn UntrustedString_new(mut a_arg: crate::c_types::Str) -> UntrustedString {
	UntrustedString { inner: ObjOps::heap_alloc(lightning_types::string::UntrustedString (
		a_arg.into_string(),
	)), is_owned: true }
}
impl Clone for UntrustedString {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUntrustedString>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UntrustedString_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUntrustedString)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UntrustedString
pub extern "C" fn UntrustedString_clone(orig: &UntrustedString) -> UntrustedString {
	orig.clone()
}
/// Get a string which allows debug introspection of a UntrustedString object
pub extern "C" fn UntrustedString_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_types::string::UntrustedString }).into()}
/// Checks if two UntrustedStrings contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn UntrustedString_eq(a: &UntrustedString, b: &UntrustedString) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Generates a non-cryptographic 64-bit hash of the UntrustedString.
#[no_mangle]
pub extern "C" fn UntrustedString_hash(o: &UntrustedString) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Get the string representation of a UntrustedString object
pub extern "C" fn UntrustedString_to_str(o: &crate::lightning_types::string::UntrustedString) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}

use lightning_types::string::PrintableString as nativePrintableStringImport;
pub(crate) type nativePrintableString = nativePrintableStringImport<'static, >;

/// A string that displays only printable characters, replacing control characters with
/// [`core::char::REPLACEMENT_CHARACTER`].
#[must_use]
#[repr(C)]
pub struct PrintableString {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePrintableString,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for PrintableString {
	type Target = nativePrintableString;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for PrintableString { }
unsafe impl core::marker::Sync for PrintableString { }
impl Drop for PrintableString {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePrintableString>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PrintableString, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PrintableString_free(this_obj: PrintableString) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PrintableString_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePrintableString) };
}
#[allow(unused)]
impl PrintableString {
	pub(crate) fn get_native_ref(&self) -> &'static nativePrintableString {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePrintableString {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePrintableString {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
#[no_mangle]
pub extern "C" fn PrintableString_get_a(this_ptr: &PrintableString) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val.into()
}
#[no_mangle]
pub extern "C" fn PrintableString_set_a(this_ptr: &mut PrintableString, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_str();
}
/// Constructs a new PrintableString given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PrintableString_new(mut a_arg: crate::c_types::Str) -> PrintableString {
	PrintableString { inner: ObjOps::heap_alloc(lightning_types::string::PrintableString (
		a_arg.into_str(),
	)), is_owned: true }
}
/// Get a string which allows debug introspection of a PrintableString object
pub extern "C" fn PrintableString_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_types::string::PrintableString }).into()}
#[no_mangle]
/// Get the string representation of a PrintableString object
pub extern "C" fn PrintableString_to_str(o: &crate::lightning_types::string::PrintableString) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}
