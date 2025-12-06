// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as [`ChannelManager`]s and [`ChannelMonitor`]s.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// serialization buffer size

#[no_mangle]
pub static MAX_BUF_SIZE: usize = lightning::util::ser::MAX_BUF_SIZE;

use lightning::util::ser::BigSize as nativeBigSizeImport;
pub(crate) type nativeBigSize = nativeBigSizeImport;

/// Lightning TLV uses a custom variable-length integer called `BigSize`. It is similar to Bitcoin's
/// variable-length integers except that it is serialized in big-endian instead of little-endian.
///
/// Like Bitcoin's variable-length integer, it exhibits ambiguity in that certain values can be
/// encoded in several different ways, which we must check for at deserialization-time. Thus, if
/// you're looking for an example of a variable-length integer to use for your own project, move
/// along, this is a rather poor design.
#[must_use]
#[repr(C)]
pub struct BigSize {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBigSize,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for BigSize {
	type Target = nativeBigSize;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for BigSize { }
unsafe impl core::marker::Sync for BigSize { }
impl Drop for BigSize {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBigSize>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BigSize, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BigSize_free(this_obj: BigSize) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BigSize_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBigSize) };
}
#[allow(unused)]
impl BigSize {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBigSize {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBigSize {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBigSize {
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
pub extern "C" fn BigSize_get_a(this_ptr: &BigSize) -> u64 {
	let mut inner_val = &mut BigSize::get_native_mut_ref(this_ptr).0;
	*inner_val
}
#[no_mangle]
pub extern "C" fn BigSize_set_a(this_ptr: &mut BigSize, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val;
}
/// Constructs a new BigSize given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BigSize_new(mut a_arg: u64) -> BigSize {
	BigSize { inner: ObjOps::heap_alloc(lightning::util::ser::BigSize (
		a_arg,
	)), is_owned: true }
}
impl Clone for BigSize {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBigSize>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BigSize_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeBigSize) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BigSize
pub extern "C" fn BigSize_clone(orig: &BigSize) -> BigSize {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a BigSize object
pub extern "C" fn BigSize_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::ser::BigSize }).into()}
/// Generates a non-cryptographic 64-bit hash of the BigSize.
#[no_mangle]
pub extern "C" fn BigSize_hash(o: &BigSize) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BigSizes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BigSize_eq(a: &BigSize, b: &BigSize) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the BigSize object into a byte array which can be read by BigSize_read
pub extern "C" fn BigSize_write(obj: &crate::lightning::util::ser::BigSize) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BigSize_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::util::ser::nativeBigSize) })
}
#[no_mangle]
/// Read a BigSize from a byte array, created by BigSize_write
pub extern "C" fn BigSize_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BigSizeDecodeErrorZ {
	let res: Result<lightning::util::ser::BigSize, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::ser::BigSize { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::util::ser::CollectionLength as nativeCollectionLengthImport;
pub(crate) type nativeCollectionLength = nativeCollectionLengthImport;

/// The lightning protocol uses u16s for lengths in most cases. As our serialization framework
/// primarily targets that, we must as well. However, because we may serialize objects that have
/// more than 65K entries, we need to be able to store larger values. Thus, we define a variable
/// length integer here that is backwards-compatible for values < 0xffff. We treat 0xffff as
/// \"read eight more bytes\".
///
/// To ensure we only have one valid encoding per value, we add 0xffff to values written as eight
/// bytes. Thus, 0xfffe is serialized as 0xfffe, whereas 0xffff is serialized as
/// 0xffff0000000000000000 (i.e. read-eight-bytes then zero).
#[must_use]
#[repr(C)]
pub struct CollectionLength {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCollectionLength,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for CollectionLength {
	type Target = nativeCollectionLength;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for CollectionLength { }
unsafe impl core::marker::Sync for CollectionLength { }
impl Drop for CollectionLength {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCollectionLength>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CollectionLength, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CollectionLength_free(this_obj: CollectionLength) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CollectionLength_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeCollectionLength) };
}
#[allow(unused)]
impl CollectionLength {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCollectionLength {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCollectionLength {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCollectionLength {
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
pub extern "C" fn CollectionLength_get_a(this_ptr: &CollectionLength) -> u64 {
	let mut inner_val = &mut CollectionLength::get_native_mut_ref(this_ptr).0;
	*inner_val
}
#[no_mangle]
pub extern "C" fn CollectionLength_set_a(this_ptr: &mut CollectionLength, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val;
}
/// Constructs a new CollectionLength given each field
#[must_use]
#[no_mangle]
pub extern "C" fn CollectionLength_new(mut a_arg: u64) -> CollectionLength {
	CollectionLength { inner: ObjOps::heap_alloc(lightning::util::ser::CollectionLength (
		a_arg,
	)), is_owned: true }
}
#[no_mangle]
/// Serialize the CollectionLength object into a byte array which can be read by CollectionLength_read
pub extern "C" fn CollectionLength_write(obj: &crate::lightning::util::ser::CollectionLength) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn CollectionLength_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::util::ser::nativeCollectionLength) })
}
#[no_mangle]
/// Read a CollectionLength from a byte array, created by CollectionLength_write
pub extern "C" fn CollectionLength_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CollectionLengthDecodeErrorZ {
	let res: Result<lightning::util::ser::CollectionLength, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::ser::CollectionLength { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the UntrustedString object into a byte array which can be read by UntrustedString_read
pub extern "C" fn UntrustedString_write(obj: &crate::lightning_types::string::UntrustedString) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn UntrustedString_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::string::nativeUntrustedString) })
}
#[no_mangle]
/// Read a UntrustedString from a byte array, created by UntrustedString_write
pub extern "C" fn UntrustedString_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UntrustedStringDecodeErrorZ {
	let res: Result<lightning_types::string::UntrustedString, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::string::UntrustedString { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::util::ser::Hostname as nativeHostnameImport;
pub(crate) type nativeHostname = nativeHostnameImport;

/// Represents a hostname for serialization purposes.
/// Only the character set and length will be validated.
/// The character set consists of ASCII alphanumeric characters, hyphens, and periods.
/// Its length is guaranteed to be representable by a single byte.
/// This serialization is used by [`BOLT 7`] hostnames.
///
/// [`BOLT 7`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md
#[must_use]
#[repr(C)]
pub struct Hostname {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHostname,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Hostname {
	type Target = nativeHostname;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Hostname { }
unsafe impl core::marker::Sync for Hostname { }
impl Drop for Hostname {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHostname>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Hostname, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Hostname_free(this_obj: Hostname) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Hostname_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHostname) };
}
#[allow(unused)]
impl Hostname {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHostname {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHostname {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHostname {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for Hostname {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHostname>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Hostname_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeHostname) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Hostname
pub extern "C" fn Hostname_clone(orig: &Hostname) -> Hostname {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a Hostname object
pub extern "C" fn Hostname_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::ser::Hostname }).into()}
/// Generates a non-cryptographic 64-bit hash of the Hostname.
#[no_mangle]
pub extern "C" fn Hostname_hash(o: &Hostname) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Hostnames contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Hostname_eq(a: &Hostname, b: &Hostname) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns the length of the hostname.
#[must_use]
#[no_mangle]
pub extern "C" fn Hostname_len(this_arg: &crate::lightning::util::ser::Hostname) -> u8 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.len();
	ret
}

#[no_mangle]
/// Get the string representation of a Hostname object
pub extern "C" fn Hostname_to_str(o: &crate::lightning::util::ser::Hostname) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}
#[no_mangle]
/// Serialize the Hostname object into a byte array which can be read by Hostname_read
pub extern "C" fn Hostname_write(obj: &crate::lightning::util::ser::Hostname) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Hostname_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::util::ser::nativeHostname) })
}
#[no_mangle]
/// Read a Hostname from a byte array, created by Hostname_write
pub extern "C" fn Hostname_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HostnameDecodeErrorZ {
	let res: Result<lightning::util::ser::Hostname, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::ser::Hostname { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
