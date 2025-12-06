// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This module contains a simple key-value store trait [`KVStoreSync`] that
//! allows one to implement the persistence for [`ChannelManager`], [`NetworkGraph`],
//! and [`ChannelMonitor`] all in one place.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`NetworkGraph`]: crate::routing::gossip::NetworkGraph

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// The maximum number of characters namespaces and keys may have.

#[no_mangle]
pub static KVSTORE_NAMESPACE_KEY_MAX_LEN: usize = lightning::util::persist::KVSTORE_NAMESPACE_KEY_MAX_LEN;
/// Provides an interface that allows storage and retrieval of persisted values that are associated
/// with given keys.
///
/// In order to avoid collisions the key space is segmented based on the given `primary_namespace`s
/// and `secondary_namespace`s. Implementations of this trait are free to handle them in different
/// ways, as long as per-namespace key uniqueness is asserted.
///
/// Keys and namespaces are required to be valid ASCII strings in the range of
/// [`KVSTORE_NAMESPACE_KEY_ALPHABET`] and no longer than [`KVSTORE_NAMESPACE_KEY_MAX_LEN`]. Empty
/// primary namespaces and secondary namespaces (`\"\"`) are assumed to be a valid, however, if
/// `primary_namespace` is empty, `secondary_namespace` is required to be empty, too. This means
/// that concerns should always be separated by primary namespace first, before secondary
/// namespaces are used. While the number of primary namespaces will be relatively small and is
/// determined at compile time, there may be many secondary namespaces per primary namespace. Note
/// that per-namespace uniqueness needs to also hold for keys *and* namespaces in any given
/// namespace, i.e., conflicts between keys and equally named
/// primary namespaces/secondary namespaces must be avoided.
///
/// **Note:** Users migrating custom persistence backends from the pre-v0.0.117 `KVStorePersister`
/// interface can use a concatenation of `[{primary_namespace}/[{secondary_namespace}/]]{key}` to
/// recover a `key` compatible with the data model previously assumed by `KVStorePersister::persist`.
///
/// For an asynchronous version of this trait, see [`KVStore`].
#[repr(C)]
pub struct KVStoreSync {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the data stored for the given `primary_namespace`, `secondary_namespace`, and
	/// `key`.
	///
	/// Returns an [`ErrorKind::NotFound`] if the given `key` could not be found in the given
	/// `primary_namespace` and `secondary_namespace`.
	///
	/// [`ErrorKind::NotFound`]: io::ErrorKind::NotFound
	pub read: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str, key: crate::c_types::Str) -> crate::c_types::derived::CResult_CVec_u8ZIOErrorZ,
	/// Persists the given data under the given `key`.
	///
	/// Will create the given `primary_namespace` and `secondary_namespace` if not already present in the store.
	pub write: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str, key: crate::c_types::Str, buf: crate::c_types::derived::CVec_u8Z) -> crate::c_types::derived::CResult_NoneIOErrorZ,
	/// Removes any data that had previously been persisted under the given `key`.
	///
	/// If the `lazy` flag is set to `true`, the backend implementation might choose to lazily
	/// remove the given `key` at some point in time after the method returns, e.g., as part of an
	/// eventual batch deletion of multiple keys. As a consequence, subsequent calls to
	/// [`KVStoreSync::list`] might include the removed key until the changes are actually persisted.
	///
	/// Note that while setting the `lazy` flag reduces the I/O burden of multiple subsequent
	/// `remove` calls, it also influences the atomicity guarantees as lazy `remove`s could
	/// potentially get lost on crash after the method returns. Therefore, this flag should only be
	/// set for `remove` operations that can be safely replayed at a later time.
	///
	/// All removal operations must complete in a consistent total order with [`Self::write`]s
	/// to the same key. Whether a removal operation is `lazy` or not, [`Self::write`] operations
	/// to the same key which occur before a removal completes must cancel/overwrite the pending
	/// removal.
	///
	/// Returns successfully if no data will be stored for the given `primary_namespace`,
	/// `secondary_namespace`, and `key`, independently of whether it was present before its
	/// invokation or not.
	pub remove: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str, key: crate::c_types::Str, lazy: bool) -> crate::c_types::derived::CResult_NoneIOErrorZ,
	/// Returns a list of keys that are stored under the given `secondary_namespace` in
	/// `primary_namespace`.
	///
	/// Returns the keys in arbitrary order, so users requiring a particular order need to sort the
	/// returned keys. Returns an empty list if `primary_namespace` or `secondary_namespace` is unknown.
	pub list: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str) -> crate::c_types::derived::CResult_CVec_StrZIOErrorZ,
	/// Called, if set, after this KVStoreSync has been cloned into a duplicate object.
	/// The new KVStoreSync is provided, and should be mutated as needed to perform a
	/// deep copy of the object pointed to by this_arg or avoid any double-freeing.
	pub cloned: Option<extern "C" fn (new_KVStoreSync: &mut KVStoreSync)>,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for KVStoreSync {}
unsafe impl Sync for KVStoreSync {}
#[allow(unused)]
pub(crate) fn KVStoreSync_clone_fields(orig: &KVStoreSync) -> KVStoreSync {
	KVStoreSync {
		this_arg: orig.this_arg,
		read: Clone::clone(&orig.read),
		write: Clone::clone(&orig.write),
		remove: Clone::clone(&orig.remove),
		list: Clone::clone(&orig.list),
		cloned: Clone::clone(&orig.cloned),
		free: Clone::clone(&orig.free),
	}
}
#[no_mangle]
/// Creates a copy of a KVStoreSync
pub extern "C" fn KVStoreSync_clone(orig: &KVStoreSync) -> KVStoreSync {
	let mut res = KVStoreSync_clone_fields(orig);
	if let Some(f) = orig.cloned { (f)(&mut res) };
	res
}
impl Clone for KVStoreSync {
	fn clone(&self) -> Self {
		KVStoreSync_clone(self)
	}
}
impl Clone for KVStoreSyncRef {
	fn clone(&self) -> Self {
		Self(KVStoreSync_clone(&self.0))
	}
}

use lightning::util::persist::KVStoreSync as rustKVStoreSync;
impl rustKVStoreSync for KVStoreSync {
	fn read(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str) -> Result<Vec<u8>, lightning::io::Error> {
		let mut ret = (self.read)(self.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn write(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut buf: Vec<u8>) -> Result<(), lightning::io::Error> {
		let mut local_buf = Vec::new(); for mut item in buf.drain(..) { local_buf.push( { item }); };
		let mut ret = (self.write)(self.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), local_buf.into());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn remove(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut lazy: bool) -> Result<(), lightning::io::Error> {
		let mut ret = (self.remove)(self.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), lazy);
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn list(&self, mut primary_namespace: &str, mut secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
		let mut ret = (self.list)(self.this_arg, primary_namespace.into(), secondary_namespace.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item.into_string() }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}

pub struct KVStoreSyncRef(KVStoreSync);
impl rustKVStoreSync for KVStoreSyncRef {
	fn read(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str) -> Result<Vec<u8>, lightning::io::Error> {
		let mut ret = (self.0.read)(self.0.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn write(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut buf: Vec<u8>) -> Result<(), lightning::io::Error> {
		let mut local_buf = Vec::new(); for mut item in buf.drain(..) { local_buf.push( { item }); };
		let mut ret = (self.0.write)(self.0.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), local_buf.into());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn remove(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut lazy: bool) -> Result<(), lightning::io::Error> {
		let mut ret = (self.0.remove)(self.0.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), lazy);
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn list(&self, mut primary_namespace: &str, mut secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
		let mut ret = (self.0.list)(self.0.this_arg, primary_namespace.into(), secondary_namespace.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item.into_string() }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for KVStoreSync {
	type Target = KVStoreSyncRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const KVStoreSyncRef) }
	}
}
impl core::ops::DerefMut for KVStoreSync {
	fn deref_mut(&mut self) -> &mut KVStoreSyncRef {
		unsafe { &mut *(self as *mut _ as *mut KVStoreSyncRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn KVStoreSync_free(this_ptr: KVStoreSync) { }
impl Drop for KVStoreSync {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::util::persist::KVStoreSyncWrapper as nativeKVStoreSyncWrapperImport;
pub(crate) type nativeKVStoreSyncWrapper = nativeKVStoreSyncWrapperImport<crate::lightning::util::persist::KVStoreSync, >;

/// A wrapper around a [`KVStoreSync`] that implements the [`KVStore`] trait. It is not necessary to use this type
/// directly.
#[must_use]
#[repr(C)]
pub struct KVStoreSyncWrapper {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeKVStoreSyncWrapper,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for KVStoreSyncWrapper {
	type Target = nativeKVStoreSyncWrapper;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for KVStoreSyncWrapper { }
unsafe impl core::marker::Sync for KVStoreSyncWrapper { }
impl Drop for KVStoreSyncWrapper {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeKVStoreSyncWrapper>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the KVStoreSyncWrapper, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn KVStoreSyncWrapper_free(this_obj: KVStoreSyncWrapper) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn KVStoreSyncWrapper_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeKVStoreSyncWrapper) };
}
#[allow(unused)]
impl KVStoreSyncWrapper {
	pub(crate) fn get_native_ref(&self) -> &'static nativeKVStoreSyncWrapper {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeKVStoreSyncWrapper {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeKVStoreSyncWrapper {
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
pub extern "C" fn KVStoreSyncWrapper_get_a(this_ptr: &KVStoreSyncWrapper) -> *const crate::lightning::util::persist::KVStoreSync {
	let mut inner_val = &mut KVStoreSyncWrapper::get_native_mut_ref(this_ptr).0;
	inner_val
}
#[no_mangle]
pub extern "C" fn KVStoreSyncWrapper_set_a(this_ptr: &mut KVStoreSyncWrapper, mut val: crate::lightning::util::persist::KVStoreSync) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val;
}
/// Constructs a new KVStoreSyncWrapper given each field
#[must_use]
#[no_mangle]
pub extern "C" fn KVStoreSyncWrapper_new(mut a_arg: crate::lightning::util::persist::KVStoreSync) -> KVStoreSyncWrapper {
	KVStoreSyncWrapper { inner: ObjOps::heap_alloc(lightning::util::persist::KVStoreSyncWrapper (
		a_arg,
	)), is_owned: true }
}
impl Clone for KVStoreSyncWrapper {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeKVStoreSyncWrapper>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn KVStoreSyncWrapper_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeKVStoreSyncWrapper) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the KVStoreSyncWrapper
pub extern "C" fn KVStoreSyncWrapper_clone(orig: &KVStoreSyncWrapper) -> KVStoreSyncWrapper {
	Clone::clone(orig)
}
/// Provides additional interface methods that are required for [`KVStore`]-to-[`KVStore`]
/// data migration.
#[repr(C)]
pub struct MigratableKVStore {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns *all* known keys as a list of `primary_namespace`, `secondary_namespace`, `key` tuples.
	///
	/// This is useful for migrating data from [`KVStoreSync`] implementation to [`KVStoreSync`]
	/// implementation.
	///
	/// Must exhaustively return all entries known to the store to ensure no data is missed, but
	/// may return the items in arbitrary order.
	pub list_all_keys: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CResult_CVec_C3Tuple_StrStrStrZZIOErrorZ,
	/// Implementation of KVStoreSync for this object.
	pub KVStoreSync: crate::lightning::util::persist::KVStoreSync,
	/// Called, if set, after this MigratableKVStore has been cloned into a duplicate object.
	/// The new MigratableKVStore is provided, and should be mutated as needed to perform a
	/// deep copy of the object pointed to by this_arg or avoid any double-freeing.
	pub cloned: Option<extern "C" fn (new_MigratableKVStore: &mut MigratableKVStore)>,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for MigratableKVStore {}
unsafe impl Sync for MigratableKVStore {}
#[allow(unused)]
pub(crate) fn MigratableKVStore_clone_fields(orig: &MigratableKVStore) -> MigratableKVStore {
	MigratableKVStore {
		this_arg: orig.this_arg,
		list_all_keys: Clone::clone(&orig.list_all_keys),
		KVStoreSync: crate::lightning::util::persist::KVStoreSync_clone_fields(&orig.KVStoreSync),
		cloned: Clone::clone(&orig.cloned),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::util::persist::KVStoreSync for MigratableKVStore {
	fn read(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str) -> Result<Vec<u8>, lightning::io::Error> {
		let mut ret = (self.KVStoreSync.read)(self.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn write(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut buf: Vec<u8>) -> Result<(), lightning::io::Error> {
		let mut local_buf = Vec::new(); for mut item in buf.drain(..) { local_buf.push( { item }); };
		let mut ret = (self.KVStoreSync.write)(self.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), local_buf.into());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn remove(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut lazy: bool) -> Result<(), lightning::io::Error> {
		let mut ret = (self.KVStoreSync.remove)(self.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), lazy);
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn list(&self, mut primary_namespace: &str, mut secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
		let mut ret = (self.KVStoreSync.list)(self.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item.into_string() }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}
impl lightning::util::persist::KVStoreSync for MigratableKVStoreRef {
	fn read(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str) -> Result<Vec<u8>, lightning::io::Error> {
		let mut ret = (self.0.KVStoreSync.read)(self.0.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn write(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut buf: Vec<u8>) -> Result<(), lightning::io::Error> {
		let mut local_buf = Vec::new(); for mut item in buf.drain(..) { local_buf.push( { item }); };
		let mut ret = (self.0.KVStoreSync.write)(self.0.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), local_buf.into());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn remove(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut lazy: bool) -> Result<(), lightning::io::Error> {
		let mut ret = (self.0.KVStoreSync.remove)(self.0.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), lazy);
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn list(&self, mut primary_namespace: &str, mut secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
		let mut ret = (self.0.KVStoreSync.list)(self.0.KVStoreSync.this_arg, primary_namespace.into(), secondary_namespace.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item.into_string() }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}
#[no_mangle]
/// Creates a copy of a MigratableKVStore
pub extern "C" fn MigratableKVStore_clone(orig: &MigratableKVStore) -> MigratableKVStore {
	let mut res = MigratableKVStore_clone_fields(orig);
	if let Some(f) = orig.cloned { (f)(&mut res) };
	res
}
impl Clone for MigratableKVStore {
	fn clone(&self) -> Self {
		MigratableKVStore_clone(self)
	}
}
impl Clone for MigratableKVStoreRef {
	fn clone(&self) -> Self {
		Self(MigratableKVStore_clone(&self.0))
	}
}

use lightning::util::persist::MigratableKVStore as rustMigratableKVStore;
impl rustMigratableKVStore for MigratableKVStore {
	fn list_all_keys(&self) -> Result<Vec<(String, String, String)>, lightning::io::Error> {
		let mut ret = (self.list_all_keys)(self.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1, mut orig_ret_0_0_2) = item.to_rust(); let mut local_ret_0_0 = (orig_ret_0_0_0.into_string(), orig_ret_0_0_1.into_string(), orig_ret_0_0_2.into_string()); local_ret_0_0 }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}

pub struct MigratableKVStoreRef(MigratableKVStore);
impl rustMigratableKVStore for MigratableKVStoreRef {
	fn list_all_keys(&self) -> Result<Vec<(String, String, String)>, lightning::io::Error> {
		let mut ret = (self.0.list_all_keys)(self.0.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1, mut orig_ret_0_0_2) = item.to_rust(); let mut local_ret_0_0 = (orig_ret_0_0_0.into_string(), orig_ret_0_0_1.into_string(), orig_ret_0_0_2.into_string()); local_ret_0_0 }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for MigratableKVStore {
	type Target = MigratableKVStoreRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const MigratableKVStoreRef) }
	}
}
impl core::ops::DerefMut for MigratableKVStore {
	fn deref_mut(&mut self) -> &mut MigratableKVStoreRef {
		unsafe { &mut *(self as *mut _ as *mut MigratableKVStoreRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn MigratableKVStore_free(this_ptr: MigratableKVStore) { }
impl Drop for MigratableKVStore {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Migrates all data from one store to another.
///
/// This operation assumes that `target_store` is empty, i.e., any data present under copied keys
/// might get overriden. User must ensure `source_store` is not modified during operation,
/// otherwise no consistency guarantees can be given.
///
/// Will abort and return an error if any IO operation fails. Note that in this case the
/// `target_store` might get left in an intermediate state.
#[no_mangle]
pub extern "C" fn migrate_kv_store_data(source_store: &mut crate::lightning::util::persist::MigratableKVStore, target_store: &mut crate::lightning::util::persist::MigratableKVStore) -> crate::c_types::derived::CResult_NoneIOErrorZ {
	let mut ret = lightning::util::persist::migrate_kv_store_data::<crate::lightning::util::persist::MigratableKVStore, crate::lightning::util::persist::MigratableKVStore, >(source_store, target_store);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_bitcoin(e) }).into() };
	local_ret
}

/// Read previously persisted [`ChannelMonitor`]s from the store.
#[no_mangle]
pub extern "C" fn read_channel_monitors(mut kv_store: crate::lightning::util::persist::KVStoreSync, mut entropy_source: crate::lightning::sign::EntropySource, mut signer_provider: crate::lightning::sign::SignerProvider) -> crate::c_types::derived::CResult_CVec_C2Tuple_ThirtyTwoBytesChannelMonitorZZIOErrorZ {
	let mut ret = lightning::util::persist::read_channel_monitors::<crate::lightning::util::persist::KVStoreSync, crate::lightning::sign::EntropySource, crate::lightning::sign::SignerProvider, >(kv_store, entropy_source, signer_provider);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::c_types::ThirtyTwoBytes { data: *orig_ret_0_0_0.as_ref() }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(orig_ret_0_0_1), is_owned: true }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_bitcoin(e) }).into() };
	local_ret
}


use lightning::util::persist::MonitorUpdatingPersister as nativeMonitorUpdatingPersisterImport;
pub(crate) type nativeMonitorUpdatingPersister = nativeMonitorUpdatingPersisterImport<crate::lightning::util::persist::KVStoreSync, crate::lightning::util::logger::Logger, crate::lightning::sign::EntropySource, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::chaininterface::FeeEstimator, >;

/// Implements [`Persist`] in a way that writes and reads both [`ChannelMonitor`]s and
/// [`ChannelMonitorUpdate`]s.
///
/// # Overview
///
/// The main benefit this provides over the [`KVStoreSync`]'s [`Persist`] implementation is decreased
/// I/O bandwidth and storage churn, at the expense of more IOPS (including listing, reading, and
/// deleting) and complexity. This is because it writes channel monitor differential updates,
/// whereas the other (default) implementation rewrites the entire monitor on each update. For
/// routing nodes, updates can happen many times per second to a channel, and monitors can be tens
/// of megabytes (or more). Updates can be as small as a few hundred bytes.
///
/// Note that monitors written with `MonitorUpdatingPersister` are _not_ backward-compatible with
/// the default [`KVStoreSync`]'s [`Persist`] implementation. They have a prepended byte sequence,
/// [`MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL`], applied to prevent deserialization with other
/// persisters. This is because monitors written by this struct _may_ have unapplied updates. In
/// order to downgrade, you must ensure that all updates are applied to the monitor, and remove the
/// sentinel bytes.
///
/// # Storing monitors
///
/// Monitors are stored by implementing the [`Persist`] trait, which has two functions:
///
///   - [`Persist::persist_new_channel`], which persists whole [`ChannelMonitor`]s.
///   - [`Persist::update_persisted_channel`], which persists only a [`ChannelMonitorUpdate`]
///
/// Whole [`ChannelMonitor`]s are stored in the [`CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE`],
/// using the familiar encoding of an [`OutPoint`] (e.g., `[SOME-64-CHAR-HEX-STRING]_1`) for v1
/// channels or a [`ChannelId`] (e.g., `[SOME-64-CHAR-HEX-STRING]`) for v2 channels.
///
/// Each [`ChannelMonitorUpdate`] is stored in a dynamic secondary namespace, as follows:
///
///   - primary namespace: [`CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE`]
///   - secondary namespace: [the monitor's encoded outpoint or channel id name]
///
/// Under that secondary namespace, each update is stored with a number string, like `21`, which
/// represents its `update_id` value.
///
/// For example, consider this channel, named for its transaction ID and index, or [`OutPoint`]:
///
///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
///   - Index: `1`
///
/// Full channel monitors would be stored at a single key:
///
/// `[CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
///
/// Updates would be stored as follows (with `/` delimiting primary_namespace/secondary_namespace/key):
///
/// ```text
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/1
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/2
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/3
/// ```
/// ... and so on.
///
/// # Reading channel state from storage
///
/// Channel state can be reconstructed by calling
/// [`MonitorUpdatingPersister::read_all_channel_monitors_with_updates`]. Alternatively, users can
/// list channel monitors themselves and load channels individually using
/// [`MonitorUpdatingPersister::read_channel_monitor_with_updates`].
///
/// ## EXTREMELY IMPORTANT
///
/// It is extremely important that your [`KVStoreSync::read`] implementation uses the
/// [`io::ErrorKind::NotFound`] variant correctly: that is, when a file is not found, and _only_ in
/// that circumstance (not when there is really a permissions error, for example). This is because
/// neither channel monitor reading function lists updates. Instead, either reads the monitor, and
/// using its stored `update_id`, synthesizes update storage keys, and tries them in sequence until
/// one is not found. All _other_ errors will be bubbled up in the function's [`Result`].
///
/// # Pruning stale channel updates
///
/// Stale updates are pruned when the consolidation threshold is reached according to `maximum_pending_updates`.
/// Monitor updates in the range between the latest `update_id` and `update_id - maximum_pending_updates`
/// are deleted.
/// The `lazy` flag is used on the [`KVStoreSync::remove`] method, so there are no guarantees that the deletions
/// will complete. However, stale updates are not a problem for data integrity, since updates are
/// only read that are higher than the stored [`ChannelMonitor`]'s `update_id`.
///
/// If you have many stale updates stored (such as after a crash with pending lazy deletes), and
/// would like to get rid of them, consider using the
/// [`MonitorUpdatingPersister::cleanup_stale_updates`] function.
#[must_use]
#[repr(C)]
pub struct MonitorUpdatingPersister {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMonitorUpdatingPersister,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for MonitorUpdatingPersister {
	type Target = nativeMonitorUpdatingPersister;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for MonitorUpdatingPersister { }
unsafe impl core::marker::Sync for MonitorUpdatingPersister { }
impl Drop for MonitorUpdatingPersister {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMonitorUpdatingPersister>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MonitorUpdatingPersister, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_free(this_obj: MonitorUpdatingPersister) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MonitorUpdatingPersister_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMonitorUpdatingPersister) };
}
#[allow(unused)]
impl MonitorUpdatingPersister {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMonitorUpdatingPersister {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMonitorUpdatingPersister {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMonitorUpdatingPersister {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new [`MonitorUpdatingPersister`].
///
/// The `maximum_pending_updates` parameter controls how many updates may be stored before a
/// [`MonitorUpdatingPersister`] consolidates updates by writing a full monitor. Note that
/// consolidation will frequently occur with fewer updates than what you set here; this number
/// is merely the maximum that may be stored. When setting this value, consider that for higher
/// values of `maximum_pending_updates`:
///
///   - [`MonitorUpdatingPersister`] will tend to write more [`ChannelMonitorUpdate`]s than
/// [`ChannelMonitor`]s, approaching one [`ChannelMonitor`] write for every
/// `maximum_pending_updates` [`ChannelMonitorUpdate`]s.
///   - [`MonitorUpdatingPersister`] will issue deletes differently. Lazy deletes will come in
/// \"waves\" for each [`ChannelMonitor`] write. A larger `maximum_pending_updates` means bigger,
/// less frequent \"waves.\"
///   - [`MonitorUpdatingPersister`] will potentially have more listing to do if you need to run
/// [`MonitorUpdatingPersister::cleanup_stale_updates`].
///
/// Note that you can disable the update-writing entirely by setting `maximum_pending_updates`
/// to zero, causing this [`Persist`] implementation to behave like the blanket [`Persist`]
/// implementation for all [`KVStoreSync`]s.
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_new(mut kv_store: crate::lightning::util::persist::KVStoreSync, mut logger: crate::lightning::util::logger::Logger, mut maximum_pending_updates: u64, mut entropy_source: crate::lightning::sign::EntropySource, mut signer_provider: crate::lightning::sign::SignerProvider, mut broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut fee_estimator: crate::lightning::chain::chaininterface::FeeEstimator) -> crate::lightning::util::persist::MonitorUpdatingPersister {
	let mut ret = lightning::util::persist::MonitorUpdatingPersister::new(kv_store, logger, maximum_pending_updates, entropy_source, signer_provider, broadcaster, fee_estimator);
	crate::lightning::util::persist::MonitorUpdatingPersister { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Reads all stored channel monitors, along with any stored updates for them.
///
/// It is extremely important that your [`KVStoreSync::read`] implementation uses the
/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
/// documentation for [`MonitorUpdatingPersister`].
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_read_all_channel_monitors_with_updates(this_arg: &crate::lightning::util::persist::MonitorUpdatingPersister) -> crate::c_types::derived::CResult_CVec_C2Tuple_ThirtyTwoBytesChannelMonitorZZIOErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.read_all_channel_monitors_with_updates();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::c_types::ThirtyTwoBytes { data: *orig_ret_0_0_0.as_ref() }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(orig_ret_0_0_1), is_owned: true }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_bitcoin(e) }).into() };
	local_ret
}

/// Read a single channel monitor, along with any stored updates for it.
///
/// It is extremely important that your [`KVStoreSync::read`] implementation uses the
/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
/// documentation for [`MonitorUpdatingPersister`].
///
/// For `monitor_key`, channel storage keys can be the channel's funding [`OutPoint`], with an
/// underscore `_` between txid and index for v1 channels. For example, given:
///
///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
///   - Index: `1`
///
/// The correct `monitor_key` would be:
/// `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
///
/// For v2 channels, the hex-encoded [`ChannelId`] is used directly for `monitor_key` instead.
///
/// Loading a large number of monitors will be faster if done in parallel. You can use this
/// function to accomplish this. Take care to limit the number of parallel readers.
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_read_channel_monitor_with_updates(this_arg: &crate::lightning::util::persist::MonitorUpdatingPersister, mut monitor_key: crate::c_types::Str) -> crate::c_types::derived::CResult_C2Tuple_ThirtyTwoBytesChannelMonitorZIOErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.read_channel_monitor_with_updates(monitor_key.into_str());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: *orig_ret_0_0.as_ref() }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_bitcoin(e) }).into() };
	local_ret
}

/// Cleans up stale updates for all monitors.
///
/// This function works by first listing all monitors, and then for each of them, listing all
/// updates. The updates that have an `update_id` less than or equal to than the stored monitor
/// are deleted. The deletion can either be lazy or non-lazy based on the `lazy` flag; this will
/// be passed to [`KVStoreSync::remove`].
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_cleanup_stale_updates(this_arg: &crate::lightning::util::persist::MonitorUpdatingPersister, mut lazy: bool) -> crate::c_types::derived::CResult_NoneIOErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.cleanup_stale_updates(lazy);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_bitcoin(e) }).into() };
	local_ret
}

impl From<nativeMonitorUpdatingPersister> for crate::lightning::chain::chainmonitor::Persist {
	fn from(obj: nativeMonitorUpdatingPersister) -> Self {
		let rust_obj = crate::lightning::util::persist::MonitorUpdatingPersister { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MonitorUpdatingPersister_as_Persist(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(MonitorUpdatingPersister_free_void);
		ret
	}
}
/// Constructs a new Persist which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Persist must be freed before this_arg is
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_as_Persist(this_arg: &MonitorUpdatingPersister) -> crate::lightning::chain::chainmonitor::Persist {
	crate::lightning::chain::chainmonitor::Persist {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		persist_new_channel: MonitorUpdatingPersister_Persist_persist_new_channel,
		update_persisted_channel: MonitorUpdatingPersister_Persist_update_persisted_channel,
		archive_persisted_channel: MonitorUpdatingPersister_Persist_archive_persisted_channel,
		get_and_clear_completed_updates: MonitorUpdatingPersister_Persist_get_and_clear_completed_updates,
	}
}

#[must_use]
extern "C" fn MonitorUpdatingPersister_Persist_persist_new_channel(this_arg: *const c_void, mut monitor_name: crate::lightning::util::persist::MonitorName, monitor: &crate::lightning::chain::channelmonitor::ChannelMonitor) -> crate::lightning::chain::ChannelMonitorUpdateStatus {
	let mut ret = <nativeMonitorUpdatingPersister as lightning::chain::chainmonitor::Persist<crate::lightning::sign::ecdsa::EcdsaChannelSigner, >>::persist_new_channel(unsafe { &mut *(this_arg as *mut nativeMonitorUpdatingPersister) }, monitor_name.into_native(), monitor.get_native_ref());
	crate::lightning::chain::ChannelMonitorUpdateStatus::native_into(ret)
}
#[must_use]
extern "C" fn MonitorUpdatingPersister_Persist_update_persisted_channel(this_arg: *const c_void, mut monitor_name: crate::lightning::util::persist::MonitorName, mut monitor_update: crate::lightning::chain::channelmonitor::ChannelMonitorUpdate, monitor: &crate::lightning::chain::channelmonitor::ChannelMonitor) -> crate::lightning::chain::ChannelMonitorUpdateStatus {
	let mut local_monitor_update = if monitor_update.inner.is_null() { None } else { Some( { monitor_update.get_native_ref() }) };
	let mut ret = <nativeMonitorUpdatingPersister as lightning::chain::chainmonitor::Persist<crate::lightning::sign::ecdsa::EcdsaChannelSigner, >>::update_persisted_channel(unsafe { &mut *(this_arg as *mut nativeMonitorUpdatingPersister) }, monitor_name.into_native(), local_monitor_update, monitor.get_native_ref());
	crate::lightning::chain::ChannelMonitorUpdateStatus::native_into(ret)
}
extern "C" fn MonitorUpdatingPersister_Persist_archive_persisted_channel(this_arg: *const c_void, mut monitor_name: crate::lightning::util::persist::MonitorName) {
	<nativeMonitorUpdatingPersister as lightning::chain::chainmonitor::Persist<crate::lightning::sign::ecdsa::EcdsaChannelSigner, >>::archive_persisted_channel(unsafe { &mut *(this_arg as *mut nativeMonitorUpdatingPersister) }, monitor_name.into_native())
}
#[must_use]
extern "C" fn MonitorUpdatingPersister_Persist_get_and_clear_completed_updates(this_arg: *const c_void) -> crate::c_types::derived::CVec_C2Tuple_ChannelIdu64ZZ {
	let mut ret = <nativeMonitorUpdatingPersister as lightning::chain::chainmonitor::Persist<crate::lightning::sign::ecdsa::EcdsaChannelSigner, >>::get_and_clear_completed_updates(unsafe { &mut *(this_arg as *mut nativeMonitorUpdatingPersister) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item; let mut local_ret_0 = (crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, orig_ret_0_1).into(); local_ret_0 }); };
	local_ret.into()
}

/// A struct representing a name for a channel monitor.
///
/// `MonitorName` is primarily used within the [`MonitorUpdatingPersister`]
/// in functions that store or retrieve [`ChannelMonitor`] snapshots.
/// It provides a consistent way to generate a unique key for channel
/// monitors based on the channel's funding [`OutPoint`] for v1 channels or
/// [`ChannelId`] for v2 channels. Use [`ChannelMonitor::persistence_key`] to
/// obtain the correct `MonitorName`.
///
/// While users of the Lightning Dev Kit library generally won't need
/// to interact with [`MonitorName`] directly, it can be useful for:
/// - Custom persistence implementations
/// - Debugging or logging channel monitor operations
/// - Extending the functionality of the `MonitorUpdatingPersister`
///
/// # Examples
///
/// ```
/// use std::str::FromStr;
///
/// use bitcoin::Txid;
/// use bitcoin::hashes::hex::FromHex;
///
/// use lightning::util::persist::MonitorName;
/// use lightning::chain::transaction::OutPoint;
/// use lightning::ln::types::ChannelId;
///
/// // v1 channel
/// let outpoint = OutPoint {
///\t txid: Txid::from_str(\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\").unwrap(),
///\t index: 1,
/// };
/// let monitor_name = MonitorName::V1Channel(outpoint);
/// assert_eq!(&monitor_name.to_string(), \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1\");
///
/// // v2 channel
/// let channel_id = ChannelId(<[u8; 32]>::from_hex(\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\").unwrap());
/// let monitor_name = MonitorName::V2Channel(channel_id);
/// assert_eq!(&monitor_name.to_string(), \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\");
///
/// // Using MonitorName to generate a storage key
/// let storage_key = format!(\"channel_monitors/{}\", monitor_name);
/// ```
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum MonitorName {
	/// The outpoint of the channel's funding transaction.
	V1Channel(
		crate::lightning::chain::transaction::OutPoint),
	/// The id of the channel produced by [`ChannelId::v2_from_revocation_basepoints`].
	V2Channel(
		crate::lightning::ln::types::ChannelId),
}
use lightning::util::persist::MonitorName as MonitorNameImport;
pub(crate) type nativeMonitorName = MonitorNameImport;

impl MonitorName {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMonitorName {
		match self {
			MonitorName::V1Channel (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeMonitorName::V1Channel (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			MonitorName::V2Channel (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeMonitorName::V2Channel (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeMonitorName {
		match self {
			MonitorName::V1Channel (mut a, ) => {
				nativeMonitorName::V1Channel (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			MonitorName::V2Channel (mut a, ) => {
				nativeMonitorName::V2Channel (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &MonitorNameImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeMonitorName) };
		match native {
			nativeMonitorName::V1Channel (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				MonitorName::V1Channel (
					crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeMonitorName::V2Channel (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				MonitorName::V2Channel (
					crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeMonitorName) -> Self {
		match native {
			nativeMonitorName::V1Channel (mut a, ) => {
				MonitorName::V1Channel (
					crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeMonitorName::V2Channel (mut a, ) => {
				MonitorName::V2Channel (
					crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the MonitorName
#[no_mangle]
pub extern "C" fn MonitorName_free(this_ptr: MonitorName) { }
/// Creates a copy of the MonitorName
#[no_mangle]
pub extern "C" fn MonitorName_clone(orig: &MonitorName) -> MonitorName {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MonitorName_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const MonitorName)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MonitorName_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut MonitorName) };
}
#[no_mangle]
/// Utility method to constructs a new V1Channel-variant MonitorName
pub extern "C" fn MonitorName_v1_channel(a: crate::lightning::chain::transaction::OutPoint) -> MonitorName {
	MonitorName::V1Channel(a, )
}
#[no_mangle]
/// Utility method to constructs a new V2Channel-variant MonitorName
pub extern "C" fn MonitorName_v2_channel(a: crate::lightning::ln::types::ChannelId) -> MonitorName {
	MonitorName::V2Channel(a, )
}
/// Get a string which allows debug introspection of a MonitorName object
pub extern "C" fn MonitorName_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::persist::MonitorName }).into()}
/// Checks if two MonitorNames contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn MonitorName_eq(a: &MonitorName, b: &MonitorName) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Generates a non-cryptographic 64-bit hash of the MonitorName.
#[no_mangle]
pub extern "C" fn MonitorName_hash(o: &MonitorName) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Get the string representation of a MonitorName object
pub extern "C" fn MonitorName_to_str(o: &crate::lightning::util::persist::MonitorName) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}

use lightning::util::persist::UpdateName as nativeUpdateNameImport;
pub(crate) type nativeUpdateName = nativeUpdateNameImport;

/// A struct representing a name for a channel monitor update.
///
/// [`UpdateName`] is primarily used within the [`MonitorUpdatingPersister`] in
/// functions that store or retrieve partial updates to channel monitors. It
/// provides a consistent way to generate and parse unique identifiers for
/// monitor updates based on their sequence number.
///
/// The name is derived from the update's sequence ID, which is a monotonically
/// increasing u64 value. This format allows for easy ordering of updates and
/// efficient storage and retrieval in key-value stores.
///
/// # Usage
///
/// While users of the Lightning Dev Kit library generally won't need to
/// interact with `UpdateName` directly, it still can be useful for custom
/// persistence implementations. The u64 value is the update_id that can be
/// compared with [ChannelMonitor::get_latest_update_id] to check if this update
/// has been applied to the channel monitor or not, which is useful for pruning
/// stale channel monitor updates off persistence.
///
/// # Examples
///
/// ```
/// use lightning::util::persist::UpdateName;
///
/// let update_id: u64 = 42;
/// let update_name = UpdateName::from(update_id);
/// assert_eq!(update_name.as_str(), \"42\");
///
/// // Using UpdateName to generate a storage key
/// let monitor_name = \"some_monitor_name\";
/// let storage_key = format!(\"channel_monitor_updates/{}/{}\", monitor_name, update_name.as_str());
/// ```
#[must_use]
#[repr(C)]
pub struct UpdateName {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUpdateName,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for UpdateName {
	type Target = nativeUpdateName;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for UpdateName { }
unsafe impl core::marker::Sync for UpdateName { }
impl Drop for UpdateName {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUpdateName>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UpdateName, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UpdateName_free(this_obj: UpdateName) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UpdateName_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUpdateName) };
}
#[allow(unused)]
impl UpdateName {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUpdateName {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUpdateName {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUpdateName {
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
pub extern "C" fn UpdateName_get_a(this_ptr: &UpdateName) -> u64 {
	let mut inner_val = &mut UpdateName::get_native_mut_ref(this_ptr).0;
	*inner_val
}
#[no_mangle]
pub extern "C" fn UpdateName_set_a(this_ptr: &mut UpdateName, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val;
}
/// Get a string which allows debug introspection of a UpdateName object
pub extern "C" fn UpdateName_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::persist::UpdateName }).into()}
/// Constructs an [`UpdateName`], after verifying that an update sequence ID
/// can be derived from the given `name`.
#[must_use]
#[no_mangle]
pub extern "C" fn UpdateName_new(mut name: crate::c_types::Str) -> crate::c_types::derived::CResult_UpdateNameIOErrorZ {
	let mut ret = lightning::util::persist::UpdateName::new(name.into_string());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::persist::UpdateName { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_bitcoin(e) }).into() };
	local_ret
}

/// Convert this update name to a string slice.
///
/// This method is particularly useful when you need to use the update name
/// as part of a key in a key-value store or when logging.
///
/// # Examples
///
/// ```
/// use lightning::util::persist::UpdateName;
///
/// let update_name = UpdateName::from(42);
/// assert_eq!(update_name.as_str(), \"42\");
/// ```
#[must_use]
#[no_mangle]
pub extern "C" fn UpdateName_as_str(this_arg: &crate::lightning::util::persist::UpdateName) -> crate::c_types::Str {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_str();
	ret.into()
}

#[no_mangle]
/// Build a UpdateName from a u64
pub extern "C" fn UpdateName_from_u64(f: u64) -> crate::lightning::util::persist::UpdateName {
	let from_obj = f;
	crate::lightning::util::persist::UpdateName { inner: ObjOps::heap_alloc((lightning::util::persist::UpdateName::from(from_obj))), is_owned: true }
}
