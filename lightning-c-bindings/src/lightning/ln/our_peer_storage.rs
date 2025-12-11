// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! `DecryptedOurPeerStorage` enables storage of encrypted serialized channel data.
//! It provides encryption of data to maintain data integrity and
//! security during transmission.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::ln::our_peer_storage::DecryptedOurPeerStorage as nativeDecryptedOurPeerStorageImport;
pub(crate) type nativeDecryptedOurPeerStorage = nativeDecryptedOurPeerStorageImport;

/// [`DecryptedOurPeerStorage`] is used to store serialised channel information that allows for the creation of a
/// `peer_storage` backup.
///
/// This structure is designed to serialize channel data for backup and supports encryption
/// using `ChaCha20Poly1305RFC` for transmission.
///
/// # Key Methods
/// - [`DecryptedOurPeerStorage::new`]: Returns [`DecryptedOurPeerStorage`] with the given data.
/// - [`DecryptedOurPeerStorage::encrypt`]: Returns [`EncryptedOurPeerStorage`] created from encrypting the provided data.
/// - [`DecryptedOurPeerStorage::into_vec`]: Returns the data in [`Vec<u8>`] format.
///
/// ## Example
/// ```
/// use lightning::ln::our_peer_storage::DecryptedOurPeerStorage;
/// use lightning::sign::{KeysManager, NodeSigner};
/// let seed = [1u8; 32];
/// let keys_mgr = KeysManager::new(&seed, 42, 42, true);
/// let key = keys_mgr.get_peer_storage_key();
/// let decrypted_ops = DecryptedOurPeerStorage::new(vec![1, 2, 3]);
/// let our_peer_storage = decrypted_ops.encrypt(&key, &[0u8; 32]);
/// let decrypted_data = our_peer_storage.decrypt(&key).unwrap();
/// assert_eq!(decrypted_data.into_vec(), vec![1, 2, 3]);
/// ```
#[must_use]
#[repr(C)]
pub struct DecryptedOurPeerStorage {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDecryptedOurPeerStorage,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for DecryptedOurPeerStorage {
	type Target = nativeDecryptedOurPeerStorage;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for DecryptedOurPeerStorage { }
unsafe impl core::marker::Sync for DecryptedOurPeerStorage { }
impl Drop for DecryptedOurPeerStorage {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDecryptedOurPeerStorage>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DecryptedOurPeerStorage, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DecryptedOurPeerStorage_free(this_obj: DecryptedOurPeerStorage) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DecryptedOurPeerStorage_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDecryptedOurPeerStorage) };
}
#[allow(unused)]
impl DecryptedOurPeerStorage {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDecryptedOurPeerStorage {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDecryptedOurPeerStorage {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDecryptedOurPeerStorage {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Returns [`DecryptedOurPeerStorage`] with the given data.
#[must_use]
#[no_mangle]
pub extern "C" fn DecryptedOurPeerStorage_new(mut data: crate::c_types::derived::CVec_u8Z) -> crate::lightning::ln::our_peer_storage::DecryptedOurPeerStorage {
	let mut local_data = Vec::new(); for mut item in data.into_rust().drain(..) { local_data.push( { item }); };
	let mut ret = lightning::ln::our_peer_storage::DecryptedOurPeerStorage::new(local_data);
	crate::lightning::ln::our_peer_storage::DecryptedOurPeerStorage { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns data stored in [`Vec<u8>`] format.
#[must_use]
#[no_mangle]
pub extern "C" fn DecryptedOurPeerStorage_into_vec(mut this_arg: crate::lightning::ln::our_peer_storage::DecryptedOurPeerStorage) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_vec();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { item }); };
	local_ret.into()
}

/// Encrypts the data inside [`DecryptedOurPeerStorage`] using [`PeerStorageKey`] and `random_bytes`
/// and returns [`EncryptedOurPeerStorage`].
#[must_use]
#[no_mangle]
pub extern "C" fn DecryptedOurPeerStorage_encrypt(mut this_arg: crate::lightning::ln::our_peer_storage::DecryptedOurPeerStorage, key: &crate::lightning::sign::PeerStorageKey, random_bytes: *const [u8; 32]) -> crate::lightning::ln::our_peer_storage::EncryptedOurPeerStorage {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).encrypt(key.get_native_ref(), unsafe { &*random_bytes});
	crate::lightning::ln::our_peer_storage::EncryptedOurPeerStorage { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::ln::our_peer_storage::EncryptedOurPeerStorage as nativeEncryptedOurPeerStorageImport;
pub(crate) type nativeEncryptedOurPeerStorage = nativeEncryptedOurPeerStorageImport;

/// [`EncryptedOurPeerStorage`] represents encrypted state of the corresponding [`DecryptedOurPeerStorage`].
///
/// # Key Methods
/// - [`EncryptedOurPeerStorage::new`]: Returns [`EncryptedOurPeerStorage`] with the given encrypted cipher.
/// - [`EncryptedOurPeerStorage::decrypt`]: Returns [`DecryptedOurPeerStorage`] created from decrypting the cipher.
/// - [`EncryptedOurPeerStorage::into_vec`]: Returns the cipher in [`Vec<u8>`] format.
#[must_use]
#[repr(C)]
pub struct EncryptedOurPeerStorage {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeEncryptedOurPeerStorage,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for EncryptedOurPeerStorage {
	type Target = nativeEncryptedOurPeerStorage;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for EncryptedOurPeerStorage { }
unsafe impl core::marker::Sync for EncryptedOurPeerStorage { }
impl Drop for EncryptedOurPeerStorage {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeEncryptedOurPeerStorage>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the EncryptedOurPeerStorage, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn EncryptedOurPeerStorage_free(this_obj: EncryptedOurPeerStorage) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn EncryptedOurPeerStorage_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeEncryptedOurPeerStorage) };
}
#[allow(unused)]
impl EncryptedOurPeerStorage {
	pub(crate) fn get_native_ref(&self) -> &'static nativeEncryptedOurPeerStorage {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeEncryptedOurPeerStorage {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeEncryptedOurPeerStorage {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Returns [`EncryptedOurPeerStorage`] if cipher is of appropriate length, else returns error.
#[must_use]
#[no_mangle]
pub extern "C" fn EncryptedOurPeerStorage_new(mut cipher: crate::c_types::derived::CVec_u8Z) -> crate::c_types::derived::CResult_EncryptedOurPeerStorageNoneZ {
	let mut local_cipher = Vec::new(); for mut item in cipher.into_rust().drain(..) { local_cipher.push( { item }); };
	let mut ret = lightning::ln::our_peer_storage::EncryptedOurPeerStorage::new(local_cipher);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::our_peer_storage::EncryptedOurPeerStorage { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Returns cipher in the format [`Vec<u8>`].
#[must_use]
#[no_mangle]
pub extern "C" fn EncryptedOurPeerStorage_into_vec(mut this_arg: crate::lightning::ln::our_peer_storage::EncryptedOurPeerStorage) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_vec();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { item }); };
	local_ret.into()
}

/// Returns [`DecryptedOurPeerStorage`] if it successfully decrypts the ciphertext with the `key`,
/// else returns error.
#[must_use]
#[no_mangle]
pub extern "C" fn EncryptedOurPeerStorage_decrypt(mut this_arg: crate::lightning::ln::our_peer_storage::EncryptedOurPeerStorage, key: &crate::lightning::sign::PeerStorageKey) -> crate::c_types::derived::CResult_DecryptedOurPeerStorageNoneZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).decrypt(key.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::our_peer_storage::DecryptedOurPeerStorage { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

