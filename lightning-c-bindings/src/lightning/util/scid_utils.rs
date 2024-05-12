// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for creating and parsing short channel ids.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Maximum block height that can be used in a `short_channel_id`. This
/// value is based on the 3-bytes available for block height.

#[no_mangle]
pub static MAX_SCID_BLOCK: u64 = lightning::util::scid_utils::MAX_SCID_BLOCK;
/// Maximum transaction index that can be used in a `short_channel_id`.
/// This value is based on the 3-bytes available for tx index.

#[no_mangle]
pub static MAX_SCID_TX_INDEX: u64 = lightning::util::scid_utils::MAX_SCID_TX_INDEX;
/// Maximum vout index that can be used in a `short_channel_id`. This
/// value is based on the 2-bytes available for the vout index.

#[no_mangle]
pub static MAX_SCID_VOUT_INDEX: u64 = lightning::util::scid_utils::MAX_SCID_VOUT_INDEX;
/// A `short_channel_id` construction error
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ShortChannelIdError {
	/// Block height too high
	BlockOverflow,
	/// Tx index too high
	TxIndexOverflow,
	/// Vout index too high
	VoutIndexOverflow,
}
use lightning::util::scid_utils::ShortChannelIdError as ShortChannelIdErrorImport;
pub(crate) type nativeShortChannelIdError = ShortChannelIdErrorImport;

impl ShortChannelIdError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeShortChannelIdError {
		match self {
			ShortChannelIdError::BlockOverflow => nativeShortChannelIdError::BlockOverflow,
			ShortChannelIdError::TxIndexOverflow => nativeShortChannelIdError::TxIndexOverflow,
			ShortChannelIdError::VoutIndexOverflow => nativeShortChannelIdError::VoutIndexOverflow,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeShortChannelIdError {
		match self {
			ShortChannelIdError::BlockOverflow => nativeShortChannelIdError::BlockOverflow,
			ShortChannelIdError::TxIndexOverflow => nativeShortChannelIdError::TxIndexOverflow,
			ShortChannelIdError::VoutIndexOverflow => nativeShortChannelIdError::VoutIndexOverflow,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &ShortChannelIdErrorImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeShortChannelIdError) };
		match native {
			nativeShortChannelIdError::BlockOverflow => ShortChannelIdError::BlockOverflow,
			nativeShortChannelIdError::TxIndexOverflow => ShortChannelIdError::TxIndexOverflow,
			nativeShortChannelIdError::VoutIndexOverflow => ShortChannelIdError::VoutIndexOverflow,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeShortChannelIdError) -> Self {
		match native {
			nativeShortChannelIdError::BlockOverflow => ShortChannelIdError::BlockOverflow,
			nativeShortChannelIdError::TxIndexOverflow => ShortChannelIdError::TxIndexOverflow,
			nativeShortChannelIdError::VoutIndexOverflow => ShortChannelIdError::VoutIndexOverflow,
		}
	}
}
/// Creates a copy of the ShortChannelIdError
#[no_mangle]
pub extern "C" fn ShortChannelIdError_clone(orig: &ShortChannelIdError) -> ShortChannelIdError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ShortChannelIdError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const ShortChannelIdError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ShortChannelIdError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut ShortChannelIdError) };
}
#[no_mangle]
/// Utility method to constructs a new BlockOverflow-variant ShortChannelIdError
pub extern "C" fn ShortChannelIdError_block_overflow() -> ShortChannelIdError {
	ShortChannelIdError::BlockOverflow}
#[no_mangle]
/// Utility method to constructs a new TxIndexOverflow-variant ShortChannelIdError
pub extern "C" fn ShortChannelIdError_tx_index_overflow() -> ShortChannelIdError {
	ShortChannelIdError::TxIndexOverflow}
#[no_mangle]
/// Utility method to constructs a new VoutIndexOverflow-variant ShortChannelIdError
pub extern "C" fn ShortChannelIdError_vout_index_overflow() -> ShortChannelIdError {
	ShortChannelIdError::VoutIndexOverflow}
/// Get a string which allows debug introspection of a ShortChannelIdError object
pub extern "C" fn ShortChannelIdError_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::scid_utils::ShortChannelIdError }).into()}
/// Checks if two ShortChannelIdErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ShortChannelIdError_eq(a: &ShortChannelIdError, b: &ShortChannelIdError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Extracts the block height (most significant 3-bytes) from the `short_channel_id`
#[no_mangle]
pub extern "C" fn block_from_scid(mut short_channel_id: u64) -> u32 {
	let mut ret = lightning::util::scid_utils::block_from_scid(short_channel_id);
	ret
}

/// Extracts the tx index (bytes [2..4]) from the `short_channel_id`
#[no_mangle]
pub extern "C" fn tx_index_from_scid(mut short_channel_id: u64) -> u32 {
	let mut ret = lightning::util::scid_utils::tx_index_from_scid(short_channel_id);
	ret
}

/// Extracts the vout (bytes [0..2]) from the `short_channel_id`
#[no_mangle]
pub extern "C" fn vout_from_scid(mut short_channel_id: u64) -> u16 {
	let mut ret = lightning::util::scid_utils::vout_from_scid(short_channel_id);
	ret
}

/// Constructs a `short_channel_id` using the components pieces. Results in an error
/// if the block height, tx index, or vout index overflow the maximum sizes.
#[no_mangle]
pub extern "C" fn scid_from_parts(mut block: u64, mut tx_index: u64, mut vout_index: u64) -> crate::c_types::derived::CResult_u64ShortChannelIdErrorZ {
	let mut ret = lightning::util::scid_utils::scid_from_parts(block, tx_index, vout_index);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::scid_utils::ShortChannelIdError::native_into(e) }).into() };
	local_ret
}

mod fake_scid {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
