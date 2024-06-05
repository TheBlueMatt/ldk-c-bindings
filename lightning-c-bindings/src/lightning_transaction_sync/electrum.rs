// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Chain sync using the electrum protocol

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_transaction_sync::electrum::ElectrumSyncClient as nativeElectrumSyncClientImport;
pub(crate) type nativeElectrumSyncClient = nativeElectrumSyncClientImport<crate::lightning::util::logger::Logger, >;

/// Synchronizes LDK with a given Electrum server.
///
/// Needs to be registered with a [`ChainMonitor`] via the [`Filter`] interface to be informed of
/// transactions and outputs to monitor for on-chain confirmation, unconfirmation, and
/// reconfirmation.
///
/// Note that registration via [`Filter`] needs to happen before any calls to
/// [`Watch::watch_channel`] to ensure we get notified of the items to monitor.
///
/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
/// [`Watch::watch_channel`]: lightning::chain::Watch::watch_channel
/// [`Filter`]: lightning::chain::Filter
#[must_use]
#[repr(C)]
pub struct ElectrumSyncClient {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeElectrumSyncClient,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ElectrumSyncClient {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeElectrumSyncClient>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ElectrumSyncClient, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ElectrumSyncClient_free(this_obj: ElectrumSyncClient) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ElectrumSyncClient_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeElectrumSyncClient) };
}
#[allow(unused)]
impl ElectrumSyncClient {
	pub(crate) fn get_native_ref(&self) -> &'static nativeElectrumSyncClient {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeElectrumSyncClient {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeElectrumSyncClient {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Returns a new [`ElectrumSyncClient`] object.
#[must_use]
#[no_mangle]
pub extern "C" fn ElectrumSyncClient_new(mut server_url: crate::c_types::Str, mut logger: crate::lightning::util::logger::Logger) -> crate::c_types::derived::CResult_ElectrumSyncClientTxSyncErrorZ {
	let mut ret = lightning_transaction_sync::electrum::ElectrumSyncClient::new(server_url.into_string(), logger);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_transaction_sync::electrum::ElectrumSyncClient { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_transaction_sync::error::TxSyncError::native_into(e) }).into() };
	local_ret
}

/// Synchronizes the given `confirmables` via their [`Confirm`] interface implementations. This
/// method should be called regularly to keep LDK up-to-date with current chain data.
///
/// For example, instances of [`ChannelManager`] and [`ChainMonitor`] can be informed about the
/// newest on-chain activity related to the items previously registered via the [`Filter`]
/// interface.
///
/// [`Confirm`]: lightning::chain::Confirm
/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
/// [`Filter`]: lightning::chain::Filter
#[must_use]
#[no_mangle]
pub extern "C" fn ElectrumSyncClient_sync(this_arg: &crate::lightning_transaction_sync::electrum::ElectrumSyncClient, mut confirmables: crate::c_types::derived::CVec_ConfirmZ) -> crate::c_types::derived::CResult_NoneTxSyncErrorZ {
	let mut local_confirmables = Vec::new(); for mut item in confirmables.into_rust().drain(..) { local_confirmables.push( { item }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sync(local_confirmables);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_transaction_sync::error::TxSyncError::native_into(e) }).into() };
	local_ret
}

impl From<nativeElectrumSyncClient> for crate::lightning::chain::Filter {
	fn from(obj: nativeElectrumSyncClient) -> Self {
		let rust_obj = crate::lightning_transaction_sync::electrum::ElectrumSyncClient { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ElectrumSyncClient_as_Filter(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(ElectrumSyncClient_free_void);
		ret
	}
}
/// Constructs a new Filter which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Filter must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ElectrumSyncClient_as_Filter(this_arg: &ElectrumSyncClient) -> crate::lightning::chain::Filter {
	crate::lightning::chain::Filter {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		register_tx: ElectrumSyncClient_Filter_register_tx,
		register_output: ElectrumSyncClient_Filter_register_output,
	}
}

extern "C" fn ElectrumSyncClient_Filter_register_tx(this_arg: *const c_void, txid: *const [u8; 32], mut script_pubkey: crate::c_types::u8slice) {
	<nativeElectrumSyncClient as lightning::chain::Filter>::register_tx(unsafe { &mut *(this_arg as *mut nativeElectrumSyncClient) }, &::bitcoin::hash_types::Txid::from_slice(&unsafe { &*txid }[..]).unwrap(), ::bitcoin::blockdata::script::Script::from_bytes(script_pubkey.to_slice()))
}
extern "C" fn ElectrumSyncClient_Filter_register_output(this_arg: *const c_void, mut output: crate::lightning::chain::WatchedOutput) {
	<nativeElectrumSyncClient as lightning::chain::Filter>::register_output(unsafe { &mut *(this_arg as *mut nativeElectrumSyncClient) }, *unsafe { Box::from_raw(output.take_inner()) })
}

