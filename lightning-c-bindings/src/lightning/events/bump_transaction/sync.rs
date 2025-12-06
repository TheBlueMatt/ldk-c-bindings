// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This module provides synchronous wrappers around [`BumpTransactionEventHandler`] and related types.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An alternative to [`CoinSelectionSourceSync`] that can be implemented and used along
/// [`WalletSync`] to provide a default implementation to [`CoinSelectionSourceSync`].
///
/// For an asynchronous version of this trait, see [`WalletSource`].
#[repr(C)]
pub struct WalletSourceSync {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns all UTXOs, with at least 1 confirmation each, that are available to spend.
	pub list_confirmed_utxos: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CResult_CVec_UtxoZNoneZ,
	/// Returns a script to use for change above dust resulting from a successful coin selection
	/// attempt.
	pub get_change_script: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CResult_CVec_u8ZNoneZ,
	/// Signs and provides the full [`TxIn::script_sig`] and [`TxIn::witness`] for all inputs within
	/// the transaction known to the wallet (i.e., any provided via
	/// [`WalletSource::list_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
	///
	/// [`TxIn::script_sig`]: bitcoin::TxIn::script_sig
	/// [`TxIn::witness`]: bitcoin::TxIn::witness
	pub sign_psbt: extern "C" fn (this_arg: *const c_void, psbt: crate::c_types::derived::CVec_u8Z) -> crate::c_types::derived::CResult_TransactionNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for WalletSourceSync {}
unsafe impl Sync for WalletSourceSync {}
#[allow(unused)]
pub(crate) fn WalletSourceSync_clone_fields(orig: &WalletSourceSync) -> WalletSourceSync {
	WalletSourceSync {
		this_arg: orig.this_arg,
		list_confirmed_utxos: Clone::clone(&orig.list_confirmed_utxos),
		get_change_script: Clone::clone(&orig.get_change_script),
		sign_psbt: Clone::clone(&orig.sign_psbt),
		free: Clone::clone(&orig.free),
	}
}

use lightning::events::bump_transaction::sync::WalletSourceSync as rustWalletSourceSync;
impl rustWalletSourceSync for WalletSourceSync {
	fn list_confirmed_utxos(&self) -> Result<Vec<lightning::events::bump_transaction::Utxo>, ()> {
		let mut ret = (self.list_confirmed_utxos)(self.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn get_change_script(&self) -> Result<bitcoin::ScriptBuf, ()> {
		let mut ret = (self.get_change_script)(self.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { ::bitcoin::script::ScriptBuf::from((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust()) }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_psbt(&self, mut psbt: bitcoin::Psbt) -> Result<bitcoin::Transaction, ()> {
		let mut ret = (self.sign_psbt)(self.this_arg, psbt.serialize().into());
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_bitcoin() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

pub struct WalletSourceSyncRef(WalletSourceSync);
impl rustWalletSourceSync for WalletSourceSyncRef {
	fn list_confirmed_utxos(&self) -> Result<Vec<lightning::events::bump_transaction::Utxo>, ()> {
		let mut ret = (self.0.list_confirmed_utxos)(self.0.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn get_change_script(&self) -> Result<bitcoin::ScriptBuf, ()> {
		let mut ret = (self.0.get_change_script)(self.0.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { ::bitcoin::script::ScriptBuf::from((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust()) }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_psbt(&self, mut psbt: bitcoin::Psbt) -> Result<bitcoin::Transaction, ()> {
		let mut ret = (self.0.sign_psbt)(self.0.this_arg, psbt.serialize().into());
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_bitcoin() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for WalletSourceSync {
	type Target = WalletSourceSyncRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const WalletSourceSyncRef) }
	}
}
impl core::ops::DerefMut for WalletSourceSync {
	fn deref_mut(&mut self) -> &mut WalletSourceSyncRef {
		unsafe { &mut *(self as *mut _ as *mut WalletSourceSyncRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn WalletSourceSync_free(this_ptr: WalletSourceSync) { }
impl Drop for WalletSourceSync {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::events::bump_transaction::sync::WalletSync as nativeWalletSyncImport;
pub(crate) type nativeWalletSync = nativeWalletSyncImport<crate::lightning::events::bump_transaction::sync::WalletSourceSync, crate::lightning::util::logger::Logger, >;

/// A wrapper over [`WalletSourceSync`] that implements [`CoinSelectionSourceSync`] by preferring
/// UTXOs that would avoid conflicting double spends. If not enough UTXOs are available to do so,
/// conflicting double spends may happen.
///
/// For an asynchronous version of this wrapper, see [`Wallet`].
#[must_use]
#[repr(C)]
pub struct WalletSync {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeWalletSync,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for WalletSync {
	type Target = nativeWalletSync;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for WalletSync { }
unsafe impl core::marker::Sync for WalletSync { }
impl Drop for WalletSync {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeWalletSync>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the WalletSync, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn WalletSync_free(this_obj: WalletSync) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn WalletSync_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeWalletSync) };
}
#[allow(unused)]
impl WalletSync {
	pub(crate) fn get_native_ref(&self) -> &'static nativeWalletSync {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeWalletSync {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeWalletSync {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new [`WalletSync`] instance.
#[must_use]
#[no_mangle]
pub extern "C" fn WalletSync_new(mut source: crate::lightning::events::bump_transaction::sync::WalletSourceSync, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::events::bump_transaction::sync::WalletSync {
	let mut ret = lightning::events::bump_transaction::sync::WalletSync::new(source, logger);
	crate::lightning::events::bump_transaction::sync::WalletSync { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeWalletSync> for crate::lightning::events::bump_transaction::sync::CoinSelectionSourceSync {
	fn from(obj: nativeWalletSync) -> Self {
		let rust_obj = crate::lightning::events::bump_transaction::sync::WalletSync { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = WalletSync_as_CoinSelectionSourceSync(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(WalletSync_free_void);
		ret
	}
}
/// Constructs a new CoinSelectionSourceSync which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned CoinSelectionSourceSync must be freed before this_arg is
#[no_mangle]
pub extern "C" fn WalletSync_as_CoinSelectionSourceSync(this_arg: &WalletSync) -> crate::lightning::events::bump_transaction::sync::CoinSelectionSourceSync {
	crate::lightning::events::bump_transaction::sync::CoinSelectionSourceSync {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		select_confirmed_utxos: WalletSync_CoinSelectionSourceSync_select_confirmed_utxos,
		sign_psbt: WalletSync_CoinSelectionSourceSync_sign_psbt,
	}
}

#[must_use]
extern "C" fn WalletSync_CoinSelectionSourceSync_select_confirmed_utxos(this_arg: *const c_void, mut claim_id: crate::c_types::ThirtyTwoBytes, mut must_spend: crate::c_types::derived::CVec_InputZ, mut must_pay_to: crate::c_types::derived::CVec_TxOutZ, mut target_feerate_sat_per_1000_weight: u32, mut max_tx_weight: u64) -> crate::c_types::derived::CResult_CoinSelectionNoneZ {
	let mut local_must_spend = Vec::new(); for mut item in must_spend.into_rust().drain(..) { local_must_spend.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_must_pay_to = Vec::new(); for mut item in must_pay_to.into_rust().drain(..) { local_must_pay_to.push( { item.into_rust() }); };
	let mut ret = <nativeWalletSync as lightning::events::bump_transaction::sync::CoinSelectionSourceSync>::select_confirmed_utxos(unsafe { &mut *(this_arg as *mut nativeWalletSync) }, ::lightning::chain::ClaimId(claim_id.data), local_must_spend, &local_must_pay_to[..], target_feerate_sat_per_1000_weight, max_tx_weight);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::events::bump_transaction::CoinSelection { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn WalletSync_CoinSelectionSourceSync_sign_psbt(this_arg: *const c_void, mut psbt: crate::c_types::derived::CVec_u8Z) -> crate::c_types::derived::CResult_TransactionNoneZ {
	let mut ret = <nativeWalletSync as lightning::events::bump_transaction::sync::CoinSelectionSourceSync>::sign_psbt(unsafe { &mut *(this_arg as *mut nativeWalletSync) }, ::bitcoin::Psbt::deserialize(psbt.as_slice()).expect("Invalid PSBT format"));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Transaction::from_bitcoin(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// An abstraction over a bitcoin wallet that can perform coin selection over a set of UTXOs and can
/// sign for them. The coin selection method aims to mimic Bitcoin Core's `fundrawtransaction` RPC,
/// which most wallets should be able to satisfy. Otherwise, consider implementing
/// [`WalletSourceSync`], which can provide a default implementation of this trait when used with
/// [`WalletSync`].
///
/// For an asynchronous version of this trait, see [`CoinSelectionSource`].
#[repr(C)]
pub struct CoinSelectionSourceSync {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Performs coin selection of a set of UTXOs, with at least 1 confirmation each, that are
	/// available to spend. Implementations are free to pick their coin selection algorithm of
	/// choice, as long as the following requirements are met:
	///
	/// 1. `must_spend` contains a set of [`Input`]s that must be included in the transaction
	///    throughout coin selection, but must not be returned as part of the result.
	/// 2. `must_pay_to` contains a set of [`TxOut`]s that must be included in the transaction
	///    throughout coin selection. In some cases, like when funding an anchor transaction, this
	///    set is empty. Implementations should ensure they handle this correctly on their end,
	///    e.g., Bitcoin Core's `fundrawtransaction` RPC requires at least one output to be
	///    provided, in which case a zero-value empty OP_RETURN output can be used instead.
	/// 3. Enough inputs must be selected/contributed for the resulting transaction (including the
	///    inputs and outputs noted above) to meet `target_feerate_sat_per_1000_weight`.
	/// 4. The final transaction must have a weight smaller than `max_tx_weight`; if this
	///    constraint can't be met, return an `Err`. In the case of counterparty-signed HTLC
	///    transactions, we will remove a chunk of HTLCs and try your algorithm again. As for
	///    anchor transactions, we will try your coin selection again with the same input-output
	///    set when you call [`ChannelMonitor::rebroadcast_pending_claims`], as anchor transactions
	///    cannot be downsized.
	///
	/// Implementations must take note that [`Input::satisfaction_weight`] only tracks the weight of
	/// the input's `script_sig` and `witness`. Some wallets, like Bitcoin Core's, may require
	/// providing the full input weight. Failing to do so may lead to underestimating fee bumps and
	/// delaying block inclusion.
	///
	/// The `claim_id` must map to the set of external UTXOs assigned to the claim, such that they
	/// can be re-used within new fee-bumped iterations of the original claiming transaction,
	/// ensuring that claims don't double spend each other. If a specific `claim_id` has never had a
	/// transaction associated with it, and all of the available UTXOs have already been assigned to
	/// other claims, implementations must be willing to double spend their UTXOs. The choice of
	/// which UTXOs to double spend is left to the implementation, but it must strive to keep the
	/// set of other claims being double spent to a minimum.
	///
	/// [`ChannelMonitor::rebroadcast_pending_claims`]: crate::chain::channelmonitor::ChannelMonitor::rebroadcast_pending_claims
	pub select_confirmed_utxos: extern "C" fn (this_arg: *const c_void, claim_id: crate::c_types::ThirtyTwoBytes, must_spend: crate::c_types::derived::CVec_InputZ, must_pay_to: crate::c_types::derived::CVec_TxOutZ, target_feerate_sat_per_1000_weight: u32, max_tx_weight: u64) -> crate::c_types::derived::CResult_CoinSelectionNoneZ,
	/// Signs and provides the full witness for all inputs within the transaction known to the
	/// trait (i.e., any provided via [`CoinSelectionSourceSync::select_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
	pub sign_psbt: extern "C" fn (this_arg: *const c_void, psbt: crate::c_types::derived::CVec_u8Z) -> crate::c_types::derived::CResult_TransactionNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CoinSelectionSourceSync {}
unsafe impl Sync for CoinSelectionSourceSync {}
#[allow(unused)]
pub(crate) fn CoinSelectionSourceSync_clone_fields(orig: &CoinSelectionSourceSync) -> CoinSelectionSourceSync {
	CoinSelectionSourceSync {
		this_arg: orig.this_arg,
		select_confirmed_utxos: Clone::clone(&orig.select_confirmed_utxos),
		sign_psbt: Clone::clone(&orig.sign_psbt),
		free: Clone::clone(&orig.free),
	}
}

use lightning::events::bump_transaction::sync::CoinSelectionSourceSync as rustCoinSelectionSourceSync;
impl rustCoinSelectionSourceSync for CoinSelectionSourceSync {
	fn select_confirmed_utxos(&self, mut claim_id: lightning::chain::ClaimId, mut must_spend: Vec<lightning::events::bump_transaction::Input>, mut must_pay_to: &[bitcoin::TxOut], mut target_feerate_sat_per_1000_weight: u32, mut max_tx_weight: u64) -> Result<lightning::events::bump_transaction::CoinSelection, ()> {
		let mut local_must_spend = Vec::new(); for mut item in must_spend.drain(..) { local_must_spend.push( { crate::lightning::events::bump_transaction::Input { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
		let mut local_must_pay_to_clone = Vec::new(); local_must_pay_to_clone.extend_from_slice(must_pay_to); let mut must_pay_to = local_must_pay_to_clone; let mut local_must_pay_to = Vec::new(); for mut item in must_pay_to.drain(..) { local_must_pay_to.push( { crate::c_types::TxOut::from_rust(&item) }); };
		let mut ret = (self.select_confirmed_utxos)(self.this_arg, crate::c_types::ThirtyTwoBytes { data: claim_id.0 }, local_must_spend.into(), local_must_pay_to.into(), target_feerate_sat_per_1000_weight, max_tx_weight);
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_psbt(&self, mut psbt: bitcoin::Psbt) -> Result<bitcoin::Transaction, ()> {
		let mut ret = (self.sign_psbt)(self.this_arg, psbt.serialize().into());
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_bitcoin() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

pub struct CoinSelectionSourceSyncRef(CoinSelectionSourceSync);
impl rustCoinSelectionSourceSync for CoinSelectionSourceSyncRef {
	fn select_confirmed_utxos(&self, mut claim_id: lightning::chain::ClaimId, mut must_spend: Vec<lightning::events::bump_transaction::Input>, mut must_pay_to: &[bitcoin::TxOut], mut target_feerate_sat_per_1000_weight: u32, mut max_tx_weight: u64) -> Result<lightning::events::bump_transaction::CoinSelection, ()> {
		let mut local_must_spend = Vec::new(); for mut item in must_spend.drain(..) { local_must_spend.push( { crate::lightning::events::bump_transaction::Input { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
		let mut local_must_pay_to_clone = Vec::new(); local_must_pay_to_clone.extend_from_slice(must_pay_to); let mut must_pay_to = local_must_pay_to_clone; let mut local_must_pay_to = Vec::new(); for mut item in must_pay_to.drain(..) { local_must_pay_to.push( { crate::c_types::TxOut::from_rust(&item) }); };
		let mut ret = (self.0.select_confirmed_utxos)(self.0.this_arg, crate::c_types::ThirtyTwoBytes { data: claim_id.0 }, local_must_spend.into(), local_must_pay_to.into(), target_feerate_sat_per_1000_weight, max_tx_weight);
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_psbt(&self, mut psbt: bitcoin::Psbt) -> Result<bitcoin::Transaction, ()> {
		let mut ret = (self.0.sign_psbt)(self.0.this_arg, psbt.serialize().into());
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_bitcoin() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for CoinSelectionSourceSync {
	type Target = CoinSelectionSourceSyncRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const CoinSelectionSourceSyncRef) }
	}
}
impl core::ops::DerefMut for CoinSelectionSourceSync {
	fn deref_mut(&mut self) -> &mut CoinSelectionSourceSyncRef {
		unsafe { &mut *(self as *mut _ as *mut CoinSelectionSourceSyncRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn CoinSelectionSourceSync_free(this_ptr: CoinSelectionSourceSync) { }
impl Drop for CoinSelectionSourceSync {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::events::bump_transaction::sync::BumpTransactionEventHandlerSync as nativeBumpTransactionEventHandlerSyncImport;
pub(crate) type nativeBumpTransactionEventHandlerSync = nativeBumpTransactionEventHandlerSyncImport<crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::events::bump_transaction::sync::CoinSelectionSourceSync, crate::lightning::sign::SignerProvider, crate::lightning::util::logger::Logger, >;

/// A handler for [`Event::BumpTransaction`] events that sources confirmed UTXOs from a
/// [`CoinSelectionSourceSync`] to fee bump transactions via Child-Pays-For-Parent (CPFP) or
/// Replace-By-Fee (RBF).
///
/// For an asynchronous version of this handler, see [`BumpTransactionEventHandler`].
///
/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
#[must_use]
#[repr(C)]
pub struct BumpTransactionEventHandlerSync {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBumpTransactionEventHandlerSync,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for BumpTransactionEventHandlerSync {
	type Target = nativeBumpTransactionEventHandlerSync;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for BumpTransactionEventHandlerSync { }
unsafe impl core::marker::Sync for BumpTransactionEventHandlerSync { }
impl Drop for BumpTransactionEventHandlerSync {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBumpTransactionEventHandlerSync>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BumpTransactionEventHandlerSync, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BumpTransactionEventHandlerSync_free(this_obj: BumpTransactionEventHandlerSync) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BumpTransactionEventHandlerSync_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBumpTransactionEventHandlerSync) };
}
#[allow(unused)]
impl BumpTransactionEventHandlerSync {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBumpTransactionEventHandlerSync {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBumpTransactionEventHandlerSync {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBumpTransactionEventHandlerSync {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new instance of [`BumpTransactionEventHandlerSync`].
#[must_use]
#[no_mangle]
pub extern "C" fn BumpTransactionEventHandlerSync_new(mut broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut utxo_source: crate::lightning::events::bump_transaction::sync::CoinSelectionSourceSync, mut signer_provider: crate::lightning::sign::SignerProvider, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::events::bump_transaction::sync::BumpTransactionEventHandlerSync {
	let mut ret = lightning::events::bump_transaction::sync::BumpTransactionEventHandlerSync::new(broadcaster, utxo_source, signer_provider, logger);
	crate::lightning::events::bump_transaction::sync::BumpTransactionEventHandlerSync { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Handles all variants of [`BumpTransactionEvent`].
#[no_mangle]
pub extern "C" fn BumpTransactionEventHandlerSync_handle_event(this_arg: &crate::lightning::events::bump_transaction::sync::BumpTransactionEventHandlerSync, event: &crate::lightning::events::bump_transaction::BumpTransactionEvent) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_event(&event.to_native())
}

