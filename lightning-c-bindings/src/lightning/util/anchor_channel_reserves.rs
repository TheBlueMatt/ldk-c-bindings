// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Defines anchor channel reserve requirements.
//!
//! The Lightning protocol advances the state of the channel based on commitment and HTLC
//! transactions, which allow each participant to unilaterally close the channel with the correct
//! state and resolve pending HTLCs on-chain. Originally, these transactions are signed by both
//! counterparties over the entire transaction and therefore contain a fixed fee, which can be
//! updated with the `update_fee` message by the funder. However, these fees can lead to
//! disagreements and can diverge from the prevailing fee rate if a party is disconnected.
//!
//! To address these issues, fees are provided exogenously for anchor output channels.
//! Anchor outputs are negotiated on channel opening to add outputs to each commitment transaction.
//! These outputs can be spent in a child transaction with additional fees to incentivize the
//! mining of the parent transaction, this technique is called Child Pays For Parent (CPFP).
//! Similarly, HTLC transactions will be signed with `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` so
//! additional inputs and outputs can be added to pay for fees.
//!
//! UTXO reserves will therefore be required to supply commitment transactions and HTLC
//! transactions with fees to be confirmed in a timely manner. If HTLCs are not resolved
//! appropriately, it can lead to loss of funds of the in-flight HLTCs as mentioned above. Only
//! partially satisfying UTXO requirements incurs the risk of not being able to resolve a subset of
//! HTLCs.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::util::anchor_channel_reserves::AnchorChannelReserveContext as nativeAnchorChannelReserveContextImport;
pub(crate) type nativeAnchorChannelReserveContext = nativeAnchorChannelReserveContextImport;

/// Parameters defining the context around the anchor channel reserve requirement calculation.
#[must_use]
#[repr(C)]
pub struct AnchorChannelReserveContext {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAnchorChannelReserveContext,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for AnchorChannelReserveContext {
	type Target = nativeAnchorChannelReserveContext;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for AnchorChannelReserveContext { }
unsafe impl core::marker::Sync for AnchorChannelReserveContext { }
impl Drop for AnchorChannelReserveContext {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeAnchorChannelReserveContext>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the AnchorChannelReserveContext, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn AnchorChannelReserveContext_free(this_obj: AnchorChannelReserveContext) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AnchorChannelReserveContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeAnchorChannelReserveContext) };
}
#[allow(unused)]
impl AnchorChannelReserveContext {
	pub(crate) fn get_native_ref(&self) -> &'static nativeAnchorChannelReserveContext {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeAnchorChannelReserveContext {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeAnchorChannelReserveContext {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The expected number of accepted in-flight HTLCs per channel.
///
/// Note that malicious counterparties can saturate the number of accepted in-flight HTLCs up to
/// the maximum prior to forcing a unilateral closure. This estimate can include that case as a
/// weighted average, assuming some percentage of channels are controlled by malicious peers and
/// have the maximum number of accepted in-flight HTLCs.
///
/// See [ChannelHandshakeConfig::our_max_accepted_htlcs] to configure the maximum number of
/// accepted in-flight HTLCs.
///
/// [ChannelHandshakeConfig::our_max_accepted_htlcs]: crate::util::config::ChannelHandshakeConfig::our_max_accepted_htlcs
#[no_mangle]
pub extern "C" fn AnchorChannelReserveContext_get_expected_accepted_htlcs(this_ptr: &AnchorChannelReserveContext) -> u16 {
	let mut inner_val = &mut AnchorChannelReserveContext::get_native_mut_ref(this_ptr).expected_accepted_htlcs;
	*inner_val
}
/// The expected number of accepted in-flight HTLCs per channel.
///
/// Note that malicious counterparties can saturate the number of accepted in-flight HTLCs up to
/// the maximum prior to forcing a unilateral closure. This estimate can include that case as a
/// weighted average, assuming some percentage of channels are controlled by malicious peers and
/// have the maximum number of accepted in-flight HTLCs.
///
/// See [ChannelHandshakeConfig::our_max_accepted_htlcs] to configure the maximum number of
/// accepted in-flight HTLCs.
///
/// [ChannelHandshakeConfig::our_max_accepted_htlcs]: crate::util::config::ChannelHandshakeConfig::our_max_accepted_htlcs
#[no_mangle]
pub extern "C" fn AnchorChannelReserveContext_set_expected_accepted_htlcs(this_ptr: &mut AnchorChannelReserveContext, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.expected_accepted_htlcs = val;
}
/// Whether the wallet handling anchor channel reserves creates Taproot P2TR outputs for any new
/// outputs, or Segwit P2WPKH outputs otherwise.
#[no_mangle]
pub extern "C" fn AnchorChannelReserveContext_get_taproot_wallet(this_ptr: &AnchorChannelReserveContext) -> bool {
	let mut inner_val = &mut AnchorChannelReserveContext::get_native_mut_ref(this_ptr).taproot_wallet;
	*inner_val
}
/// Whether the wallet handling anchor channel reserves creates Taproot P2TR outputs for any new
/// outputs, or Segwit P2WPKH outputs otherwise.
#[no_mangle]
pub extern "C" fn AnchorChannelReserveContext_set_taproot_wallet(this_ptr: &mut AnchorChannelReserveContext, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.taproot_wallet = val;
}
impl Clone for AnchorChannelReserveContext {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeAnchorChannelReserveContext>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AnchorChannelReserveContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeAnchorChannelReserveContext) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the AnchorChannelReserveContext
pub extern "C" fn AnchorChannelReserveContext_clone(orig: &AnchorChannelReserveContext) -> AnchorChannelReserveContext {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a AnchorChannelReserveContext object
pub extern "C" fn AnchorChannelReserveContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::anchor_channel_reserves::AnchorChannelReserveContext }).into()}
/// Checks if two AnchorChannelReserveContexts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn AnchorChannelReserveContext_eq(a: &AnchorChannelReserveContext, b: &AnchorChannelReserveContext) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Creates a "default" AnchorChannelReserveContext. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorChannelReserveContext_default() -> AnchorChannelReserveContext {
	AnchorChannelReserveContext { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
/// Returns the amount that needs to be maintained as a reserve per anchor channel.
///
/// This reserve currently needs to be allocated as a disjoint set of at least 1 UTXO per channel,
/// as claims are not yet aggregated across channels.
///
/// To only require 1 UTXO per channel, it is assumed that, on average, transactions are able to
/// get confirmed within 1 block with [ConfirmationTarget::UrgentOnChainSweep], or that only a
/// portion of channels will go through unilateral closure at the same time, allowing UTXOs to be
/// shared. Otherwise, multiple UTXOs would be needed per channel:
/// - HTLC time-out transactions with different expiries cannot be aggregated. This could result in
/// many individual transactions that need to be confirmed starting from different, but potentially
/// sequential block heights.
/// - If each transaction takes N blocks to confirm, at least N UTXOs per channel are needed to
/// provide the necessary concurrency.
///
/// The returned amount includes the fee to spend a single UTXO of the type indicated by
/// [AnchorChannelReserveContext::taproot_wallet]. Larger sets of UTXOs with more complex witnesses
/// will need to include the corresponding fee required to spend them.
///
/// [ConfirmationTarget::UrgentOnChainSweep]: crate::chain::chaininterface::ConfirmationTarget::UrgentOnChainSweep
#[no_mangle]
pub extern "C" fn get_reserve_per_channel(context: &crate::lightning::util::anchor_channel_reserves::AnchorChannelReserveContext) -> u64 {
	let mut ret = lightning::util::anchor_channel_reserves::get_reserve_per_channel(context.get_native_ref());
	ret.to_sat()
}

/// Calculates the number of anchor channels that can be supported by the reserve provided
/// by `utxos`.
#[no_mangle]
pub extern "C" fn get_supportable_anchor_channels(context: &crate::lightning::util::anchor_channel_reserves::AnchorChannelReserveContext, mut utxos: crate::c_types::derived::CVec_UtxoZ) -> u64 {
	let mut local_utxos = Vec::new(); for mut item in utxos.into_rust().drain(..) { local_utxos.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::util::anchor_channel_reserves::get_supportable_anchor_channels(context.get_native_ref(), &local_utxos[..]);
	ret
}

/// Verifies whether the anchor channel reserve provided by `utxos` is sufficient to support
/// an additional anchor channel.
///
/// This should be verified:
/// - Before opening a new outbound anchor channel with [ChannelManager::create_channel].
/// - Before accepting a new inbound anchor channel while handling [Event::OpenChannelRequest].
///
/// [ChannelManager::create_channel]: crate::ln::channelmanager::ChannelManager::create_channel
/// [Event::OpenChannelRequest]: crate::events::Event::OpenChannelRequest
#[no_mangle]
pub extern "C" fn can_support_additional_anchor_channel(context: &crate::lightning::util::anchor_channel_reserves::AnchorChannelReserveContext, mut utxos: crate::c_types::derived::CVec_UtxoZ, a_channel_manager: &crate::lightning::ln::channelmanager::ChannelManager, chain_monitor: &crate::lightning::chain::chainmonitor::ChainMonitor) -> bool {
	let mut local_utxos = Vec::new(); for mut item in utxos.into_rust().drain(..) { local_utxos.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::util::anchor_channel_reserves::can_support_additional_anchor_channel::<crate::lightning::ln::channelmanager::ChannelManager, crate::lightning::sign::ecdsa::EcdsaChannelSigner, crate::lightning::chain::Filter, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger, crate::lightning::chain::chainmonitor::Persist, crate::lightning::sign::EntropySource, &'static lightning::chain::chainmonitor::ChainMonitor<crate::lightning::sign::ecdsa::EcdsaChannelSigner, crate::lightning::chain::Filter, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger, crate::lightning::chain::chainmonitor::Persist, crate::lightning::sign::EntropySource>, >(context.get_native_ref(), &local_utxos[..], a_channel_manager.as_ref_to(), chain_monitor.get_native_ref());
	ret
}

