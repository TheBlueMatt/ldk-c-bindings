// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Various user-configurable channel limits and settings which ChannelManager
//! applies for you.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::util::config::ChannelHandshakeConfig as nativeChannelHandshakeConfigImport;
pub(crate) type nativeChannelHandshakeConfig = nativeChannelHandshakeConfigImport;

/// Configuration we set when applicable.
///
/// Default::default() provides sane defaults.
#[must_use]
#[repr(C)]
pub struct ChannelHandshakeConfig {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelHandshakeConfig,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelHandshakeConfig {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelHandshakeConfig>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelHandshakeConfig, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_free(this_obj: ChannelHandshakeConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeConfig_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelHandshakeConfig); }
}
#[allow(unused)]
impl ChannelHandshakeConfig {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelHandshakeConfig {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelHandshakeConfig {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelHandshakeConfig {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Confirmations we will wait for before considering the channel locked in.
/// Applied only for inbound channels (see ChannelHandshakeLimits::max_minimum_depth for the
/// equivalent limit applied to outbound channels).
///
/// Default value: 6.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_minimum_depth(this_ptr: &ChannelHandshakeConfig) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().minimum_depth;
	*inner_val
}
/// Confirmations we will wait for before considering the channel locked in.
/// Applied only for inbound channels (see ChannelHandshakeLimits::max_minimum_depth for the
/// equivalent limit applied to outbound channels).
///
/// Default value: 6.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_minimum_depth(this_ptr: &mut ChannelHandshakeConfig, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.minimum_depth = val;
}
/// Set to the number of blocks we require our counterparty to wait to claim their money (ie
/// the number of blocks we have to punish our counterparty if they broadcast a revoked
/// transaction).
///
/// This is one of the main parameters of our security model. We (or one of our watchtowers) MUST
/// be online to check for revoked transactions on-chain at least once every our_to_self_delay
/// blocks (minus some margin to allow us enough time to broadcast and confirm a transaction,
/// possibly with time in between to RBF the spending transaction).
///
/// Meanwhile, asking for a too high delay, we bother peer to freeze funds for nothing in
/// case of an honest unilateral channel close, which implicitly decrease the economic value of
/// our channel.
///
/// Default value: [`BREAKDOWN_TIMEOUT`], we enforce it as a minimum at channel opening so you
/// can tweak config to ask for more security, not less.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_our_to_self_delay(this_ptr: &ChannelHandshakeConfig) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().our_to_self_delay;
	*inner_val
}
/// Set to the number of blocks we require our counterparty to wait to claim their money (ie
/// the number of blocks we have to punish our counterparty if they broadcast a revoked
/// transaction).
///
/// This is one of the main parameters of our security model. We (or one of our watchtowers) MUST
/// be online to check for revoked transactions on-chain at least once every our_to_self_delay
/// blocks (minus some margin to allow us enough time to broadcast and confirm a transaction,
/// possibly with time in between to RBF the spending transaction).
///
/// Meanwhile, asking for a too high delay, we bother peer to freeze funds for nothing in
/// case of an honest unilateral channel close, which implicitly decrease the economic value of
/// our channel.
///
/// Default value: [`BREAKDOWN_TIMEOUT`], we enforce it as a minimum at channel opening so you
/// can tweak config to ask for more security, not less.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_our_to_self_delay(this_ptr: &mut ChannelHandshakeConfig, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.our_to_self_delay = val;
}
/// Set to the smallest value HTLC we will accept to process.
///
/// This value is sent to our counterparty on channel-open and we close the channel any time
/// our counterparty misbehaves by sending us an HTLC with a value smaller than this.
///
/// Default value: 1. If the value is less than 1, it is ignored and set to 1, as is required
/// by the protocol.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_our_htlc_minimum_msat(this_ptr: &ChannelHandshakeConfig) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().our_htlc_minimum_msat;
	*inner_val
}
/// Set to the smallest value HTLC we will accept to process.
///
/// This value is sent to our counterparty on channel-open and we close the channel any time
/// our counterparty misbehaves by sending us an HTLC with a value smaller than this.
///
/// Default value: 1. If the value is less than 1, it is ignored and set to 1, as is required
/// by the protocol.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_our_htlc_minimum_msat(this_ptr: &mut ChannelHandshakeConfig, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.our_htlc_minimum_msat = val;
}
/// Constructs a new ChannelHandshakeConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_new(mut minimum_depth_arg: u32, mut our_to_self_delay_arg: u16, mut our_htlc_minimum_msat_arg: u64) -> ChannelHandshakeConfig {
	ChannelHandshakeConfig { inner: ObjOps::heap_alloc(nativeChannelHandshakeConfig {
		minimum_depth: minimum_depth_arg,
		our_to_self_delay: our_to_self_delay_arg,
		our_htlc_minimum_msat: our_htlc_minimum_msat_arg,
	}), is_owned: true }
}
impl Clone for ChannelHandshakeConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelHandshakeConfig>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelHandshakeConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelHandshakeConfig
pub extern "C" fn ChannelHandshakeConfig_clone(orig: &ChannelHandshakeConfig) -> ChannelHandshakeConfig {
	orig.clone()
}
/// Creates a "default" ChannelHandshakeConfig. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_default() -> ChannelHandshakeConfig {
	ChannelHandshakeConfig { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}

use lightning::util::config::ChannelHandshakeLimits as nativeChannelHandshakeLimitsImport;
pub(crate) type nativeChannelHandshakeLimits = nativeChannelHandshakeLimitsImport;

/// Optional channel limits which are applied during channel creation.
///
/// These limits are only applied to our counterparty's limits, not our own.
///
/// Use 0/<type>::max_value() as appropriate to skip checking.
///
/// Provides sane defaults for most configurations.
///
/// Most additional limits are disabled except those with which specify a default in individual
/// field documentation. Note that this may result in barely-usable channels, but since they
/// are applied mostly only to incoming channels that's not much of a problem.
#[must_use]
#[repr(C)]
pub struct ChannelHandshakeLimits {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelHandshakeLimits,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelHandshakeLimits {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelHandshakeLimits>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelHandshakeLimits, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_free(this_obj: ChannelHandshakeLimits) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeLimits_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelHandshakeLimits); }
}
#[allow(unused)]
impl ChannelHandshakeLimits {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelHandshakeLimits {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelHandshakeLimits {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelHandshakeLimits {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Minimum allowed satoshis when a channel is funded, this is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_funding_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_funding_satoshis;
	*inner_val
}
/// Minimum allowed satoshis when a channel is funded, this is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_funding_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_funding_satoshis = val;
}
/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
/// you to limit the maximum minimum-size they can require.
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_htlc_minimum_msat(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_htlc_minimum_msat;
	*inner_val
}
/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
/// you to limit the maximum minimum-size they can require.
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_htlc_minimum_msat(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_htlc_minimum_msat = val;
}
/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_max_htlc_value_in_flight_msat(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_max_htlc_value_in_flight_msat;
	*inner_val
}
/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_max_htlc_value_in_flight_msat(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_max_htlc_value_in_flight_msat = val;
}
/// The remote node will require we keep a certain amount in direct payment to ourselves at all
/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_channel_reserve_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_channel_reserve_satoshis;
	*inner_val
}
/// The remote node will require we keep a certain amount in direct payment to ourselves at all
/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_channel_reserve_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_channel_reserve_satoshis = val;
}
/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
/// time. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_max_accepted_htlcs(this_ptr: &ChannelHandshakeLimits) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_max_accepted_htlcs;
	*inner_val
}
/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
/// time. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_max_accepted_htlcs(this_ptr: &mut ChannelHandshakeLimits, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_max_accepted_htlcs = val;
}
/// Before a channel is usable the funding transaction will need to be confirmed by at least a
/// certain number of blocks, specified by the node which is not the funder (as the funder can
/// assume they aren't going to double-spend themselves).
/// This config allows you to set a limit on the maximum amount of time to wait.
///
/// Default value: 144, or roughly one day and only applies to outbound channels.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_minimum_depth(this_ptr: &ChannelHandshakeLimits) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_minimum_depth;
	*inner_val
}
/// Before a channel is usable the funding transaction will need to be confirmed by at least a
/// certain number of blocks, specified by the node which is not the funder (as the funder can
/// assume they aren't going to double-spend themselves).
/// This config allows you to set a limit on the maximum amount of time to wait.
///
/// Default value: 144, or roughly one day and only applies to outbound channels.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_minimum_depth(this_ptr: &mut ChannelHandshakeLimits, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_minimum_depth = val;
}
/// Set to force an incoming channel to match our announced channel preference in
/// [`ChannelConfig::announced_channel`].
///
/// For a node which is not online reliably, this should be set to true and
/// [`ChannelConfig::announced_channel`] set to false, ensuring that no announced (aka public)
/// channels will ever be opened.
///
/// Default value: true.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_force_announced_channel_preference(this_ptr: &ChannelHandshakeLimits) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().force_announced_channel_preference;
	*inner_val
}
/// Set to force an incoming channel to match our announced channel preference in
/// [`ChannelConfig::announced_channel`].
///
/// For a node which is not online reliably, this should be set to true and
/// [`ChannelConfig::announced_channel`] set to false, ensuring that no announced (aka public)
/// channels will ever be opened.
///
/// Default value: true.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_force_announced_channel_preference(this_ptr: &mut ChannelHandshakeLimits, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.force_announced_channel_preference = val;
}
/// Set to the amount of time we're willing to wait to claim money back to us.
///
/// Not checking this value would be a security issue, as our peer would be able to set it to
/// max relative lock-time (a year) and we would \"lose\" money as it would be locked for a long time.
///
/// Default value: 2016, which we also enforce as a maximum value so you can tweak config to
/// reduce the loss of having useless locked funds (if your peer accepts)
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_their_to_self_delay(this_ptr: &ChannelHandshakeLimits) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().their_to_self_delay;
	*inner_val
}
/// Set to the amount of time we're willing to wait to claim money back to us.
///
/// Not checking this value would be a security issue, as our peer would be able to set it to
/// max relative lock-time (a year) and we would \"lose\" money as it would be locked for a long time.
///
/// Default value: 2016, which we also enforce as a maximum value so you can tweak config to
/// reduce the loss of having useless locked funds (if your peer accepts)
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_their_to_self_delay(this_ptr: &mut ChannelHandshakeLimits, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.their_to_self_delay = val;
}
/// Constructs a new ChannelHandshakeLimits given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_new(mut min_funding_satoshis_arg: u64, mut max_htlc_minimum_msat_arg: u64, mut min_max_htlc_value_in_flight_msat_arg: u64, mut max_channel_reserve_satoshis_arg: u64, mut min_max_accepted_htlcs_arg: u16, mut max_minimum_depth_arg: u32, mut force_announced_channel_preference_arg: bool, mut their_to_self_delay_arg: u16) -> ChannelHandshakeLimits {
	ChannelHandshakeLimits { inner: ObjOps::heap_alloc(nativeChannelHandshakeLimits {
		min_funding_satoshis: min_funding_satoshis_arg,
		max_htlc_minimum_msat: max_htlc_minimum_msat_arg,
		min_max_htlc_value_in_flight_msat: min_max_htlc_value_in_flight_msat_arg,
		max_channel_reserve_satoshis: max_channel_reserve_satoshis_arg,
		min_max_accepted_htlcs: min_max_accepted_htlcs_arg,
		max_minimum_depth: max_minimum_depth_arg,
		force_announced_channel_preference: force_announced_channel_preference_arg,
		their_to_self_delay: their_to_self_delay_arg,
	}), is_owned: true }
}
impl Clone for ChannelHandshakeLimits {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelHandshakeLimits>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeLimits_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelHandshakeLimits)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelHandshakeLimits
pub extern "C" fn ChannelHandshakeLimits_clone(orig: &ChannelHandshakeLimits) -> ChannelHandshakeLimits {
	orig.clone()
}
/// Creates a "default" ChannelHandshakeLimits. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_default() -> ChannelHandshakeLimits {
	ChannelHandshakeLimits { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}

use lightning::util::config::ChannelConfig as nativeChannelConfigImport;
pub(crate) type nativeChannelConfig = nativeChannelConfigImport;

/// Options which apply on a per-channel basis and may change at runtime or based on negotiation
/// with our counterparty.
#[must_use]
#[repr(C)]
pub struct ChannelConfig {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelConfig,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelConfig {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelConfig>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelConfig, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelConfig_free(this_obj: ChannelConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelConfig_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelConfig); }
}
#[allow(unused)]
impl ChannelConfig {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelConfig {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelConfig {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelConfig {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Amount (in millionths of a satoshi) charged per satoshi for payments forwarded outbound
/// over the channel.
/// This may be allowed to change at runtime in a later update, however doing so must result in
/// update messages sent to notify all nodes of our updated relay fee.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelConfig_get_forwarding_fee_proportional_millionths(this_ptr: &ChannelConfig) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().forwarding_fee_proportional_millionths;
	*inner_val
}
/// Amount (in millionths of a satoshi) charged per satoshi for payments forwarded outbound
/// over the channel.
/// This may be allowed to change at runtime in a later update, however doing so must result in
/// update messages sent to notify all nodes of our updated relay fee.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelConfig_set_forwarding_fee_proportional_millionths(this_ptr: &mut ChannelConfig, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.forwarding_fee_proportional_millionths = val;
}
/// Amount (in milli-satoshi) charged for payments forwarded outbound over the channel, in
/// excess of [`forwarding_fee_proportional_millionths`].
/// This may be allowed to change at runtime in a later update, however doing so must result in
/// update messages sent to notify all nodes of our updated relay fee.
///
/// The default value of a single satoshi roughly matches the market rate on many routing nodes
/// as of July 2021. Adjusting it upwards or downwards may change whether nodes route through
/// this node.
///
/// Default value: 1000.
///
/// [`forwarding_fee_proportional_millionths`]: ChannelConfig::forwarding_fee_proportional_millionths
#[no_mangle]
pub extern "C" fn ChannelConfig_get_forwarding_fee_base_msat(this_ptr: &ChannelConfig) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().forwarding_fee_base_msat;
	*inner_val
}
/// Amount (in milli-satoshi) charged for payments forwarded outbound over the channel, in
/// excess of [`forwarding_fee_proportional_millionths`].
/// This may be allowed to change at runtime in a later update, however doing so must result in
/// update messages sent to notify all nodes of our updated relay fee.
///
/// The default value of a single satoshi roughly matches the market rate on many routing nodes
/// as of July 2021. Adjusting it upwards or downwards may change whether nodes route through
/// this node.
///
/// Default value: 1000.
///
/// [`forwarding_fee_proportional_millionths`]: ChannelConfig::forwarding_fee_proportional_millionths
#[no_mangle]
pub extern "C" fn ChannelConfig_set_forwarding_fee_base_msat(this_ptr: &mut ChannelConfig, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.forwarding_fee_base_msat = val;
}
/// The difference in the CLTV value between incoming HTLCs and an outbound HTLC forwarded over
/// the channel this config applies to.
///
/// This is analogous to [`ChannelHandshakeConfig::our_to_self_delay`] but applies to in-flight
/// HTLC balance when a channel appears on-chain whereas
/// [`ChannelHandshakeConfig::our_to_self_delay`] applies to the remaining
/// (non-HTLC-encumbered) balance.
///
/// Thus, for HTLC-encumbered balances to be enforced on-chain when a channel is force-closed,
/// we (or one of our watchtowers) MUST be online to check for broadcast of the current
/// commitment transaction at least once per this many blocks (minus some margin to allow us
/// enough time to broadcast and confirm a transaction, possibly with time in between to RBF
/// the spending transaction).
///
/// Default value: 72 (12 hours at an average of 6 blocks/hour).
/// Minimum value: [`MIN_CLTV_EXPIRY_DELTA`], any values less than this will be treated as
///                [`MIN_CLTV_EXPIRY_DELTA`] instead.
///
/// [`MIN_CLTV_EXPIRY_DELTA`]: crate::ln::channelmanager::MIN_CLTV_EXPIRY_DELTA
#[no_mangle]
pub extern "C" fn ChannelConfig_get_cltv_expiry_delta(this_ptr: &ChannelConfig) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The difference in the CLTV value between incoming HTLCs and an outbound HTLC forwarded over
/// the channel this config applies to.
///
/// This is analogous to [`ChannelHandshakeConfig::our_to_self_delay`] but applies to in-flight
/// HTLC balance when a channel appears on-chain whereas
/// [`ChannelHandshakeConfig::our_to_self_delay`] applies to the remaining
/// (non-HTLC-encumbered) balance.
///
/// Thus, for HTLC-encumbered balances to be enforced on-chain when a channel is force-closed,
/// we (or one of our watchtowers) MUST be online to check for broadcast of the current
/// commitment transaction at least once per this many blocks (minus some margin to allow us
/// enough time to broadcast and confirm a transaction, possibly with time in between to RBF
/// the spending transaction).
///
/// Default value: 72 (12 hours at an average of 6 blocks/hour).
/// Minimum value: [`MIN_CLTV_EXPIRY_DELTA`], any values less than this will be treated as
///                [`MIN_CLTV_EXPIRY_DELTA`] instead.
///
/// [`MIN_CLTV_EXPIRY_DELTA`]: crate::ln::channelmanager::MIN_CLTV_EXPIRY_DELTA
#[no_mangle]
pub extern "C" fn ChannelConfig_set_cltv_expiry_delta(this_ptr: &mut ChannelConfig, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Set to announce the channel publicly and notify all nodes that they can route via this
/// channel.
///
/// This should only be set to true for nodes which expect to be online reliably.
///
/// As the node which funds a channel picks this value this will only apply for new outbound
/// channels unless [`ChannelHandshakeLimits::force_announced_channel_preference`] is set.
///
/// This cannot be changed after the initial channel handshake.
///
/// Default value: false.
#[no_mangle]
pub extern "C" fn ChannelConfig_get_announced_channel(this_ptr: &ChannelConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().announced_channel;
	*inner_val
}
/// Set to announce the channel publicly and notify all nodes that they can route via this
/// channel.
///
/// This should only be set to true for nodes which expect to be online reliably.
///
/// As the node which funds a channel picks this value this will only apply for new outbound
/// channels unless [`ChannelHandshakeLimits::force_announced_channel_preference`] is set.
///
/// This cannot be changed after the initial channel handshake.
///
/// Default value: false.
#[no_mangle]
pub extern "C" fn ChannelConfig_set_announced_channel(this_ptr: &mut ChannelConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.announced_channel = val;
}
/// When set, we commit to an upfront shutdown_pubkey at channel open. If our counterparty
/// supports it, they will then enforce the mutual-close output to us matches what we provided
/// at intialization, preventing us from closing to an alternate pubkey.
///
/// This is set to true by default to provide a slight increase in security, though ultimately
/// any attacker who is able to take control of a channel can just as easily send the funds via
/// lightning payments, so we never require that our counterparties support this option.
///
/// This cannot be changed after a channel has been initialized.
///
/// Default value: true.
#[no_mangle]
pub extern "C" fn ChannelConfig_get_commit_upfront_shutdown_pubkey(this_ptr: &ChannelConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().commit_upfront_shutdown_pubkey;
	*inner_val
}
/// When set, we commit to an upfront shutdown_pubkey at channel open. If our counterparty
/// supports it, they will then enforce the mutual-close output to us matches what we provided
/// at intialization, preventing us from closing to an alternate pubkey.
///
/// This is set to true by default to provide a slight increase in security, though ultimately
/// any attacker who is able to take control of a channel can just as easily send the funds via
/// lightning payments, so we never require that our counterparties support this option.
///
/// This cannot be changed after a channel has been initialized.
///
/// Default value: true.
#[no_mangle]
pub extern "C" fn ChannelConfig_set_commit_upfront_shutdown_pubkey(this_ptr: &mut ChannelConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.commit_upfront_shutdown_pubkey = val;
}
/// Limit our total exposure to in-flight HTLCs which are burned to fees as they are too
/// small to claim on-chain.
///
/// When an HTLC present in one of our channels is below a \"dust\" threshold, the HTLC will
/// not be claimable on-chain, instead being turned into additional miner fees if either
/// party force-closes the channel. Because the threshold is per-HTLC, our total exposure
/// to such payments may be sustantial if there are many dust HTLCs present when the
/// channel is force-closed.
///
/// This limit is applied for sent, forwarded, and received HTLCs and limits the total
/// exposure across all three types per-channel. Setting this too low may prevent the
/// sending or receipt of low-value HTLCs on high-traffic nodes, and this limit is very
/// important to prevent stealing of dust HTLCs by miners.
///
/// Default value: 5_000_000 msat.
#[no_mangle]
pub extern "C" fn ChannelConfig_get_max_dust_htlc_exposure_msat(this_ptr: &ChannelConfig) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_dust_htlc_exposure_msat;
	*inner_val
}
/// Limit our total exposure to in-flight HTLCs which are burned to fees as they are too
/// small to claim on-chain.
///
/// When an HTLC present in one of our channels is below a \"dust\" threshold, the HTLC will
/// not be claimable on-chain, instead being turned into additional miner fees if either
/// party force-closes the channel. Because the threshold is per-HTLC, our total exposure
/// to such payments may be sustantial if there are many dust HTLCs present when the
/// channel is force-closed.
///
/// This limit is applied for sent, forwarded, and received HTLCs and limits the total
/// exposure across all three types per-channel. Setting this too low may prevent the
/// sending or receipt of low-value HTLCs on high-traffic nodes, and this limit is very
/// important to prevent stealing of dust HTLCs by miners.
///
/// Default value: 5_000_000 msat.
#[no_mangle]
pub extern "C" fn ChannelConfig_set_max_dust_htlc_exposure_msat(this_ptr: &mut ChannelConfig, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_dust_htlc_exposure_msat = val;
}
/// The additional fee we're willing to pay to avoid waiting for the counterparty's
/// `to_self_delay` to reclaim funds.
///
/// When we close a channel cooperatively with our counterparty, we negotiate a fee for the
/// closing transaction which both sides find acceptable, ultimately paid by the channel
/// funder/initiator.
///
/// When we are the funder, because we have to pay the channel closing fee, we bound the
/// acceptable fee by our [`Background`] and [`Normal`] fees, with the upper bound increased by
/// this value. Because the on-chain fee we'd pay to force-close the channel is kept near our
/// [`Normal`] feerate during normal operation, this value represents the additional fee we're
/// willing to pay in order to avoid waiting for our counterparty's to_self_delay to reclaim our
/// funds.
///
/// When we are not the funder, we require the closing transaction fee pay at least our
/// [`Background`] fee estimate, but allow our counterparty to pay as much fee as they like.
/// Thus, this value is ignored when we are not the funder.
///
/// Default value: 1000 satoshis.
///
/// [`Normal`]: crate::chain::chaininterface::ConfirmationTarget::Normal
/// [`Background`]: crate::chain::chaininterface::ConfirmationTarget::Background
#[no_mangle]
pub extern "C" fn ChannelConfig_get_force_close_avoidance_max_fee_satoshis(this_ptr: &ChannelConfig) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().force_close_avoidance_max_fee_satoshis;
	*inner_val
}
/// The additional fee we're willing to pay to avoid waiting for the counterparty's
/// `to_self_delay` to reclaim funds.
///
/// When we close a channel cooperatively with our counterparty, we negotiate a fee for the
/// closing transaction which both sides find acceptable, ultimately paid by the channel
/// funder/initiator.
///
/// When we are the funder, because we have to pay the channel closing fee, we bound the
/// acceptable fee by our [`Background`] and [`Normal`] fees, with the upper bound increased by
/// this value. Because the on-chain fee we'd pay to force-close the channel is kept near our
/// [`Normal`] feerate during normal operation, this value represents the additional fee we're
/// willing to pay in order to avoid waiting for our counterparty's to_self_delay to reclaim our
/// funds.
///
/// When we are not the funder, we require the closing transaction fee pay at least our
/// [`Background`] fee estimate, but allow our counterparty to pay as much fee as they like.
/// Thus, this value is ignored when we are not the funder.
///
/// Default value: 1000 satoshis.
///
/// [`Normal`]: crate::chain::chaininterface::ConfirmationTarget::Normal
/// [`Background`]: crate::chain::chaininterface::ConfirmationTarget::Background
#[no_mangle]
pub extern "C" fn ChannelConfig_set_force_close_avoidance_max_fee_satoshis(this_ptr: &mut ChannelConfig, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.force_close_avoidance_max_fee_satoshis = val;
}
/// Constructs a new ChannelConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelConfig_new(mut forwarding_fee_proportional_millionths_arg: u32, mut forwarding_fee_base_msat_arg: u32, mut cltv_expiry_delta_arg: u16, mut announced_channel_arg: bool, mut commit_upfront_shutdown_pubkey_arg: bool, mut max_dust_htlc_exposure_msat_arg: u64, mut force_close_avoidance_max_fee_satoshis_arg: u64) -> ChannelConfig {
	ChannelConfig { inner: ObjOps::heap_alloc(nativeChannelConfig {
		forwarding_fee_proportional_millionths: forwarding_fee_proportional_millionths_arg,
		forwarding_fee_base_msat: forwarding_fee_base_msat_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
		announced_channel: announced_channel_arg,
		commit_upfront_shutdown_pubkey: commit_upfront_shutdown_pubkey_arg,
		max_dust_htlc_exposure_msat: max_dust_htlc_exposure_msat_arg,
		force_close_avoidance_max_fee_satoshis: force_close_avoidance_max_fee_satoshis_arg,
	}), is_owned: true }
}
impl Clone for ChannelConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelConfig>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelConfig
pub extern "C" fn ChannelConfig_clone(orig: &ChannelConfig) -> ChannelConfig {
	orig.clone()
}
/// Creates a "default" ChannelConfig. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelConfig_default() -> ChannelConfig {
	ChannelConfig { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
#[no_mangle]
/// Serialize the ChannelConfig object into a byte array which can be read by ChannelConfig_read
pub extern "C" fn ChannelConfig_write(obj: &ChannelConfig) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelConfig_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelConfig) })
}
#[no_mangle]
/// Read a ChannelConfig from a byte array, created by ChannelConfig_write
pub extern "C" fn ChannelConfig_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelConfigDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::config::ChannelConfig { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::util::config::UserConfig as nativeUserConfigImport;
pub(crate) type nativeUserConfig = nativeUserConfigImport;

/// Top-level config which holds ChannelHandshakeLimits and ChannelConfig.
///
/// Default::default() provides sane defaults for most configurations
/// (but currently with 0 relay fees!)
#[must_use]
#[repr(C)]
pub struct UserConfig {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUserConfig,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for UserConfig {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUserConfig>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UserConfig, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UserConfig_free(this_obj: UserConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UserConfig_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUserConfig); }
}
#[allow(unused)]
impl UserConfig {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUserConfig {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUserConfig {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUserConfig {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Channel config that we propose to our counterparty.
#[no_mangle]
pub extern "C" fn UserConfig_get_own_channel_config(this_ptr: &UserConfig) -> crate::lightning::util::config::ChannelHandshakeConfig {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().own_channel_config;
	crate::lightning::util::config::ChannelHandshakeConfig { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::config::ChannelHandshakeConfig<>) as *mut _) }, is_owned: false }
}
/// Channel config that we propose to our counterparty.
#[no_mangle]
pub extern "C" fn UserConfig_set_own_channel_config(this_ptr: &mut UserConfig, mut val: crate::lightning::util::config::ChannelHandshakeConfig) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.own_channel_config = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Limits applied to our counterparty's proposed channel config settings.
#[no_mangle]
pub extern "C" fn UserConfig_get_peer_channel_config_limits(this_ptr: &UserConfig) -> crate::lightning::util::config::ChannelHandshakeLimits {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().peer_channel_config_limits;
	crate::lightning::util::config::ChannelHandshakeLimits { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::config::ChannelHandshakeLimits<>) as *mut _) }, is_owned: false }
}
/// Limits applied to our counterparty's proposed channel config settings.
#[no_mangle]
pub extern "C" fn UserConfig_set_peer_channel_config_limits(this_ptr: &mut UserConfig, mut val: crate::lightning::util::config::ChannelHandshakeLimits) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.peer_channel_config_limits = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Channel config which affects behavior during channel lifetime.
#[no_mangle]
pub extern "C" fn UserConfig_get_channel_options(this_ptr: &UserConfig) -> crate::lightning::util::config::ChannelConfig {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_options;
	crate::lightning::util::config::ChannelConfig { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::config::ChannelConfig<>) as *mut _) }, is_owned: false }
}
/// Channel config which affects behavior during channel lifetime.
#[no_mangle]
pub extern "C" fn UserConfig_set_channel_options(this_ptr: &mut UserConfig, mut val: crate::lightning::util::config::ChannelConfig) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_options = *unsafe { Box::from_raw(val.take_inner()) };
}
/// If this is set to false, we will reject any HTLCs which were to be forwarded over private
/// channels. This prevents us from taking on HTLC-forwarding risk when we intend to run as a
/// node which is not online reliably.
///
/// For nodes which are not online reliably, you should set all channels to *not* be announced
/// (using [`ChannelConfig::announced_channel`] and
/// [`ChannelHandshakeLimits::force_announced_channel_preference`]) and set this to false to
/// ensure you are not exposed to any forwarding risk.
///
/// Note that because you cannot change a channel's announced state after creation, there is no
/// way to disable forwarding on public channels retroactively. Thus, in order to change a node
/// from a publicly-announced forwarding node to a private non-forwarding node you must close
/// all your channels and open new ones. For privacy, you should also change your node_id
/// (swapping all private and public key material for new ones) at that time.
///
/// Default value: false.
#[no_mangle]
pub extern "C" fn UserConfig_get_accept_forwards_to_priv_channels(this_ptr: &UserConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().accept_forwards_to_priv_channels;
	*inner_val
}
/// If this is set to false, we will reject any HTLCs which were to be forwarded over private
/// channels. This prevents us from taking on HTLC-forwarding risk when we intend to run as a
/// node which is not online reliably.
///
/// For nodes which are not online reliably, you should set all channels to *not* be announced
/// (using [`ChannelConfig::announced_channel`] and
/// [`ChannelHandshakeLimits::force_announced_channel_preference`]) and set this to false to
/// ensure you are not exposed to any forwarding risk.
///
/// Note that because you cannot change a channel's announced state after creation, there is no
/// way to disable forwarding on public channels retroactively. Thus, in order to change a node
/// from a publicly-announced forwarding node to a private non-forwarding node you must close
/// all your channels and open new ones. For privacy, you should also change your node_id
/// (swapping all private and public key material for new ones) at that time.
///
/// Default value: false.
#[no_mangle]
pub extern "C" fn UserConfig_set_accept_forwards_to_priv_channels(this_ptr: &mut UserConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.accept_forwards_to_priv_channels = val;
}
/// Constructs a new UserConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn UserConfig_new(mut own_channel_config_arg: crate::lightning::util::config::ChannelHandshakeConfig, mut peer_channel_config_limits_arg: crate::lightning::util::config::ChannelHandshakeLimits, mut channel_options_arg: crate::lightning::util::config::ChannelConfig, mut accept_forwards_to_priv_channels_arg: bool) -> UserConfig {
	UserConfig { inner: ObjOps::heap_alloc(nativeUserConfig {
		own_channel_config: *unsafe { Box::from_raw(own_channel_config_arg.take_inner()) },
		peer_channel_config_limits: *unsafe { Box::from_raw(peer_channel_config_limits_arg.take_inner()) },
		channel_options: *unsafe { Box::from_raw(channel_options_arg.take_inner()) },
		accept_forwards_to_priv_channels: accept_forwards_to_priv_channels_arg,
	}), is_owned: true }
}
impl Clone for UserConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUserConfig>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UserConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUserConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UserConfig
pub extern "C" fn UserConfig_clone(orig: &UserConfig) -> UserConfig {
	orig.clone()
}
/// Creates a "default" UserConfig. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn UserConfig_default() -> UserConfig {
	UserConfig { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
