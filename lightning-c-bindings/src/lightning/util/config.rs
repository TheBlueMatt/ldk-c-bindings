// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Various user-configurable channel limits and settings which ChannelManager
//! applies for you.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::util::config::ChannelHandshakeConfig as nativeChannelHandshakeConfigImport;
pub(crate) type nativeChannelHandshakeConfig = nativeChannelHandshakeConfigImport;

/// Configuration we set when applicable.
///
/// `Default::default()` provides sane defaults.
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

impl core::ops::Deref for ChannelHandshakeConfig {
	type Target = nativeChannelHandshakeConfig;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ChannelHandshakeConfig { }
unsafe impl core::marker::Sync for ChannelHandshakeConfig { }
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelHandshakeConfig) };
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
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Confirmations we will wait for before considering the channel locked in.
/// Applied only for inbound channels (see [`ChannelHandshakeLimits::max_minimum_depth`] for the
/// equivalent limit applied to outbound channels).
///
/// A lower-bound of `1` is applied, requiring all channels to have a confirmed commitment
/// transaction before operation. If you wish to accept channels with zero confirmations, see
/// [`UserConfig::manually_accept_inbound_channels`] and
/// [`ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`].
///
/// Default value: `6`
///
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel_from_trusted_peer_0conf
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_minimum_depth(this_ptr: &ChannelHandshakeConfig) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().minimum_depth;
	*inner_val
}
/// Confirmations we will wait for before considering the channel locked in.
/// Applied only for inbound channels (see [`ChannelHandshakeLimits::max_minimum_depth`] for the
/// equivalent limit applied to outbound channels).
///
/// A lower-bound of `1` is applied, requiring all channels to have a confirmed commitment
/// transaction before operation. If you wish to accept channels with zero confirmations, see
/// [`UserConfig::manually_accept_inbound_channels`] and
/// [`ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`].
///
/// Default value: `6`
///
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel_from_trusted_peer_0conf
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
/// Default value: [`BREAKDOWN_TIMEOUT`] (We enforce it as a minimum at channel opening so you
/// can tweak config to ask for more security, not less.)
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
/// Default value: [`BREAKDOWN_TIMEOUT`] (We enforce it as a minimum at channel opening so you
/// can tweak config to ask for more security, not less.)
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_our_to_self_delay(this_ptr: &mut ChannelHandshakeConfig, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.our_to_self_delay = val;
}
/// Set to the smallest value HTLC we will accept to process.
///
/// This value is sent to our counterparty on channel-open and we close the channel any time
/// our counterparty misbehaves by sending us an HTLC with a value smaller than this.
///
/// Default value: `1` (If the value is less than `1`, it is ignored and set to `1`, as is
/// required by the protocol.
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
/// Default value: `1` (If the value is less than `1`, it is ignored and set to `1`, as is
/// required by the protocol.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_our_htlc_minimum_msat(this_ptr: &mut ChannelHandshakeConfig, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.our_htlc_minimum_msat = val;
}
/// Sets the percentage of the channel value we will cap the total value of outstanding inbound
/// HTLCs to.
///
/// This can be set to a value between 1-100, where the value corresponds to the percent of the
/// channel value in whole percentages.
///
/// Note that:
/// * If configured to another value than the default value `10`, any new channels created with
///   the non default value will cause versions of LDK prior to 0.0.104 to refuse to read the
///   `ChannelManager`.
///
/// * This caps the total value for inbound HTLCs in-flight only, and there's currently
///   no way to configure the cap for the total value of outbound HTLCs in-flight.
///
/// * The requirements for your node being online to ensure the safety of HTLC-encumbered funds
///   are different from the non-HTLC-encumbered funds. This makes this an important knob to
///   restrict exposure to loss due to being offline for too long.
///   See [`ChannelHandshakeConfig::our_to_self_delay`] and [`ChannelConfig::cltv_expiry_delta`]
///   for more information.
///
/// Default value: `10`
///
/// Minimum value: `1` (Any values less will be treated as `1` instead.)
///
/// Maximum value: `100` (Any values larger will be treated as `100` instead.)
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_max_inbound_htlc_value_in_flight_percent_of_channel(this_ptr: &ChannelHandshakeConfig) -> u8 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_inbound_htlc_value_in_flight_percent_of_channel;
	*inner_val
}
/// Sets the percentage of the channel value we will cap the total value of outstanding inbound
/// HTLCs to.
///
/// This can be set to a value between 1-100, where the value corresponds to the percent of the
/// channel value in whole percentages.
///
/// Note that:
/// * If configured to another value than the default value `10`, any new channels created with
///   the non default value will cause versions of LDK prior to 0.0.104 to refuse to read the
///   `ChannelManager`.
///
/// * This caps the total value for inbound HTLCs in-flight only, and there's currently
///   no way to configure the cap for the total value of outbound HTLCs in-flight.
///
/// * The requirements for your node being online to ensure the safety of HTLC-encumbered funds
///   are different from the non-HTLC-encumbered funds. This makes this an important knob to
///   restrict exposure to loss due to being offline for too long.
///   See [`ChannelHandshakeConfig::our_to_self_delay`] and [`ChannelConfig::cltv_expiry_delta`]
///   for more information.
///
/// Default value: `10`
///
/// Minimum value: `1` (Any values less will be treated as `1` instead.)
///
/// Maximum value: `100` (Any values larger will be treated as `100` instead.)
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_max_inbound_htlc_value_in_flight_percent_of_channel(this_ptr: &mut ChannelHandshakeConfig, mut val: u8) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_inbound_htlc_value_in_flight_percent_of_channel = val;
}
/// If set, we attempt to negotiate the `scid_privacy` (referred to as `scid_alias` in the
/// BOLTs) option for outbound private channels. This provides better privacy by not including
/// our real on-chain channel UTXO in each invoice and requiring that our counterparty only
/// relay HTLCs to us using the channel's SCID alias.
///
/// If this option is set, channels may be created that will not be readable by LDK versions
/// prior to 0.0.106, causing [`ChannelManager`]'s read method to return a
/// [`DecodeError::InvalidValue`].
///
/// Note that setting this to true does *not* prevent us from opening channels with
/// counterparties that do not support the `scid_alias` option; we will simply fall back to a
/// private channel without that option.
///
/// Ignored if the channel is negotiated to be announced, see
/// [`ChannelHandshakeConfig::announce_for_forwarding`] and
/// [`ChannelHandshakeLimits::force_announced_channel_preference`] for more.
///
/// Default value: `false` (This value is likely to change to `true` in the future.)
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`DecodeError::InvalidValue`]: crate::ln::msgs::DecodeError::InvalidValue
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_negotiate_scid_privacy(this_ptr: &ChannelHandshakeConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().negotiate_scid_privacy;
	*inner_val
}
/// If set, we attempt to negotiate the `scid_privacy` (referred to as `scid_alias` in the
/// BOLTs) option for outbound private channels. This provides better privacy by not including
/// our real on-chain channel UTXO in each invoice and requiring that our counterparty only
/// relay HTLCs to us using the channel's SCID alias.
///
/// If this option is set, channels may be created that will not be readable by LDK versions
/// prior to 0.0.106, causing [`ChannelManager`]'s read method to return a
/// [`DecodeError::InvalidValue`].
///
/// Note that setting this to true does *not* prevent us from opening channels with
/// counterparties that do not support the `scid_alias` option; we will simply fall back to a
/// private channel without that option.
///
/// Ignored if the channel is negotiated to be announced, see
/// [`ChannelHandshakeConfig::announce_for_forwarding`] and
/// [`ChannelHandshakeLimits::force_announced_channel_preference`] for more.
///
/// Default value: `false` (This value is likely to change to `true` in the future.)
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`DecodeError::InvalidValue`]: crate::ln::msgs::DecodeError::InvalidValue
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_negotiate_scid_privacy(this_ptr: &mut ChannelHandshakeConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.negotiate_scid_privacy = val;
}
/// Set to announce the channel publicly and notify all nodes that they can route via this
/// channel.
///
/// This should only be set to true for nodes which expect to be online reliably.
///
/// As the node which funds a channel picks this value this will only apply for new outbound
/// channels unless [`ChannelHandshakeLimits::force_announced_channel_preference`] is set.
///
/// Default value: `false`
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_announce_for_forwarding(this_ptr: &ChannelHandshakeConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().announce_for_forwarding;
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
/// Default value: `false`
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_announce_for_forwarding(this_ptr: &mut ChannelHandshakeConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.announce_for_forwarding = val;
}
/// When set, we commit to an upfront shutdown_pubkey at channel open. If our counterparty
/// supports it, they will then enforce the mutual-close output to us matches what we provided
/// at intialization, preventing us from closing to an alternate pubkey.
///
/// This is set to true by default to provide a slight increase in security, though ultimately
/// any attacker who is able to take control of a channel can just as easily send the funds via
/// lightning payments, so we never require that our counterparties support this option.
///
/// The upfront key committed is provided from [`SignerProvider::get_shutdown_scriptpubkey`].
///
/// Default value: `true`
///
/// [`SignerProvider::get_shutdown_scriptpubkey`]: crate::sign::SignerProvider::get_shutdown_scriptpubkey
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_commit_upfront_shutdown_pubkey(this_ptr: &ChannelHandshakeConfig) -> bool {
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
/// The upfront key committed is provided from [`SignerProvider::get_shutdown_scriptpubkey`].
///
/// Default value: `true`
///
/// [`SignerProvider::get_shutdown_scriptpubkey`]: crate::sign::SignerProvider::get_shutdown_scriptpubkey
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_commit_upfront_shutdown_pubkey(this_ptr: &mut ChannelHandshakeConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.commit_upfront_shutdown_pubkey = val;
}
/// The Proportion of the channel value to configure as counterparty's channel reserve,
/// i.e., `their_channel_reserve_satoshis` for both outbound and inbound channels.
///
/// `their_channel_reserve_satoshis` is the minimum balance that the other node has to maintain
/// on their side, at all times.
/// This ensures that if our counterparty broadcasts a revoked state, we can punish them by
/// claiming at least this value on chain.
///
/// Channel reserve values greater than 30% could be considered highly unreasonable, since that
/// amount can never be used for payments.
/// Also, if our selected channel reserve for counterparty and counterparty's selected
/// channel reserve for us sum up to equal or greater than channel value, channel negotiations
/// will fail.
///
/// Note: Versions of LDK earlier than v0.0.104 will fail to read channels with any channel reserve
/// other than the default value.
///
/// Default value: `10_000` millionths (i.e., 1% of channel value)
///
/// Minimum value: If the calculated proportional value is less than `1000` sats, it will be
///                treated as `1000` sats instead, which is a safe implementation-specific lower
///                bound.
///
/// Maximum value: `1_000_000` (i.e., 100% of channel value. Any values larger than one million
///                will be treated as one million instead, although channel negotiations will
///                fail in that case.)
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_their_channel_reserve_proportional_millionths(this_ptr: &ChannelHandshakeConfig) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().their_channel_reserve_proportional_millionths;
	*inner_val
}
/// The Proportion of the channel value to configure as counterparty's channel reserve,
/// i.e., `their_channel_reserve_satoshis` for both outbound and inbound channels.
///
/// `their_channel_reserve_satoshis` is the minimum balance that the other node has to maintain
/// on their side, at all times.
/// This ensures that if our counterparty broadcasts a revoked state, we can punish them by
/// claiming at least this value on chain.
///
/// Channel reserve values greater than 30% could be considered highly unreasonable, since that
/// amount can never be used for payments.
/// Also, if our selected channel reserve for counterparty and counterparty's selected
/// channel reserve for us sum up to equal or greater than channel value, channel negotiations
/// will fail.
///
/// Note: Versions of LDK earlier than v0.0.104 will fail to read channels with any channel reserve
/// other than the default value.
///
/// Default value: `10_000` millionths (i.e., 1% of channel value)
///
/// Minimum value: If the calculated proportional value is less than `1000` sats, it will be
///                treated as `1000` sats instead, which is a safe implementation-specific lower
///                bound.
///
/// Maximum value: `1_000_000` (i.e., 100% of channel value. Any values larger than one million
///                will be treated as one million instead, although channel negotiations will
///                fail in that case.)
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_their_channel_reserve_proportional_millionths(this_ptr: &mut ChannelHandshakeConfig, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.their_channel_reserve_proportional_millionths = val;
}
/// If set, we attempt to negotiate the `anchors_zero_fee_htlc_tx`option for all future
/// channels. This feature requires having a reserve of onchain funds readily available to bump
/// transactions in the event of a channel force close to avoid the possibility of losing funds.
///
/// Note that if you wish accept inbound channels with anchor outputs, you must enable
/// [`UserConfig::manually_accept_inbound_channels`] and manually accept them with
/// [`ChannelManager::accept_inbound_channel`]. This is done to give you the chance to check
/// whether your reserve of onchain funds is enough to cover the fees for all existing and new
/// channels featuring anchor outputs in the event of a force close.
///
/// If this option is set, channels may be created that will not be readable by LDK versions
/// prior to 0.0.116, causing [`ChannelManager`]'s read method to return a
/// [`DecodeError::InvalidValue`].
///
/// Note that setting this to true does *not* prevent us from opening channels with
/// counterparties that do not support the `anchors_zero_fee_htlc_tx` option; we will simply
/// fall back to a `static_remote_key` channel.
///
/// LDK will not support the legacy `option_anchors` commitment version due to a discovered
/// vulnerability after its deployment. For more context, see the [`SIGHASH_SINGLE + update_fee
/// Considered Harmful`] mailing list post.
///
/// Default value: `false` (This value is likely to change to `true` in the future.)
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`DecodeError::InvalidValue`]: crate::ln::msgs::DecodeError::InvalidValue
/// [`SIGHASH_SINGLE + update_fee Considered Harmful`]: https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-September/002796.html
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_negotiate_anchors_zero_fee_htlc_tx(this_ptr: &ChannelHandshakeConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().negotiate_anchors_zero_fee_htlc_tx;
	*inner_val
}
/// If set, we attempt to negotiate the `anchors_zero_fee_htlc_tx`option for all future
/// channels. This feature requires having a reserve of onchain funds readily available to bump
/// transactions in the event of a channel force close to avoid the possibility of losing funds.
///
/// Note that if you wish accept inbound channels with anchor outputs, you must enable
/// [`UserConfig::manually_accept_inbound_channels`] and manually accept them with
/// [`ChannelManager::accept_inbound_channel`]. This is done to give you the chance to check
/// whether your reserve of onchain funds is enough to cover the fees for all existing and new
/// channels featuring anchor outputs in the event of a force close.
///
/// If this option is set, channels may be created that will not be readable by LDK versions
/// prior to 0.0.116, causing [`ChannelManager`]'s read method to return a
/// [`DecodeError::InvalidValue`].
///
/// Note that setting this to true does *not* prevent us from opening channels with
/// counterparties that do not support the `anchors_zero_fee_htlc_tx` option; we will simply
/// fall back to a `static_remote_key` channel.
///
/// LDK will not support the legacy `option_anchors` commitment version due to a discovered
/// vulnerability after its deployment. For more context, see the [`SIGHASH_SINGLE + update_fee
/// Considered Harmful`] mailing list post.
///
/// Default value: `false` (This value is likely to change to `true` in the future.)
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`DecodeError::InvalidValue`]: crate::ln::msgs::DecodeError::InvalidValue
/// [`SIGHASH_SINGLE + update_fee Considered Harmful`]: https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-September/002796.html
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_negotiate_anchors_zero_fee_htlc_tx(this_ptr: &mut ChannelHandshakeConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.negotiate_anchors_zero_fee_htlc_tx = val;
}
/// The maximum number of HTLCs in-flight from our counterparty towards us at the same time.
///
/// Increasing the value can help improve liquidity and stability in
/// routing at the cost of higher long term disk / DB usage.
///
/// Note: Versions of LDK earlier than v0.0.115 will fail to read channels with a configuration
/// other than the default value.
///
/// Default value: `50`
///
/// Maximum value: `483` (Any values larger will be treated as `483`. This is the BOLT #2 spec
/// limit on `max_accepted_htlcs`.)
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_our_max_accepted_htlcs(this_ptr: &ChannelHandshakeConfig) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().our_max_accepted_htlcs;
	*inner_val
}
/// The maximum number of HTLCs in-flight from our counterparty towards us at the same time.
///
/// Increasing the value can help improve liquidity and stability in
/// routing at the cost of higher long term disk / DB usage.
///
/// Note: Versions of LDK earlier than v0.0.115 will fail to read channels with a configuration
/// other than the default value.
///
/// Default value: `50`
///
/// Maximum value: `483` (Any values larger will be treated as `483`. This is the BOLT #2 spec
/// limit on `max_accepted_htlcs`.)
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_our_max_accepted_htlcs(this_ptr: &mut ChannelHandshakeConfig, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.our_max_accepted_htlcs = val;
}
/// Constructs a new ChannelHandshakeConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_new(mut minimum_depth_arg: u32, mut our_to_self_delay_arg: u16, mut our_htlc_minimum_msat_arg: u64, mut max_inbound_htlc_value_in_flight_percent_of_channel_arg: u8, mut negotiate_scid_privacy_arg: bool, mut announce_for_forwarding_arg: bool, mut commit_upfront_shutdown_pubkey_arg: bool, mut their_channel_reserve_proportional_millionths_arg: u32, mut negotiate_anchors_zero_fee_htlc_tx_arg: bool, mut our_max_accepted_htlcs_arg: u16) -> ChannelHandshakeConfig {
	ChannelHandshakeConfig { inner: ObjOps::heap_alloc(nativeChannelHandshakeConfig {
		minimum_depth: minimum_depth_arg,
		our_to_self_delay: our_to_self_delay_arg,
		our_htlc_minimum_msat: our_htlc_minimum_msat_arg,
		max_inbound_htlc_value_in_flight_percent_of_channel: max_inbound_htlc_value_in_flight_percent_of_channel_arg,
		negotiate_scid_privacy: negotiate_scid_privacy_arg,
		announce_for_forwarding: announce_for_forwarding_arg,
		commit_upfront_shutdown_pubkey: commit_upfront_shutdown_pubkey_arg,
		their_channel_reserve_proportional_millionths: their_channel_reserve_proportional_millionths_arg,
		negotiate_anchors_zero_fee_htlc_tx: negotiate_anchors_zero_fee_htlc_tx_arg,
		our_max_accepted_htlcs: our_max_accepted_htlcs_arg,
	}), is_owned: true }
}
impl Clone for ChannelHandshakeConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelHandshakeConfig>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelHandshakeConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelHandshakeConfig
pub extern "C" fn ChannelHandshakeConfig_clone(orig: &ChannelHandshakeConfig) -> ChannelHandshakeConfig {
	orig.clone()
}
/// Get a string which allows debug introspection of a ChannelHandshakeConfig object
pub extern "C" fn ChannelHandshakeConfig_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::config::ChannelHandshakeConfig }).into()}
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
/// Use `0` or `<type>::max_value()` as appropriate to skip checking.
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

impl core::ops::Deref for ChannelHandshakeLimits {
	type Target = nativeChannelHandshakeLimits;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ChannelHandshakeLimits { }
unsafe impl core::marker::Sync for ChannelHandshakeLimits { }
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelHandshakeLimits) };
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
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Minimum allowed satoshis when a channel is funded. This is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: `1000`
/// (Minimum of [`ChannelHandshakeConfig::their_channel_reserve_proportional_millionths`])
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_funding_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_funding_satoshis;
	*inner_val
}
/// Minimum allowed satoshis when a channel is funded. This is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: `1000`
/// (Minimum of [`ChannelHandshakeConfig::their_channel_reserve_proportional_millionths`])
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_funding_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_funding_satoshis = val;
}
/// Maximum allowed satoshis when a channel is funded. This is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: `2^24 - 1`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_funding_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_funding_satoshis;
	*inner_val
}
/// Maximum allowed satoshis when a channel is funded. This is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: `2^24 - 1`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_funding_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_funding_satoshis = val;
}
/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
/// you to limit the maximum minimum-size they can require.
///
/// Default value: `u64::max_value`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_htlc_minimum_msat(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_htlc_minimum_msat;
	*inner_val
}
/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
/// you to limit the maximum minimum-size they can require.
///
/// Default value: `u64::max_value`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_htlc_minimum_msat(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_htlc_minimum_msat = val;
}
/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
///
/// Default value: `0`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_max_htlc_value_in_flight_msat(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_max_htlc_value_in_flight_msat;
	*inner_val
}
/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
///
/// Default value: `0`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_max_htlc_value_in_flight_msat(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_max_htlc_value_in_flight_msat = val;
}
/// The remote node will require we keep a certain amount in direct payment to ourselves at all
/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
///
/// Default value: `u64::max_value`.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_channel_reserve_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_channel_reserve_satoshis;
	*inner_val
}
/// The remote node will require we keep a certain amount in direct payment to ourselves at all
/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
///
/// Default value: `u64::max_value`.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_channel_reserve_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_channel_reserve_satoshis = val;
}
/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
/// time. This allows you to set a minimum such value.
///
/// Default value: `0`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_max_accepted_htlcs(this_ptr: &ChannelHandshakeLimits) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().min_max_accepted_htlcs;
	*inner_val
}
/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
/// time. This allows you to set a minimum such value.
///
/// Default value: `0`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_max_accepted_htlcs(this_ptr: &mut ChannelHandshakeLimits, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.min_max_accepted_htlcs = val;
}
/// Before a channel is usable the funding transaction will need to be confirmed by at least a
/// certain number of blocks, specified by the node which is not the funder (as the funder can
/// assume they aren't going to double-spend themselves).
/// This config allows you to set a limit on the maximum amount of time to wait.
///
/// Default value: `144`, or roughly one day and only applies to outbound channels
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
/// Default value: `144`, or roughly one day and only applies to outbound channels
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_minimum_depth(this_ptr: &mut ChannelHandshakeLimits, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_minimum_depth = val;
}
/// Whether we implicitly trust funding transactions generated by us for our own outbound
/// channels to not be double-spent.
///
/// If this is set, we assume that our own funding transactions are *never* double-spent, and
/// thus we can trust them without any confirmations. This is generally a reasonable
/// assumption, given we're the only ones who could ever double-spend it (assuming we have sole
/// control of the signing keys).
///
/// You may wish to un-set this if you allow the user to (or do in an automated fashion)
/// double-spend the funding transaction to RBF with an alternative channel open.
///
/// This only applies if our counterparty set their confirmations-required value to `0`, and we
/// always trust our own funding transaction at `1` confirmation irrespective of this value.
/// Thus, this effectively acts as a `min_minimum_depth`, with the only possible values being
/// `true` (`0`) and `false` (`1`).
///
/// Default value: `true`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_trust_own_funding_0conf(this_ptr: &ChannelHandshakeLimits) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().trust_own_funding_0conf;
	*inner_val
}
/// Whether we implicitly trust funding transactions generated by us for our own outbound
/// channels to not be double-spent.
///
/// If this is set, we assume that our own funding transactions are *never* double-spent, and
/// thus we can trust them without any confirmations. This is generally a reasonable
/// assumption, given we're the only ones who could ever double-spend it (assuming we have sole
/// control of the signing keys).
///
/// You may wish to un-set this if you allow the user to (or do in an automated fashion)
/// double-spend the funding transaction to RBF with an alternative channel open.
///
/// This only applies if our counterparty set their confirmations-required value to `0`, and we
/// always trust our own funding transaction at `1` confirmation irrespective of this value.
/// Thus, this effectively acts as a `min_minimum_depth`, with the only possible values being
/// `true` (`0`) and `false` (`1`).
///
/// Default value: `true`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_trust_own_funding_0conf(this_ptr: &mut ChannelHandshakeLimits, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.trust_own_funding_0conf = val;
}
/// Set to force an incoming channel to match our announced channel preference in
/// [`ChannelHandshakeConfig::announce_for_forwarding`].
///
/// For a node which is not online reliably, this should be set to true and
/// [`ChannelHandshakeConfig::announce_for_forwarding`] set to false, ensuring that no announced (aka public)
/// channels will ever be opened.
///
/// Default value: `true`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_force_announced_channel_preference(this_ptr: &ChannelHandshakeLimits) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().force_announced_channel_preference;
	*inner_val
}
/// Set to force an incoming channel to match our announced channel preference in
/// [`ChannelHandshakeConfig::announce_for_forwarding`].
///
/// For a node which is not online reliably, this should be set to true and
/// [`ChannelHandshakeConfig::announce_for_forwarding`] set to false, ensuring that no announced (aka public)
/// channels will ever be opened.
///
/// Default value: `true`
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_force_announced_channel_preference(this_ptr: &mut ChannelHandshakeLimits, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.force_announced_channel_preference = val;
}
/// Set to the amount of time we're willing to wait to claim money back to us.
///
/// Not checking this value would be a security issue, as our peer would be able to set it to
/// max relative lock-time (a year) and we would \"lose\" money as it would be locked for a long time.
///
/// Default value: `2016`, which we also enforce as a maximum value so you can tweak config to
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
/// Default value: `2016`, which we also enforce as a maximum value so you can tweak config to
/// reduce the loss of having useless locked funds (if your peer accepts)
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_their_to_self_delay(this_ptr: &mut ChannelHandshakeLimits, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.their_to_self_delay = val;
}
/// Constructs a new ChannelHandshakeLimits given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_new(mut min_funding_satoshis_arg: u64, mut max_funding_satoshis_arg: u64, mut max_htlc_minimum_msat_arg: u64, mut min_max_htlc_value_in_flight_msat_arg: u64, mut max_channel_reserve_satoshis_arg: u64, mut min_max_accepted_htlcs_arg: u16, mut max_minimum_depth_arg: u32, mut trust_own_funding_0conf_arg: bool, mut force_announced_channel_preference_arg: bool, mut their_to_self_delay_arg: u16) -> ChannelHandshakeLimits {
	ChannelHandshakeLimits { inner: ObjOps::heap_alloc(nativeChannelHandshakeLimits {
		min_funding_satoshis: min_funding_satoshis_arg,
		max_funding_satoshis: max_funding_satoshis_arg,
		max_htlc_minimum_msat: max_htlc_minimum_msat_arg,
		min_max_htlc_value_in_flight_msat: min_max_htlc_value_in_flight_msat_arg,
		max_channel_reserve_satoshis: max_channel_reserve_satoshis_arg,
		min_max_accepted_htlcs: min_max_accepted_htlcs_arg,
		max_minimum_depth: max_minimum_depth_arg,
		trust_own_funding_0conf: trust_own_funding_0conf_arg,
		force_announced_channel_preference: force_announced_channel_preference_arg,
		their_to_self_delay: their_to_self_delay_arg,
	}), is_owned: true }
}
impl Clone for ChannelHandshakeLimits {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelHandshakeLimits>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeLimits_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelHandshakeLimits)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelHandshakeLimits
pub extern "C" fn ChannelHandshakeLimits_clone(orig: &ChannelHandshakeLimits) -> ChannelHandshakeLimits {
	orig.clone()
}
/// Get a string which allows debug introspection of a ChannelHandshakeLimits object
pub extern "C" fn ChannelHandshakeLimits_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::config::ChannelHandshakeLimits }).into()}
/// Creates a "default" ChannelHandshakeLimits. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_default() -> ChannelHandshakeLimits {
	ChannelHandshakeLimits { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
/// Options for how to set the max dust exposure allowed on a channel. See
/// [`ChannelConfig::max_dust_htlc_exposure`] for details.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum MaxDustHTLCExposure {
	/// This sets a fixed limit on the total dust exposure in millisatoshis. Setting this too low
	/// may prevent the sending or receipt of low-value HTLCs on high-traffic nodes, however this
	/// limit is very important to prevent stealing of large amounts of dust HTLCs by miners
	/// through [fee griefing
	/// attacks](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-May/002714.html).
	///
	/// Note that if the feerate increases significantly, without a manual increase
	/// to this maximum the channel may be unable to send/receive HTLCs between the maximum dust
	/// exposure and the new minimum value for HTLCs to be economically viable to claim.
	FixedLimitMsat(
		u64),
	/// This sets a multiplier on the [`ConfirmationTarget::MaximumFeeEstimate`] feerate (in
	/// sats/KW) to determine the maximum allowed dust exposure. If this variant is used then the
	/// maximum dust exposure in millisatoshis is calculated as:
	/// `feerate_per_kw * value`. For example, with our default value
	/// `FeeRateMultiplier(10_000)`:
	///
	/// - For the minimum fee rate of 1 sat/vByte (250 sat/KW, although the minimum
	///   defaults to 253 sats/KW for rounding, see [`FeeEstimator`]), the max dust exposure would
	///   be 253 * 10_000 = 2,530,000 msats.
	/// - For a fee rate of 30 sat/vByte (7500 sat/KW), the max dust exposure would be
	///   7500 * 50_000 = 75,000,000 msats (0.00075 BTC).
	///
	/// Note, if you're using a third-party fee estimator, this may leave you more exposed to a
	/// fee griefing attack, where your fee estimator may purposely overestimate the fee rate,
	/// causing you to accept more dust HTLCs than you would otherwise.
	///
	/// This variant is primarily meant to serve pre-anchor channels, as HTLC fees being included
	/// on HTLC outputs means your channel may be subject to more dust exposure in the event of
	/// increases in fee rate.
	///
	/// # Backwards Compatibility
	/// This variant only became available in LDK 0.0.116, so if you downgrade to a prior version
	/// by default this will be set to a [`Self::FixedLimitMsat`] of 5,000,000 msat.
	///
	/// [`FeeEstimator`]: crate::chain::chaininterface::FeeEstimator
	/// [`ConfirmationTarget::MaximumFeeEstimate`]: crate::chain::chaininterface::ConfirmationTarget::MaximumFeeEstimate
	FeeRateMultiplier(
		u64),
}
use lightning::util::config::MaxDustHTLCExposure as MaxDustHTLCExposureImport;
pub(crate) type nativeMaxDustHTLCExposure = MaxDustHTLCExposureImport;

impl MaxDustHTLCExposure {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMaxDustHTLCExposure {
		match self {
			MaxDustHTLCExposure::FixedLimitMsat (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeMaxDustHTLCExposure::FixedLimitMsat (
					a_nonref,
				)
			},
			MaxDustHTLCExposure::FeeRateMultiplier (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeMaxDustHTLCExposure::FeeRateMultiplier (
					a_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeMaxDustHTLCExposure {
		match self {
			MaxDustHTLCExposure::FixedLimitMsat (mut a, ) => {
				nativeMaxDustHTLCExposure::FixedLimitMsat (
					a,
				)
			},
			MaxDustHTLCExposure::FeeRateMultiplier (mut a, ) => {
				nativeMaxDustHTLCExposure::FeeRateMultiplier (
					a,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &MaxDustHTLCExposureImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeMaxDustHTLCExposure) };
		match native {
			nativeMaxDustHTLCExposure::FixedLimitMsat (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				MaxDustHTLCExposure::FixedLimitMsat (
					a_nonref,
				)
			},
			nativeMaxDustHTLCExposure::FeeRateMultiplier (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				MaxDustHTLCExposure::FeeRateMultiplier (
					a_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeMaxDustHTLCExposure) -> Self {
		match native {
			nativeMaxDustHTLCExposure::FixedLimitMsat (mut a, ) => {
				MaxDustHTLCExposure::FixedLimitMsat (
					a,
				)
			},
			nativeMaxDustHTLCExposure::FeeRateMultiplier (mut a, ) => {
				MaxDustHTLCExposure::FeeRateMultiplier (
					a,
				)
			},
		}
	}
}
/// Frees any resources used by the MaxDustHTLCExposure
#[no_mangle]
pub extern "C" fn MaxDustHTLCExposure_free(this_ptr: MaxDustHTLCExposure) { }
/// Creates a copy of the MaxDustHTLCExposure
#[no_mangle]
pub extern "C" fn MaxDustHTLCExposure_clone(orig: &MaxDustHTLCExposure) -> MaxDustHTLCExposure {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MaxDustHTLCExposure_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const MaxDustHTLCExposure)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MaxDustHTLCExposure_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut MaxDustHTLCExposure) };
}
#[no_mangle]
/// Utility method to constructs a new FixedLimitMsat-variant MaxDustHTLCExposure
pub extern "C" fn MaxDustHTLCExposure_fixed_limit_msat(a: u64) -> MaxDustHTLCExposure {
	MaxDustHTLCExposure::FixedLimitMsat(a, )
}
#[no_mangle]
/// Utility method to constructs a new FeeRateMultiplier-variant MaxDustHTLCExposure
pub extern "C" fn MaxDustHTLCExposure_fee_rate_multiplier(a: u64) -> MaxDustHTLCExposure {
	MaxDustHTLCExposure::FeeRateMultiplier(a, )
}
/// Get a string which allows debug introspection of a MaxDustHTLCExposure object
pub extern "C" fn MaxDustHTLCExposure_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::config::MaxDustHTLCExposure }).into()}
/// Checks if two MaxDustHTLCExposures contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn MaxDustHTLCExposure_eq(a: &MaxDustHTLCExposure, b: &MaxDustHTLCExposure) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the MaxDustHTLCExposure object into a byte array which can be read by MaxDustHTLCExposure_read
pub extern "C" fn MaxDustHTLCExposure_write(obj: &crate::lightning::util::config::MaxDustHTLCExposure) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn MaxDustHTLCExposure_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	MaxDustHTLCExposure_write(unsafe { &*(obj as *const MaxDustHTLCExposure) })
}
#[no_mangle]
/// Read a MaxDustHTLCExposure from a byte array, created by MaxDustHTLCExposure_write
pub extern "C" fn MaxDustHTLCExposure_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_MaxDustHTLCExposureDecodeErrorZ {
	let res: Result<lightning::util::config::MaxDustHTLCExposure, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::config::MaxDustHTLCExposure::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
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

impl core::ops::Deref for ChannelConfig {
	type Target = nativeChannelConfig;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ChannelConfig { }
unsafe impl core::marker::Sync for ChannelConfig { }
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelConfig) };
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
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Amount (in millionths of a satoshi) charged per satoshi for payments forwarded outbound
/// over the channel.
/// This may be allowed to change at runtime in a later update, however doing so must result in
/// update messages sent to notify all nodes of our updated relay fee.
///
/// Default value: `0`
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
/// Default value: `0`
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
/// Default value: `1000`
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
/// Default value: `1000`
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
/// Default value: `72` (12 hours at an average of 6 blocks/hour)
///
/// Minimum value: [`MIN_CLTV_EXPIRY_DELTA`] (Any values less than this will be treated as
///                [`MIN_CLTV_EXPIRY_DELTA`] instead.)
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
/// Default value: `72` (12 hours at an average of 6 blocks/hour)
///
/// Minimum value: [`MIN_CLTV_EXPIRY_DELTA`] (Any values less than this will be treated as
///                [`MIN_CLTV_EXPIRY_DELTA`] instead.)
///
/// [`MIN_CLTV_EXPIRY_DELTA`]: crate::ln::channelmanager::MIN_CLTV_EXPIRY_DELTA
#[no_mangle]
pub extern "C" fn ChannelConfig_set_cltv_expiry_delta(this_ptr: &mut ChannelConfig, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Limit our total exposure to potential loss to on-chain fees on close, including in-flight
/// HTLCs which are burned to fees as they are too small to claim on-chain and fees on
/// commitment transaction(s) broadcasted by our counterparty in excess of our own fee estimate.
///
/// # HTLC-based Dust Exposure
///
/// When an HTLC present in one of our channels is below a \"dust\" threshold, the HTLC will
/// not be claimable on-chain, instead being turned into additional miner fees if either
/// party force-closes the channel. Because the threshold is per-HTLC, our total exposure
/// to such payments may be substantial if there are many dust HTLCs present when the
/// channel is force-closed.
///
/// The dust threshold for each HTLC is based on the `dust_limit_satoshis` for each party in a
/// channel negotiated throughout the channel open process, along with the fees required to have
/// a broadcastable HTLC spending transaction. When a channel supports anchor outputs
/// (specifically the zero fee HTLC transaction variant), this threshold no longer takes into
/// account the HTLC transaction fee as it is zero. Because of this, you may want to set this
/// value to a fixed limit for channels using anchor outputs, while the fee rate multiplier
/// variant is primarily intended for use with pre-anchor channels.
///
/// The selected limit is applied for sent, forwarded, and received HTLCs and limits the total
/// exposure across all three types per-channel.
///
/// # Transaction Fee Dust Exposure
///
/// Further, counterparties broadcasting a commitment transaction in a force-close may result
/// in other balance being burned to fees, and thus all fees on commitment and HTLC
/// transactions in excess of our local fee estimates are included in the dust calculation.
///
/// Because of this, another way to look at this limit is to divide it by 43,000 (or 218,750
/// for non-anchor channels) and see it as the maximum feerate disagreement (in sats/vB) per
/// non-dust HTLC we're allowed to have with our peers before risking a force-closure for
/// inbound channels.
///
/// Thus, for the default value of 10_000 * a current feerate estimate of 10 sat/vB (or 2,500
/// sat/KW), we risk force-closure if we disagree with our peer by:
/// * `10_000 * 2_500 / 43_000 / (483*2)` = 0.6 sat/vB for anchor channels with 483 HTLCs in
///   both directions (the maximum),
/// * `10_000 * 2_500 / 43_000 / (50*2)` = 5.8 sat/vB for anchor channels with 50 HTLCs in both
///   directions (the LDK default max from [`ChannelHandshakeConfig::our_max_accepted_htlcs`])
/// * `10_000 * 2_500 / 218_750 / (483*2)` = 0.1 sat/vB for non-anchor channels with 483 HTLCs
///   in both directions (the maximum),
/// * `10_000 * 2_500 / 218_750 / (50*2)` = 1.1 sat/vB for non-anchor channels with 50 HTLCs
///   in both (the LDK default maximum from [`ChannelHandshakeConfig::our_max_accepted_htlcs`])
///
/// Note that when using [`MaxDustHTLCExposure::FeeRateMultiplier`] this maximum disagreement
/// will scale linearly with increases (or decreases) in the our feerate estimates. Further,
/// for anchor channels we expect our counterparty to use a relatively low feerate estimate
/// while we use [`ConfirmationTarget::MaximumFeeEstimate`] (which should be relatively high)
/// and feerate disagreement force-closures should only occur when theirs is higher than ours.
///
/// Default value: [`MaxDustHTLCExposure::FeeRateMultiplier`] with a multiplier of `10_000`
///
/// [`ConfirmationTarget::MaximumFeeEstimate`]: crate::chain::chaininterface::ConfirmationTarget::MaximumFeeEstimate
#[no_mangle]
pub extern "C" fn ChannelConfig_get_max_dust_htlc_exposure(this_ptr: &ChannelConfig) -> crate::lightning::util::config::MaxDustHTLCExposure {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_dust_htlc_exposure;
	crate::lightning::util::config::MaxDustHTLCExposure::from_native(inner_val)
}
/// Limit our total exposure to potential loss to on-chain fees on close, including in-flight
/// HTLCs which are burned to fees as they are too small to claim on-chain and fees on
/// commitment transaction(s) broadcasted by our counterparty in excess of our own fee estimate.
///
/// # HTLC-based Dust Exposure
///
/// When an HTLC present in one of our channels is below a \"dust\" threshold, the HTLC will
/// not be claimable on-chain, instead being turned into additional miner fees if either
/// party force-closes the channel. Because the threshold is per-HTLC, our total exposure
/// to such payments may be substantial if there are many dust HTLCs present when the
/// channel is force-closed.
///
/// The dust threshold for each HTLC is based on the `dust_limit_satoshis` for each party in a
/// channel negotiated throughout the channel open process, along with the fees required to have
/// a broadcastable HTLC spending transaction. When a channel supports anchor outputs
/// (specifically the zero fee HTLC transaction variant), this threshold no longer takes into
/// account the HTLC transaction fee as it is zero. Because of this, you may want to set this
/// value to a fixed limit for channels using anchor outputs, while the fee rate multiplier
/// variant is primarily intended for use with pre-anchor channels.
///
/// The selected limit is applied for sent, forwarded, and received HTLCs and limits the total
/// exposure across all three types per-channel.
///
/// # Transaction Fee Dust Exposure
///
/// Further, counterparties broadcasting a commitment transaction in a force-close may result
/// in other balance being burned to fees, and thus all fees on commitment and HTLC
/// transactions in excess of our local fee estimates are included in the dust calculation.
///
/// Because of this, another way to look at this limit is to divide it by 43,000 (or 218,750
/// for non-anchor channels) and see it as the maximum feerate disagreement (in sats/vB) per
/// non-dust HTLC we're allowed to have with our peers before risking a force-closure for
/// inbound channels.
///
/// Thus, for the default value of 10_000 * a current feerate estimate of 10 sat/vB (or 2,500
/// sat/KW), we risk force-closure if we disagree with our peer by:
/// * `10_000 * 2_500 / 43_000 / (483*2)` = 0.6 sat/vB for anchor channels with 483 HTLCs in
///   both directions (the maximum),
/// * `10_000 * 2_500 / 43_000 / (50*2)` = 5.8 sat/vB for anchor channels with 50 HTLCs in both
///   directions (the LDK default max from [`ChannelHandshakeConfig::our_max_accepted_htlcs`])
/// * `10_000 * 2_500 / 218_750 / (483*2)` = 0.1 sat/vB for non-anchor channels with 483 HTLCs
///   in both directions (the maximum),
/// * `10_000 * 2_500 / 218_750 / (50*2)` = 1.1 sat/vB for non-anchor channels with 50 HTLCs
///   in both (the LDK default maximum from [`ChannelHandshakeConfig::our_max_accepted_htlcs`])
///
/// Note that when using [`MaxDustHTLCExposure::FeeRateMultiplier`] this maximum disagreement
/// will scale linearly with increases (or decreases) in the our feerate estimates. Further,
/// for anchor channels we expect our counterparty to use a relatively low feerate estimate
/// while we use [`ConfirmationTarget::MaximumFeeEstimate`] (which should be relatively high)
/// and feerate disagreement force-closures should only occur when theirs is higher than ours.
///
/// Default value: [`MaxDustHTLCExposure::FeeRateMultiplier`] with a multiplier of `10_000`
///
/// [`ConfirmationTarget::MaximumFeeEstimate`]: crate::chain::chaininterface::ConfirmationTarget::MaximumFeeEstimate
#[no_mangle]
pub extern "C" fn ChannelConfig_set_max_dust_htlc_exposure(this_ptr: &mut ChannelConfig, mut val: crate::lightning::util::config::MaxDustHTLCExposure) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_dust_htlc_exposure = val.into_native();
}
/// The additional fee we're willing to pay to avoid waiting for the counterparty's
/// `to_self_delay` to reclaim funds.
///
/// When we close a channel cooperatively with our counterparty, we negotiate a fee for the
/// closing transaction which both sides find acceptable, ultimately paid by the channel
/// funder/initiator.
///
/// When we are the funder, because we have to pay the channel closing fee, we bound the
/// acceptable fee by our [`ChannelCloseMinimum`] and [`NonAnchorChannelFee`] fees, with the upper bound increased by
/// this value. Because the on-chain fee we'd pay to force-close the channel is kept near our
/// [`NonAnchorChannelFee`] feerate during normal operation, this value represents the additional fee we're
/// willing to pay in order to avoid waiting for our counterparty's to_self_delay to reclaim our
/// funds.
///
/// When we are not the funder, we require the closing transaction fee pay at least our
/// [`ChannelCloseMinimum`] fee estimate, but allow our counterparty to pay as much fee as they like.
/// Thus, this value is ignored when we are not the funder.
///
/// Default value: `1000`
///
/// [`NonAnchorChannelFee`]: crate::chain::chaininterface::ConfirmationTarget::NonAnchorChannelFee
/// [`ChannelCloseMinimum`]: crate::chain::chaininterface::ConfirmationTarget::ChannelCloseMinimum
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
/// acceptable fee by our [`ChannelCloseMinimum`] and [`NonAnchorChannelFee`] fees, with the upper bound increased by
/// this value. Because the on-chain fee we'd pay to force-close the channel is kept near our
/// [`NonAnchorChannelFee`] feerate during normal operation, this value represents the additional fee we're
/// willing to pay in order to avoid waiting for our counterparty's to_self_delay to reclaim our
/// funds.
///
/// When we are not the funder, we require the closing transaction fee pay at least our
/// [`ChannelCloseMinimum`] fee estimate, but allow our counterparty to pay as much fee as they like.
/// Thus, this value is ignored when we are not the funder.
///
/// Default value: `1000`
///
/// [`NonAnchorChannelFee`]: crate::chain::chaininterface::ConfirmationTarget::NonAnchorChannelFee
/// [`ChannelCloseMinimum`]: crate::chain::chaininterface::ConfirmationTarget::ChannelCloseMinimum
#[no_mangle]
pub extern "C" fn ChannelConfig_set_force_close_avoidance_max_fee_satoshis(this_ptr: &mut ChannelConfig, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.force_close_avoidance_max_fee_satoshis = val;
}
/// If set, allows this channel's counterparty to skim an additional fee off this node's inbound
/// HTLCs. Useful for liquidity providers to offload on-chain channel costs to end users.
///
/// Usage:
/// - The payee will set this option and set its invoice route hints to use [intercept scids]
///   generated by this channel's counterparty.
/// - The counterparty will get an [`HTLCIntercepted`] event upon payment forward, and call
///   [`forward_intercepted_htlc`] with less than the amount provided in
///   [`HTLCIntercepted::expected_outbound_amount_msat`]. The difference between the expected and
///   actual forward amounts is their fee. See
///   <https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2#flow-lsp-trusts-client-model>
///   for how this feature may be used in the LSP use case.
///
/// # Note
/// It's important for payee wallet software to verify that [`PaymentClaimable::amount_msat`] is
/// as-expected if this feature is activated, otherwise they may lose money!
/// [`PaymentClaimable::counterparty_skimmed_fee_msat`] provides the fee taken by the
/// counterparty.
///
/// # Note
/// Switching this config flag on may break compatibility with versions of LDK prior to 0.0.116.
/// Unsetting this flag between restarts may lead to payment receive failures.
///
/// Default value: `false`
///
/// [intercept scids]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
/// [`forward_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::forward_intercepted_htlc
/// [`HTLCIntercepted`]: crate::events::Event::HTLCIntercepted
/// [`HTLCIntercepted::expected_outbound_amount_msat`]: crate::events::Event::HTLCIntercepted::expected_outbound_amount_msat
/// [`PaymentClaimable::amount_msat`]: crate::events::Event::PaymentClaimable::amount_msat
/// [`PaymentClaimable::counterparty_skimmed_fee_msat`]: crate::events::Event::PaymentClaimable::counterparty_skimmed_fee_msat
#[no_mangle]
pub extern "C" fn ChannelConfig_get_accept_underpaying_htlcs(this_ptr: &ChannelConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().accept_underpaying_htlcs;
	*inner_val
}
/// If set, allows this channel's counterparty to skim an additional fee off this node's inbound
/// HTLCs. Useful for liquidity providers to offload on-chain channel costs to end users.
///
/// Usage:
/// - The payee will set this option and set its invoice route hints to use [intercept scids]
///   generated by this channel's counterparty.
/// - The counterparty will get an [`HTLCIntercepted`] event upon payment forward, and call
///   [`forward_intercepted_htlc`] with less than the amount provided in
///   [`HTLCIntercepted::expected_outbound_amount_msat`]. The difference between the expected and
///   actual forward amounts is their fee. See
///   <https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2#flow-lsp-trusts-client-model>
///   for how this feature may be used in the LSP use case.
///
/// # Note
/// It's important for payee wallet software to verify that [`PaymentClaimable::amount_msat`] is
/// as-expected if this feature is activated, otherwise they may lose money!
/// [`PaymentClaimable::counterparty_skimmed_fee_msat`] provides the fee taken by the
/// counterparty.
///
/// # Note
/// Switching this config flag on may break compatibility with versions of LDK prior to 0.0.116.
/// Unsetting this flag between restarts may lead to payment receive failures.
///
/// Default value: `false`
///
/// [intercept scids]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
/// [`forward_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::forward_intercepted_htlc
/// [`HTLCIntercepted`]: crate::events::Event::HTLCIntercepted
/// [`HTLCIntercepted::expected_outbound_amount_msat`]: crate::events::Event::HTLCIntercepted::expected_outbound_amount_msat
/// [`PaymentClaimable::amount_msat`]: crate::events::Event::PaymentClaimable::amount_msat
/// [`PaymentClaimable::counterparty_skimmed_fee_msat`]: crate::events::Event::PaymentClaimable::counterparty_skimmed_fee_msat
#[no_mangle]
pub extern "C" fn ChannelConfig_set_accept_underpaying_htlcs(this_ptr: &mut ChannelConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.accept_underpaying_htlcs = val;
}
/// Constructs a new ChannelConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelConfig_new(mut forwarding_fee_proportional_millionths_arg: u32, mut forwarding_fee_base_msat_arg: u32, mut cltv_expiry_delta_arg: u16, mut max_dust_htlc_exposure_arg: crate::lightning::util::config::MaxDustHTLCExposure, mut force_close_avoidance_max_fee_satoshis_arg: u64, mut accept_underpaying_htlcs_arg: bool) -> ChannelConfig {
	ChannelConfig { inner: ObjOps::heap_alloc(nativeChannelConfig {
		forwarding_fee_proportional_millionths: forwarding_fee_proportional_millionths_arg,
		forwarding_fee_base_msat: forwarding_fee_base_msat_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
		max_dust_htlc_exposure: max_dust_htlc_exposure_arg.into_native(),
		force_close_avoidance_max_fee_satoshis: force_close_avoidance_max_fee_satoshis_arg,
		accept_underpaying_htlcs: accept_underpaying_htlcs_arg,
	}), is_owned: true }
}
impl Clone for ChannelConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelConfig>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelConfig
pub extern "C" fn ChannelConfig_clone(orig: &ChannelConfig) -> ChannelConfig {
	orig.clone()
}
/// Get a string which allows debug introspection of a ChannelConfig object
pub extern "C" fn ChannelConfig_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::config::ChannelConfig }).into()}
/// Checks if two ChannelConfigs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelConfig_eq(a: &ChannelConfig, b: &ChannelConfig) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Applies the given [`ChannelConfigUpdate`] as a partial update to the [`ChannelConfig`].
#[no_mangle]
pub extern "C" fn ChannelConfig_apply(this_arg: &mut crate::lightning::util::config::ChannelConfig, update: &crate::lightning::util::config::ChannelConfigUpdate) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::util::config::nativeChannelConfig)) }.apply(update.get_native_ref())
}

/// Creates a "default" ChannelConfig. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelConfig_default() -> ChannelConfig {
	ChannelConfig { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
#[no_mangle]
/// Serialize the ChannelConfig object into a byte array which can be read by ChannelConfig_read
pub extern "C" fn ChannelConfig_write(obj: &crate::lightning::util::config::ChannelConfig) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelConfig_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::util::config::nativeChannelConfig) })
}
#[no_mangle]
/// Read a ChannelConfig from a byte array, created by ChannelConfig_write
pub extern "C" fn ChannelConfig_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelConfigDecodeErrorZ {
	let res: Result<lightning::util::config::ChannelConfig, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::config::ChannelConfig { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::util::config::ChannelConfigUpdate as nativeChannelConfigUpdateImport;
pub(crate) type nativeChannelConfigUpdate = nativeChannelConfigUpdateImport;

/// A parallel struct to [`ChannelConfig`] to define partial updates.
#[must_use]
#[repr(C)]
pub struct ChannelConfigUpdate {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelConfigUpdate,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ChannelConfigUpdate {
	type Target = nativeChannelConfigUpdate;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ChannelConfigUpdate { }
unsafe impl core::marker::Sync for ChannelConfigUpdate { }
impl Drop for ChannelConfigUpdate {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelConfigUpdate>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelConfigUpdate, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_free(this_obj: ChannelConfigUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelConfigUpdate_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelConfigUpdate) };
}
#[allow(unused)]
impl ChannelConfigUpdate {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelConfigUpdate {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelConfigUpdate {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelConfigUpdate {
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
pub extern "C" fn ChannelConfigUpdate_get_forwarding_fee_proportional_millionths(this_ptr: &ChannelConfigUpdate) -> crate::c_types::derived::COption_u32Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().forwarding_fee_proportional_millionths;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_set_forwarding_fee_proportional_millionths(this_ptr: &mut ChannelConfigUpdate, mut val: crate::c_types::derived::COption_u32Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.forwarding_fee_proportional_millionths = local_val;
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_get_forwarding_fee_base_msat(this_ptr: &ChannelConfigUpdate) -> crate::c_types::derived::COption_u32Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().forwarding_fee_base_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_set_forwarding_fee_base_msat(this_ptr: &mut ChannelConfigUpdate, mut val: crate::c_types::derived::COption_u32Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.forwarding_fee_base_msat = local_val;
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_get_cltv_expiry_delta(this_ptr: &ChannelConfigUpdate) -> crate::c_types::derived::COption_u16Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u16Z::None } else { crate::c_types::derived::COption_u16Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_set_cltv_expiry_delta(this_ptr: &mut ChannelConfigUpdate, mut val: crate::c_types::derived::COption_u16Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = local_val;
}
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_get_max_dust_htlc_exposure_msat(this_ptr: &ChannelConfigUpdate) -> crate::c_types::derived::COption_MaxDustHTLCExposureZ {
	let mut inner_val = this_ptr.get_native_mut_ref().max_dust_htlc_exposure_msat.clone();
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_MaxDustHTLCExposureZ::None } else { crate::c_types::derived::COption_MaxDustHTLCExposureZ::Some( { crate::lightning::util::config::MaxDustHTLCExposure::native_into(inner_val.unwrap()) }) };
	local_inner_val
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_set_max_dust_htlc_exposure_msat(this_ptr: &mut ChannelConfigUpdate, mut val: crate::c_types::derived::COption_MaxDustHTLCExposureZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_native() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_dust_htlc_exposure_msat = local_val;
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_get_force_close_avoidance_max_fee_satoshis(this_ptr: &ChannelConfigUpdate) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().force_close_avoidance_max_fee_satoshis;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_set_force_close_avoidance_max_fee_satoshis(this_ptr: &mut ChannelConfigUpdate, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.force_close_avoidance_max_fee_satoshis = local_val;
}
/// Constructs a new ChannelConfigUpdate given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelConfigUpdate_new(mut forwarding_fee_proportional_millionths_arg: crate::c_types::derived::COption_u32Z, mut forwarding_fee_base_msat_arg: crate::c_types::derived::COption_u32Z, mut cltv_expiry_delta_arg: crate::c_types::derived::COption_u16Z, mut max_dust_htlc_exposure_msat_arg: crate::c_types::derived::COption_MaxDustHTLCExposureZ, mut force_close_avoidance_max_fee_satoshis_arg: crate::c_types::derived::COption_u64Z) -> ChannelConfigUpdate {
	let mut local_forwarding_fee_proportional_millionths_arg = if forwarding_fee_proportional_millionths_arg.is_some() { Some( { forwarding_fee_proportional_millionths_arg.take() }) } else { None };
	let mut local_forwarding_fee_base_msat_arg = if forwarding_fee_base_msat_arg.is_some() { Some( { forwarding_fee_base_msat_arg.take() }) } else { None };
	let mut local_cltv_expiry_delta_arg = if cltv_expiry_delta_arg.is_some() { Some( { cltv_expiry_delta_arg.take() }) } else { None };
	let mut local_max_dust_htlc_exposure_msat_arg = { /*max_dust_htlc_exposure_msat_arg*/ let max_dust_htlc_exposure_msat_arg_opt = max_dust_htlc_exposure_msat_arg; if max_dust_htlc_exposure_msat_arg_opt.is_none() { None } else { Some({ { { max_dust_htlc_exposure_msat_arg_opt.take() }.into_native() }})} };
	let mut local_force_close_avoidance_max_fee_satoshis_arg = if force_close_avoidance_max_fee_satoshis_arg.is_some() { Some( { force_close_avoidance_max_fee_satoshis_arg.take() }) } else { None };
	ChannelConfigUpdate { inner: ObjOps::heap_alloc(nativeChannelConfigUpdate {
		forwarding_fee_proportional_millionths: local_forwarding_fee_proportional_millionths_arg,
		forwarding_fee_base_msat: local_forwarding_fee_base_msat_arg,
		cltv_expiry_delta: local_cltv_expiry_delta_arg,
		max_dust_htlc_exposure_msat: local_max_dust_htlc_exposure_msat_arg,
		force_close_avoidance_max_fee_satoshis: local_force_close_avoidance_max_fee_satoshis_arg,
	}), is_owned: true }
}

use lightning::util::config::UserConfig as nativeUserConfigImport;
pub(crate) type nativeUserConfig = nativeUserConfigImport;

/// Top-level config which holds ChannelHandshakeLimits and ChannelConfig.
///
/// `Default::default()` provides sane defaults for most configurations
/// (but currently with zero relay fees!)
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

impl core::ops::Deref for UserConfig {
	type Target = nativeUserConfig;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for UserConfig { }
unsafe impl core::marker::Sync for UserConfig { }
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUserConfig) };
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
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Channel handshake config that we propose to our counterparty.
#[no_mangle]
pub extern "C" fn UserConfig_get_channel_handshake_config(this_ptr: &UserConfig) -> crate::lightning::util::config::ChannelHandshakeConfig {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_handshake_config;
	crate::lightning::util::config::ChannelHandshakeConfig { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::config::ChannelHandshakeConfig<>) as *mut _) }, is_owned: false }
}
/// Channel handshake config that we propose to our counterparty.
#[no_mangle]
pub extern "C" fn UserConfig_set_channel_handshake_config(this_ptr: &mut UserConfig, mut val: crate::lightning::util::config::ChannelHandshakeConfig) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_handshake_config = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Limits applied to our counterparty's proposed channel handshake config settings.
#[no_mangle]
pub extern "C" fn UserConfig_get_channel_handshake_limits(this_ptr: &UserConfig) -> crate::lightning::util::config::ChannelHandshakeLimits {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_handshake_limits;
	crate::lightning::util::config::ChannelHandshakeLimits { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::config::ChannelHandshakeLimits<>) as *mut _) }, is_owned: false }
}
/// Limits applied to our counterparty's proposed channel handshake config settings.
#[no_mangle]
pub extern "C" fn UserConfig_set_channel_handshake_limits(this_ptr: &mut UserConfig, mut val: crate::lightning::util::config::ChannelHandshakeLimits) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_handshake_limits = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Channel config which affects behavior during channel lifetime.
#[no_mangle]
pub extern "C" fn UserConfig_get_channel_config(this_ptr: &UserConfig) -> crate::lightning::util::config::ChannelConfig {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_config;
	crate::lightning::util::config::ChannelConfig { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::config::ChannelConfig<>) as *mut _) }, is_owned: false }
}
/// Channel config which affects behavior during channel lifetime.
#[no_mangle]
pub extern "C" fn UserConfig_set_channel_config(this_ptr: &mut UserConfig, mut val: crate::lightning::util::config::ChannelConfig) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_config = *unsafe { Box::from_raw(val.take_inner()) };
}
/// If this is set to `false`, we will reject any HTLCs which were to be forwarded over private
/// channels. This prevents us from taking on HTLC-forwarding risk when we intend to run as a
/// node which is not online reliably.
///
/// For nodes which are not online reliably, you should set all channels to *not* be announced
/// (using [`ChannelHandshakeConfig::announce_for_forwarding`] and
/// [`ChannelHandshakeLimits::force_announced_channel_preference`]) and set this to `false` to
/// ensure you are not exposed to any forwarding risk.
///
/// Note that because you cannot change a channel's announced state after creation, there is no
/// way to disable forwarding on public channels retroactively. Thus, in order to change a node
/// from a publicly-announced forwarding node to a private non-forwarding node you must close
/// all your channels and open new ones. For privacy, you should also change your node_id
/// (swapping all private and public key material for new ones) at that time.
///
/// Default value: `false`
#[no_mangle]
pub extern "C" fn UserConfig_get_accept_forwards_to_priv_channels(this_ptr: &UserConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().accept_forwards_to_priv_channels;
	*inner_val
}
/// If this is set to `false`, we will reject any HTLCs which were to be forwarded over private
/// channels. This prevents us from taking on HTLC-forwarding risk when we intend to run as a
/// node which is not online reliably.
///
/// For nodes which are not online reliably, you should set all channels to *not* be announced
/// (using [`ChannelHandshakeConfig::announce_for_forwarding`] and
/// [`ChannelHandshakeLimits::force_announced_channel_preference`]) and set this to `false` to
/// ensure you are not exposed to any forwarding risk.
///
/// Note that because you cannot change a channel's announced state after creation, there is no
/// way to disable forwarding on public channels retroactively. Thus, in order to change a node
/// from a publicly-announced forwarding node to a private non-forwarding node you must close
/// all your channels and open new ones. For privacy, you should also change your node_id
/// (swapping all private and public key material for new ones) at that time.
///
/// Default value: `false`
#[no_mangle]
pub extern "C" fn UserConfig_set_accept_forwards_to_priv_channels(this_ptr: &mut UserConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.accept_forwards_to_priv_channels = val;
}
/// If this is set to `false`, we do not accept inbound requests to open a new channel.
///
/// Default value: `true`
#[no_mangle]
pub extern "C" fn UserConfig_get_accept_inbound_channels(this_ptr: &UserConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().accept_inbound_channels;
	*inner_val
}
/// If this is set to `false`, we do not accept inbound requests to open a new channel.
///
/// Default value: `true`
#[no_mangle]
pub extern "C" fn UserConfig_set_accept_inbound_channels(this_ptr: &mut UserConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.accept_inbound_channels = val;
}
/// If this is set to `true`, the user needs to manually accept inbound requests to open a new
/// channel.
///
/// When set to `true`, [`Event::OpenChannelRequest`] will be triggered once a request to open a
/// new inbound channel is received through a [`msgs::OpenChannel`] message. In that case, a
/// [`msgs::AcceptChannel`] message will not be sent back to the counterparty node unless the
/// user explicitly chooses to accept the request.
///
/// Default value: `false`
///
/// [`Event::OpenChannelRequest`]: crate::events::Event::OpenChannelRequest
/// [`msgs::OpenChannel`]: crate::ln::msgs::OpenChannel
/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
#[no_mangle]
pub extern "C" fn UserConfig_get_manually_accept_inbound_channels(this_ptr: &UserConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().manually_accept_inbound_channels;
	*inner_val
}
/// If this is set to `true`, the user needs to manually accept inbound requests to open a new
/// channel.
///
/// When set to `true`, [`Event::OpenChannelRequest`] will be triggered once a request to open a
/// new inbound channel is received through a [`msgs::OpenChannel`] message. In that case, a
/// [`msgs::AcceptChannel`] message will not be sent back to the counterparty node unless the
/// user explicitly chooses to accept the request.
///
/// Default value: `false`
///
/// [`Event::OpenChannelRequest`]: crate::events::Event::OpenChannelRequest
/// [`msgs::OpenChannel`]: crate::ln::msgs::OpenChannel
/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
#[no_mangle]
pub extern "C" fn UserConfig_set_manually_accept_inbound_channels(this_ptr: &mut UserConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.manually_accept_inbound_channels = val;
}
///  If this is set to `true`, LDK will intercept HTLCs that are attempting to be forwarded over
///  fake short channel ids generated via [`ChannelManager::get_intercept_scid`]. Upon HTLC
///  intercept, LDK will generate an [`Event::HTLCIntercepted`] which MUST be handled by the user.
///
///  Setting this to `true` may break backwards compatibility with LDK versions < 0.0.113.
///
///  Default value: `false`
///
/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
/// [`Event::HTLCIntercepted`]: crate::events::Event::HTLCIntercepted
#[no_mangle]
pub extern "C" fn UserConfig_get_accept_intercept_htlcs(this_ptr: &UserConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().accept_intercept_htlcs;
	*inner_val
}
///  If this is set to `true`, LDK will intercept HTLCs that are attempting to be forwarded over
///  fake short channel ids generated via [`ChannelManager::get_intercept_scid`]. Upon HTLC
///  intercept, LDK will generate an [`Event::HTLCIntercepted`] which MUST be handled by the user.
///
///  Setting this to `true` may break backwards compatibility with LDK versions < 0.0.113.
///
///  Default value: `false`
///
/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
/// [`Event::HTLCIntercepted`]: crate::events::Event::HTLCIntercepted
#[no_mangle]
pub extern "C" fn UserConfig_set_accept_intercept_htlcs(this_ptr: &mut UserConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.accept_intercept_htlcs = val;
}
/// If this is set to `false`, when receiving a keysend payment we'll fail it if it has multiple
/// parts. If this is set to `true`, we'll accept the payment.
///
/// Setting this to `true` will break backwards compatibility upon downgrading to an LDK
/// version prior to 0.0.116 while receiving an MPP keysend. If we have already received an MPP
/// keysend, downgrading will cause us to fail to deserialize [`ChannelManager`].
///
/// Default value: `false`
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
#[no_mangle]
pub extern "C" fn UserConfig_get_accept_mpp_keysend(this_ptr: &UserConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().accept_mpp_keysend;
	*inner_val
}
/// If this is set to `false`, when receiving a keysend payment we'll fail it if it has multiple
/// parts. If this is set to `true`, we'll accept the payment.
///
/// Setting this to `true` will break backwards compatibility upon downgrading to an LDK
/// version prior to 0.0.116 while receiving an MPP keysend. If we have already received an MPP
/// keysend, downgrading will cause us to fail to deserialize [`ChannelManager`].
///
/// Default value: `false`
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
#[no_mangle]
pub extern "C" fn UserConfig_set_accept_mpp_keysend(this_ptr: &mut UserConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.accept_mpp_keysend = val;
}
/// If this is set to `true`, the user needs to manually pay [`Bolt12Invoice`]s when received.
///
/// When set to `true`, [`Event::InvoiceReceived`] will be generated for each received
/// [`Bolt12Invoice`] instead of being automatically paid after verification. Use
/// [`ChannelManager::send_payment_for_bolt12_invoice`] to pay the invoice or
/// [`ChannelManager::abandon_payment`] to abandon the associated payment.
///
/// Default value: `false`
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Event::InvoiceReceived`]: crate::events::Event::InvoiceReceived
/// [`ChannelManager::send_payment_for_bolt12_invoice`]: crate::ln::channelmanager::ChannelManager::send_payment_for_bolt12_invoice
/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
#[no_mangle]
pub extern "C" fn UserConfig_get_manually_handle_bolt12_invoices(this_ptr: &UserConfig) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().manually_handle_bolt12_invoices;
	*inner_val
}
/// If this is set to `true`, the user needs to manually pay [`Bolt12Invoice`]s when received.
///
/// When set to `true`, [`Event::InvoiceReceived`] will be generated for each received
/// [`Bolt12Invoice`] instead of being automatically paid after verification. Use
/// [`ChannelManager::send_payment_for_bolt12_invoice`] to pay the invoice or
/// [`ChannelManager::abandon_payment`] to abandon the associated payment.
///
/// Default value: `false`
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Event::InvoiceReceived`]: crate::events::Event::InvoiceReceived
/// [`ChannelManager::send_payment_for_bolt12_invoice`]: crate::ln::channelmanager::ChannelManager::send_payment_for_bolt12_invoice
/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
#[no_mangle]
pub extern "C" fn UserConfig_set_manually_handle_bolt12_invoices(this_ptr: &mut UserConfig, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.manually_handle_bolt12_invoices = val;
}
/// Constructs a new UserConfig given each field
#[must_use]
#[no_mangle]
pub extern "C" fn UserConfig_new(mut channel_handshake_config_arg: crate::lightning::util::config::ChannelHandshakeConfig, mut channel_handshake_limits_arg: crate::lightning::util::config::ChannelHandshakeLimits, mut channel_config_arg: crate::lightning::util::config::ChannelConfig, mut accept_forwards_to_priv_channels_arg: bool, mut accept_inbound_channels_arg: bool, mut manually_accept_inbound_channels_arg: bool, mut accept_intercept_htlcs_arg: bool, mut accept_mpp_keysend_arg: bool, mut manually_handle_bolt12_invoices_arg: bool) -> UserConfig {
	UserConfig { inner: ObjOps::heap_alloc(nativeUserConfig {
		channel_handshake_config: *unsafe { Box::from_raw(channel_handshake_config_arg.take_inner()) },
		channel_handshake_limits: *unsafe { Box::from_raw(channel_handshake_limits_arg.take_inner()) },
		channel_config: *unsafe { Box::from_raw(channel_config_arg.take_inner()) },
		accept_forwards_to_priv_channels: accept_forwards_to_priv_channels_arg,
		accept_inbound_channels: accept_inbound_channels_arg,
		manually_accept_inbound_channels: manually_accept_inbound_channels_arg,
		accept_intercept_htlcs: accept_intercept_htlcs_arg,
		accept_mpp_keysend: accept_mpp_keysend_arg,
		manually_handle_bolt12_invoices: manually_handle_bolt12_invoices_arg,
	}), is_owned: true }
}
impl Clone for UserConfig {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUserConfig>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UserConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUserConfig)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UserConfig
pub extern "C" fn UserConfig_clone(orig: &UserConfig) -> UserConfig {
	orig.clone()
}
/// Get a string which allows debug introspection of a UserConfig object
pub extern "C" fn UserConfig_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::config::UserConfig }).into()}
/// Creates a "default" UserConfig. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn UserConfig_default() -> UserConfig {
	UserConfig { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
