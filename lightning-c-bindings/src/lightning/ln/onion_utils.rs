// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Low-level onion manipulation logic and fields

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod fuzzy_onion_utils {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
/// The reason that a HTLC was failed by the local node. These errors either represent direct,
/// human-readable mappings of BOLT04 error codes or provide additional information that would
/// otherwise be erased by the BOLT04 error code.
///
/// For example:
/// [`Self::FeeInsufficient`] is a direct representation of its underlying BOLT04 error code.
/// [`Self::PrivateChannelForward`] provides additional information that is not provided by its
///  BOLT04 error code.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LocalHTLCFailureReason {
	/// There has been a temporary processing failure on the node which may resolve on retry.
	TemporaryNodeFailure,
	/// These has been a permanent processing failure on the node which will not resolve on retry.
	PermanentNodeFailure,
	/// The HTLC does not implement a feature that is required by our node.
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	RequiredNodeFeature,
	/// The onion version specified by the HTLC packet is unknown to our node.
	InvalidOnionVersion,
	/// The integrity of the HTLC packet cannot be verified because it has an invalid HMAC.
	InvalidOnionHMAC,
	/// The onion packet has an invalid ephemeral key, so the HTLC cannot be processed.
	InvalidOnionKey,
	/// A temporary forwarding error has occurred which may resolve on retry.
	TemporaryChannelFailure,
	/// A permanent forwarding error has occurred which will not resolve on retry.
	PermanentChannelFailure,
	/// The HTLC does not implement a feature that is required by our channel for processing.
	RequiredChannelFeature,
	/// The HTLC's target outgoing channel that is not known to our node.
	UnknownNextPeer,
	/// The HTLC amount is below our advertised htlc_minimum_msat.
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	AmountBelowMinimum,
	/// The HTLC does not pay sufficient fees.
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	FeeInsufficient,
	/// The HTLC does not meet the cltv_expiry_delta advertised by our node, set by
	/// [`ChannelConfig::cltv_expiry_delta`].
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	///
	/// [`ChannelConfig::cltv_expiry_delta`]: crate::util::config::ChannelConfig::cltv_expiry_delta
	IncorrectCLTVExpiry,
	/// The HTLC expires too close to the current block height to be safely processed.
	CLTVExpiryTooSoon,
	/// A payment was made to our node that either had incorrect payment information, or was
	/// unknown to us.
	IncorrectPaymentDetails,
	/// The HTLC's expiry is less than the expiry height specified by the sender.
	///
	/// The forwarding node has either tampered with this value, or the sending node has an
	/// old best block height.
	FinalIncorrectCLTVExpiry,
	/// The HTLC's amount is less than the amount specified by the sender.
	///
	/// The forwarding node has tampered with this value, or has a bug in its implementation.
	FinalIncorrectHTLCAmount,
	/// The channel has been marked as disabled because the channel peer is offline.
	ChannelDisabled,
	/// The HTLC expires too far in the future, so it is rejected to avoid the worst-case outcome
	/// of funds being held for extended periods of time.
	///
	CLTVExpiryTooFar,
	/// The HTLC payload contained in the onion packet could not be understood by our node.
	InvalidOnionPayload,
	/// The total amount for a multi-part payment did not arrive in time, so the HTLCs partially
	/// paying the amount were canceled.
	MPPTimeout,
	/// Our node was selected as part of a blinded path, but the packet we received was not
	/// properly constructed, or had incorrect values for the blinded path.
	///
	/// This may happen if the forwarding node tamperd with the HTLC or the sender or recipient
	/// implementations have a bug.
	InvalidOnionBlinding,
	/// UnknownFailureCode represents BOLT04 failure codes that we are not familiar with. We will
	/// encounter this if:
	/// - A peer sends us a new failure code that LDK has not yet been upgraded to understand.
	/// - We read a deprecated failure code from disk that LDK no longer uses.
	///
	/// See <https://github.com/lightning/bolts/blob/master/04-onion-routing.md#returning-errors>
	/// for latest defined error codes.
	UnknownFailureCode {
		/// The bolt 04 failure code.
		code: u16,
	},
	/// A HTLC forward was failed back rather than forwarded on the proposed outgoing channel
	/// because its expiry is too close to the current block height to leave time to safely claim
	/// it on chain if the channel force closes.
	ForwardExpiryBuffer,
	/// The HTLC was failed because it has invalid trampoline forwarding information.
	InvalidTrampolineForward,
	/// A HTLC receive was failed back rather than claimed because its expiry is too close to
	/// the current block height to leave time to safely claim it on chain if the channel force
	/// closes.
	PaymentClaimBuffer,
	/// The HTLC was failed because accepting it would push our commitment's total amount of dust
	/// HTLCs over the limit that we allow to be burned to miner fees if the channel closed while
	/// they are unresolved.
	DustLimitHolder,
	/// The HTLC was failed because accepting it would push our counterparty's total amount of
	/// dust (small) HTLCs over the limit that we allow to be burned to miner fees if the channel
	/// closes while they are unresolved.
	DustLimitCounterparty,
	/// The HTLC was failed because it would drop the remote party's channel balance such that it
	/// cannot cover the fees it is required to pay at various fee rates. This buffer is maintained
	/// so that channels can always maintain reasonable fee rates.
	FeeSpikeBuffer,
	/// The HTLC that requested to be forwarded over a private channel was rejected to prevent
	/// revealing the existence of the channel.
	PrivateChannelForward,
	/// The HTLC was failed because it made a request to forward over the real channel ID of a
	/// channel that implements `option_scid_alias` which is a privacy feature to prevent the
	/// real channel ID from being known.
	RealSCIDForward,
	/// The HTLC was rejected because our channel has not yet reached sufficient depth to be used.
	ChannelNotReady,
	/// A keysend payment with a preimage that did not match the HTLC has was rejected.
	InvalidKeysendPreimage,
	/// The HTLC was failed because it had an invalid trampoline payload.
	InvalidTrampolinePayload,
	/// A payment was rejected because it did not include the correct payment secret from an
	/// invoice.
	PaymentSecretRequired,
	/// The HTLC was failed because its expiry is too close to the current block height, and we
	/// expect that it will immediately be failed back by our downstream peer.
	OutgoingCLTVTooSoon,
	/// The HTLC was failed because it was pending on a channel which is now in the process of
	/// being closed.
	ChannelClosed,
	/// The HTLC was failed back because its expiry height was reached and funds were timed out
	/// on chain.
	OnChainTimeout,
	/// The HTLC was failed because zero amount HTLCs are not allowed.
	ZeroAmount,
	/// The HTLC was failed because its amount is less than the smallest HTLC that the channel
	/// can currently accept.
	///
	/// This may occur because the HTLC is smaller than the counterparty's advertised minimum
	/// accepted HTLC size, or if we have reached our maximum total dust HTLC exposure.
	HTLCMinimum,
	/// The HTLC was failed because its amount is more than then largest HTLC that the channel
	/// can currently accept.
	///
	/// This may occur because the outbound channel has insufficient liquidity to forward the HTLC,
	/// we have reached the counterparty's in-flight limits, or the HTLC exceeds our advertised
	/// maximum accepted HTLC size.
	HTLCMaximum,
	/// The HTLC was failed because our remote peer is offline.
	PeerOffline,
	/// The HTLC was failed because the channel balance was overdrawn.
	ChannelBalanceOverdrawn,
}
use lightning::ln::onion_utils::LocalHTLCFailureReason as LocalHTLCFailureReasonImport;
pub(crate) type nativeLocalHTLCFailureReason = LocalHTLCFailureReasonImport;

impl LocalHTLCFailureReason {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLocalHTLCFailureReason {
		match self {
			LocalHTLCFailureReason::TemporaryNodeFailure => nativeLocalHTLCFailureReason::TemporaryNodeFailure,
			LocalHTLCFailureReason::PermanentNodeFailure => nativeLocalHTLCFailureReason::PermanentNodeFailure,
			LocalHTLCFailureReason::RequiredNodeFeature => nativeLocalHTLCFailureReason::RequiredNodeFeature,
			LocalHTLCFailureReason::InvalidOnionVersion => nativeLocalHTLCFailureReason::InvalidOnionVersion,
			LocalHTLCFailureReason::InvalidOnionHMAC => nativeLocalHTLCFailureReason::InvalidOnionHMAC,
			LocalHTLCFailureReason::InvalidOnionKey => nativeLocalHTLCFailureReason::InvalidOnionKey,
			LocalHTLCFailureReason::TemporaryChannelFailure => nativeLocalHTLCFailureReason::TemporaryChannelFailure,
			LocalHTLCFailureReason::PermanentChannelFailure => nativeLocalHTLCFailureReason::PermanentChannelFailure,
			LocalHTLCFailureReason::RequiredChannelFeature => nativeLocalHTLCFailureReason::RequiredChannelFeature,
			LocalHTLCFailureReason::UnknownNextPeer => nativeLocalHTLCFailureReason::UnknownNextPeer,
			LocalHTLCFailureReason::AmountBelowMinimum => nativeLocalHTLCFailureReason::AmountBelowMinimum,
			LocalHTLCFailureReason::FeeInsufficient => nativeLocalHTLCFailureReason::FeeInsufficient,
			LocalHTLCFailureReason::IncorrectCLTVExpiry => nativeLocalHTLCFailureReason::IncorrectCLTVExpiry,
			LocalHTLCFailureReason::CLTVExpiryTooSoon => nativeLocalHTLCFailureReason::CLTVExpiryTooSoon,
			LocalHTLCFailureReason::IncorrectPaymentDetails => nativeLocalHTLCFailureReason::IncorrectPaymentDetails,
			LocalHTLCFailureReason::FinalIncorrectCLTVExpiry => nativeLocalHTLCFailureReason::FinalIncorrectCLTVExpiry,
			LocalHTLCFailureReason::FinalIncorrectHTLCAmount => nativeLocalHTLCFailureReason::FinalIncorrectHTLCAmount,
			LocalHTLCFailureReason::ChannelDisabled => nativeLocalHTLCFailureReason::ChannelDisabled,
			LocalHTLCFailureReason::CLTVExpiryTooFar => nativeLocalHTLCFailureReason::CLTVExpiryTooFar,
			LocalHTLCFailureReason::InvalidOnionPayload => nativeLocalHTLCFailureReason::InvalidOnionPayload,
			LocalHTLCFailureReason::MPPTimeout => nativeLocalHTLCFailureReason::MPPTimeout,
			LocalHTLCFailureReason::InvalidOnionBlinding => nativeLocalHTLCFailureReason::InvalidOnionBlinding,
			LocalHTLCFailureReason::UnknownFailureCode {ref code, } => {
				let mut code_nonref = Clone::clone(code);
				nativeLocalHTLCFailureReason::UnknownFailureCode {
					code: code_nonref,
				}
			},
			LocalHTLCFailureReason::ForwardExpiryBuffer => nativeLocalHTLCFailureReason::ForwardExpiryBuffer,
			LocalHTLCFailureReason::InvalidTrampolineForward => nativeLocalHTLCFailureReason::InvalidTrampolineForward,
			LocalHTLCFailureReason::PaymentClaimBuffer => nativeLocalHTLCFailureReason::PaymentClaimBuffer,
			LocalHTLCFailureReason::DustLimitHolder => nativeLocalHTLCFailureReason::DustLimitHolder,
			LocalHTLCFailureReason::DustLimitCounterparty => nativeLocalHTLCFailureReason::DustLimitCounterparty,
			LocalHTLCFailureReason::FeeSpikeBuffer => nativeLocalHTLCFailureReason::FeeSpikeBuffer,
			LocalHTLCFailureReason::PrivateChannelForward => nativeLocalHTLCFailureReason::PrivateChannelForward,
			LocalHTLCFailureReason::RealSCIDForward => nativeLocalHTLCFailureReason::RealSCIDForward,
			LocalHTLCFailureReason::ChannelNotReady => nativeLocalHTLCFailureReason::ChannelNotReady,
			LocalHTLCFailureReason::InvalidKeysendPreimage => nativeLocalHTLCFailureReason::InvalidKeysendPreimage,
			LocalHTLCFailureReason::InvalidTrampolinePayload => nativeLocalHTLCFailureReason::InvalidTrampolinePayload,
			LocalHTLCFailureReason::PaymentSecretRequired => nativeLocalHTLCFailureReason::PaymentSecretRequired,
			LocalHTLCFailureReason::OutgoingCLTVTooSoon => nativeLocalHTLCFailureReason::OutgoingCLTVTooSoon,
			LocalHTLCFailureReason::ChannelClosed => nativeLocalHTLCFailureReason::ChannelClosed,
			LocalHTLCFailureReason::OnChainTimeout => nativeLocalHTLCFailureReason::OnChainTimeout,
			LocalHTLCFailureReason::ZeroAmount => nativeLocalHTLCFailureReason::ZeroAmount,
			LocalHTLCFailureReason::HTLCMinimum => nativeLocalHTLCFailureReason::HTLCMinimum,
			LocalHTLCFailureReason::HTLCMaximum => nativeLocalHTLCFailureReason::HTLCMaximum,
			LocalHTLCFailureReason::PeerOffline => nativeLocalHTLCFailureReason::PeerOffline,
			LocalHTLCFailureReason::ChannelBalanceOverdrawn => nativeLocalHTLCFailureReason::ChannelBalanceOverdrawn,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLocalHTLCFailureReason {
		match self {
			LocalHTLCFailureReason::TemporaryNodeFailure => nativeLocalHTLCFailureReason::TemporaryNodeFailure,
			LocalHTLCFailureReason::PermanentNodeFailure => nativeLocalHTLCFailureReason::PermanentNodeFailure,
			LocalHTLCFailureReason::RequiredNodeFeature => nativeLocalHTLCFailureReason::RequiredNodeFeature,
			LocalHTLCFailureReason::InvalidOnionVersion => nativeLocalHTLCFailureReason::InvalidOnionVersion,
			LocalHTLCFailureReason::InvalidOnionHMAC => nativeLocalHTLCFailureReason::InvalidOnionHMAC,
			LocalHTLCFailureReason::InvalidOnionKey => nativeLocalHTLCFailureReason::InvalidOnionKey,
			LocalHTLCFailureReason::TemporaryChannelFailure => nativeLocalHTLCFailureReason::TemporaryChannelFailure,
			LocalHTLCFailureReason::PermanentChannelFailure => nativeLocalHTLCFailureReason::PermanentChannelFailure,
			LocalHTLCFailureReason::RequiredChannelFeature => nativeLocalHTLCFailureReason::RequiredChannelFeature,
			LocalHTLCFailureReason::UnknownNextPeer => nativeLocalHTLCFailureReason::UnknownNextPeer,
			LocalHTLCFailureReason::AmountBelowMinimum => nativeLocalHTLCFailureReason::AmountBelowMinimum,
			LocalHTLCFailureReason::FeeInsufficient => nativeLocalHTLCFailureReason::FeeInsufficient,
			LocalHTLCFailureReason::IncorrectCLTVExpiry => nativeLocalHTLCFailureReason::IncorrectCLTVExpiry,
			LocalHTLCFailureReason::CLTVExpiryTooSoon => nativeLocalHTLCFailureReason::CLTVExpiryTooSoon,
			LocalHTLCFailureReason::IncorrectPaymentDetails => nativeLocalHTLCFailureReason::IncorrectPaymentDetails,
			LocalHTLCFailureReason::FinalIncorrectCLTVExpiry => nativeLocalHTLCFailureReason::FinalIncorrectCLTVExpiry,
			LocalHTLCFailureReason::FinalIncorrectHTLCAmount => nativeLocalHTLCFailureReason::FinalIncorrectHTLCAmount,
			LocalHTLCFailureReason::ChannelDisabled => nativeLocalHTLCFailureReason::ChannelDisabled,
			LocalHTLCFailureReason::CLTVExpiryTooFar => nativeLocalHTLCFailureReason::CLTVExpiryTooFar,
			LocalHTLCFailureReason::InvalidOnionPayload => nativeLocalHTLCFailureReason::InvalidOnionPayload,
			LocalHTLCFailureReason::MPPTimeout => nativeLocalHTLCFailureReason::MPPTimeout,
			LocalHTLCFailureReason::InvalidOnionBlinding => nativeLocalHTLCFailureReason::InvalidOnionBlinding,
			LocalHTLCFailureReason::UnknownFailureCode {mut code, } => {
				nativeLocalHTLCFailureReason::UnknownFailureCode {
					code: code,
				}
			},
			LocalHTLCFailureReason::ForwardExpiryBuffer => nativeLocalHTLCFailureReason::ForwardExpiryBuffer,
			LocalHTLCFailureReason::InvalidTrampolineForward => nativeLocalHTLCFailureReason::InvalidTrampolineForward,
			LocalHTLCFailureReason::PaymentClaimBuffer => nativeLocalHTLCFailureReason::PaymentClaimBuffer,
			LocalHTLCFailureReason::DustLimitHolder => nativeLocalHTLCFailureReason::DustLimitHolder,
			LocalHTLCFailureReason::DustLimitCounterparty => nativeLocalHTLCFailureReason::DustLimitCounterparty,
			LocalHTLCFailureReason::FeeSpikeBuffer => nativeLocalHTLCFailureReason::FeeSpikeBuffer,
			LocalHTLCFailureReason::PrivateChannelForward => nativeLocalHTLCFailureReason::PrivateChannelForward,
			LocalHTLCFailureReason::RealSCIDForward => nativeLocalHTLCFailureReason::RealSCIDForward,
			LocalHTLCFailureReason::ChannelNotReady => nativeLocalHTLCFailureReason::ChannelNotReady,
			LocalHTLCFailureReason::InvalidKeysendPreimage => nativeLocalHTLCFailureReason::InvalidKeysendPreimage,
			LocalHTLCFailureReason::InvalidTrampolinePayload => nativeLocalHTLCFailureReason::InvalidTrampolinePayload,
			LocalHTLCFailureReason::PaymentSecretRequired => nativeLocalHTLCFailureReason::PaymentSecretRequired,
			LocalHTLCFailureReason::OutgoingCLTVTooSoon => nativeLocalHTLCFailureReason::OutgoingCLTVTooSoon,
			LocalHTLCFailureReason::ChannelClosed => nativeLocalHTLCFailureReason::ChannelClosed,
			LocalHTLCFailureReason::OnChainTimeout => nativeLocalHTLCFailureReason::OnChainTimeout,
			LocalHTLCFailureReason::ZeroAmount => nativeLocalHTLCFailureReason::ZeroAmount,
			LocalHTLCFailureReason::HTLCMinimum => nativeLocalHTLCFailureReason::HTLCMinimum,
			LocalHTLCFailureReason::HTLCMaximum => nativeLocalHTLCFailureReason::HTLCMaximum,
			LocalHTLCFailureReason::PeerOffline => nativeLocalHTLCFailureReason::PeerOffline,
			LocalHTLCFailureReason::ChannelBalanceOverdrawn => nativeLocalHTLCFailureReason::ChannelBalanceOverdrawn,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LocalHTLCFailureReasonImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLocalHTLCFailureReason) };
		match native {
			nativeLocalHTLCFailureReason::TemporaryNodeFailure => LocalHTLCFailureReason::TemporaryNodeFailure,
			nativeLocalHTLCFailureReason::PermanentNodeFailure => LocalHTLCFailureReason::PermanentNodeFailure,
			nativeLocalHTLCFailureReason::RequiredNodeFeature => LocalHTLCFailureReason::RequiredNodeFeature,
			nativeLocalHTLCFailureReason::InvalidOnionVersion => LocalHTLCFailureReason::InvalidOnionVersion,
			nativeLocalHTLCFailureReason::InvalidOnionHMAC => LocalHTLCFailureReason::InvalidOnionHMAC,
			nativeLocalHTLCFailureReason::InvalidOnionKey => LocalHTLCFailureReason::InvalidOnionKey,
			nativeLocalHTLCFailureReason::TemporaryChannelFailure => LocalHTLCFailureReason::TemporaryChannelFailure,
			nativeLocalHTLCFailureReason::PermanentChannelFailure => LocalHTLCFailureReason::PermanentChannelFailure,
			nativeLocalHTLCFailureReason::RequiredChannelFeature => LocalHTLCFailureReason::RequiredChannelFeature,
			nativeLocalHTLCFailureReason::UnknownNextPeer => LocalHTLCFailureReason::UnknownNextPeer,
			nativeLocalHTLCFailureReason::AmountBelowMinimum => LocalHTLCFailureReason::AmountBelowMinimum,
			nativeLocalHTLCFailureReason::FeeInsufficient => LocalHTLCFailureReason::FeeInsufficient,
			nativeLocalHTLCFailureReason::IncorrectCLTVExpiry => LocalHTLCFailureReason::IncorrectCLTVExpiry,
			nativeLocalHTLCFailureReason::CLTVExpiryTooSoon => LocalHTLCFailureReason::CLTVExpiryTooSoon,
			nativeLocalHTLCFailureReason::IncorrectPaymentDetails => LocalHTLCFailureReason::IncorrectPaymentDetails,
			nativeLocalHTLCFailureReason::FinalIncorrectCLTVExpiry => LocalHTLCFailureReason::FinalIncorrectCLTVExpiry,
			nativeLocalHTLCFailureReason::FinalIncorrectHTLCAmount => LocalHTLCFailureReason::FinalIncorrectHTLCAmount,
			nativeLocalHTLCFailureReason::ChannelDisabled => LocalHTLCFailureReason::ChannelDisabled,
			nativeLocalHTLCFailureReason::CLTVExpiryTooFar => LocalHTLCFailureReason::CLTVExpiryTooFar,
			nativeLocalHTLCFailureReason::InvalidOnionPayload => LocalHTLCFailureReason::InvalidOnionPayload,
			nativeLocalHTLCFailureReason::MPPTimeout => LocalHTLCFailureReason::MPPTimeout,
			nativeLocalHTLCFailureReason::InvalidOnionBlinding => LocalHTLCFailureReason::InvalidOnionBlinding,
			nativeLocalHTLCFailureReason::UnknownFailureCode {ref code, } => {
				let mut code_nonref = Clone::clone(code);
				LocalHTLCFailureReason::UnknownFailureCode {
					code: code_nonref,
				}
			},
			nativeLocalHTLCFailureReason::ForwardExpiryBuffer => LocalHTLCFailureReason::ForwardExpiryBuffer,
			nativeLocalHTLCFailureReason::InvalidTrampolineForward => LocalHTLCFailureReason::InvalidTrampolineForward,
			nativeLocalHTLCFailureReason::PaymentClaimBuffer => LocalHTLCFailureReason::PaymentClaimBuffer,
			nativeLocalHTLCFailureReason::DustLimitHolder => LocalHTLCFailureReason::DustLimitHolder,
			nativeLocalHTLCFailureReason::DustLimitCounterparty => LocalHTLCFailureReason::DustLimitCounterparty,
			nativeLocalHTLCFailureReason::FeeSpikeBuffer => LocalHTLCFailureReason::FeeSpikeBuffer,
			nativeLocalHTLCFailureReason::PrivateChannelForward => LocalHTLCFailureReason::PrivateChannelForward,
			nativeLocalHTLCFailureReason::RealSCIDForward => LocalHTLCFailureReason::RealSCIDForward,
			nativeLocalHTLCFailureReason::ChannelNotReady => LocalHTLCFailureReason::ChannelNotReady,
			nativeLocalHTLCFailureReason::InvalidKeysendPreimage => LocalHTLCFailureReason::InvalidKeysendPreimage,
			nativeLocalHTLCFailureReason::InvalidTrampolinePayload => LocalHTLCFailureReason::InvalidTrampolinePayload,
			nativeLocalHTLCFailureReason::PaymentSecretRequired => LocalHTLCFailureReason::PaymentSecretRequired,
			nativeLocalHTLCFailureReason::OutgoingCLTVTooSoon => LocalHTLCFailureReason::OutgoingCLTVTooSoon,
			nativeLocalHTLCFailureReason::ChannelClosed => LocalHTLCFailureReason::ChannelClosed,
			nativeLocalHTLCFailureReason::OnChainTimeout => LocalHTLCFailureReason::OnChainTimeout,
			nativeLocalHTLCFailureReason::ZeroAmount => LocalHTLCFailureReason::ZeroAmount,
			nativeLocalHTLCFailureReason::HTLCMinimum => LocalHTLCFailureReason::HTLCMinimum,
			nativeLocalHTLCFailureReason::HTLCMaximum => LocalHTLCFailureReason::HTLCMaximum,
			nativeLocalHTLCFailureReason::PeerOffline => LocalHTLCFailureReason::PeerOffline,
			nativeLocalHTLCFailureReason::ChannelBalanceOverdrawn => LocalHTLCFailureReason::ChannelBalanceOverdrawn,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLocalHTLCFailureReason) -> Self {
		match native {
			nativeLocalHTLCFailureReason::TemporaryNodeFailure => LocalHTLCFailureReason::TemporaryNodeFailure,
			nativeLocalHTLCFailureReason::PermanentNodeFailure => LocalHTLCFailureReason::PermanentNodeFailure,
			nativeLocalHTLCFailureReason::RequiredNodeFeature => LocalHTLCFailureReason::RequiredNodeFeature,
			nativeLocalHTLCFailureReason::InvalidOnionVersion => LocalHTLCFailureReason::InvalidOnionVersion,
			nativeLocalHTLCFailureReason::InvalidOnionHMAC => LocalHTLCFailureReason::InvalidOnionHMAC,
			nativeLocalHTLCFailureReason::InvalidOnionKey => LocalHTLCFailureReason::InvalidOnionKey,
			nativeLocalHTLCFailureReason::TemporaryChannelFailure => LocalHTLCFailureReason::TemporaryChannelFailure,
			nativeLocalHTLCFailureReason::PermanentChannelFailure => LocalHTLCFailureReason::PermanentChannelFailure,
			nativeLocalHTLCFailureReason::RequiredChannelFeature => LocalHTLCFailureReason::RequiredChannelFeature,
			nativeLocalHTLCFailureReason::UnknownNextPeer => LocalHTLCFailureReason::UnknownNextPeer,
			nativeLocalHTLCFailureReason::AmountBelowMinimum => LocalHTLCFailureReason::AmountBelowMinimum,
			nativeLocalHTLCFailureReason::FeeInsufficient => LocalHTLCFailureReason::FeeInsufficient,
			nativeLocalHTLCFailureReason::IncorrectCLTVExpiry => LocalHTLCFailureReason::IncorrectCLTVExpiry,
			nativeLocalHTLCFailureReason::CLTVExpiryTooSoon => LocalHTLCFailureReason::CLTVExpiryTooSoon,
			nativeLocalHTLCFailureReason::IncorrectPaymentDetails => LocalHTLCFailureReason::IncorrectPaymentDetails,
			nativeLocalHTLCFailureReason::FinalIncorrectCLTVExpiry => LocalHTLCFailureReason::FinalIncorrectCLTVExpiry,
			nativeLocalHTLCFailureReason::FinalIncorrectHTLCAmount => LocalHTLCFailureReason::FinalIncorrectHTLCAmount,
			nativeLocalHTLCFailureReason::ChannelDisabled => LocalHTLCFailureReason::ChannelDisabled,
			nativeLocalHTLCFailureReason::CLTVExpiryTooFar => LocalHTLCFailureReason::CLTVExpiryTooFar,
			nativeLocalHTLCFailureReason::InvalidOnionPayload => LocalHTLCFailureReason::InvalidOnionPayload,
			nativeLocalHTLCFailureReason::MPPTimeout => LocalHTLCFailureReason::MPPTimeout,
			nativeLocalHTLCFailureReason::InvalidOnionBlinding => LocalHTLCFailureReason::InvalidOnionBlinding,
			nativeLocalHTLCFailureReason::UnknownFailureCode {mut code, } => {
				LocalHTLCFailureReason::UnknownFailureCode {
					code: code,
				}
			},
			nativeLocalHTLCFailureReason::ForwardExpiryBuffer => LocalHTLCFailureReason::ForwardExpiryBuffer,
			nativeLocalHTLCFailureReason::InvalidTrampolineForward => LocalHTLCFailureReason::InvalidTrampolineForward,
			nativeLocalHTLCFailureReason::PaymentClaimBuffer => LocalHTLCFailureReason::PaymentClaimBuffer,
			nativeLocalHTLCFailureReason::DustLimitHolder => LocalHTLCFailureReason::DustLimitHolder,
			nativeLocalHTLCFailureReason::DustLimitCounterparty => LocalHTLCFailureReason::DustLimitCounterparty,
			nativeLocalHTLCFailureReason::FeeSpikeBuffer => LocalHTLCFailureReason::FeeSpikeBuffer,
			nativeLocalHTLCFailureReason::PrivateChannelForward => LocalHTLCFailureReason::PrivateChannelForward,
			nativeLocalHTLCFailureReason::RealSCIDForward => LocalHTLCFailureReason::RealSCIDForward,
			nativeLocalHTLCFailureReason::ChannelNotReady => LocalHTLCFailureReason::ChannelNotReady,
			nativeLocalHTLCFailureReason::InvalidKeysendPreimage => LocalHTLCFailureReason::InvalidKeysendPreimage,
			nativeLocalHTLCFailureReason::InvalidTrampolinePayload => LocalHTLCFailureReason::InvalidTrampolinePayload,
			nativeLocalHTLCFailureReason::PaymentSecretRequired => LocalHTLCFailureReason::PaymentSecretRequired,
			nativeLocalHTLCFailureReason::OutgoingCLTVTooSoon => LocalHTLCFailureReason::OutgoingCLTVTooSoon,
			nativeLocalHTLCFailureReason::ChannelClosed => LocalHTLCFailureReason::ChannelClosed,
			nativeLocalHTLCFailureReason::OnChainTimeout => LocalHTLCFailureReason::OnChainTimeout,
			nativeLocalHTLCFailureReason::ZeroAmount => LocalHTLCFailureReason::ZeroAmount,
			nativeLocalHTLCFailureReason::HTLCMinimum => LocalHTLCFailureReason::HTLCMinimum,
			nativeLocalHTLCFailureReason::HTLCMaximum => LocalHTLCFailureReason::HTLCMaximum,
			nativeLocalHTLCFailureReason::PeerOffline => LocalHTLCFailureReason::PeerOffline,
			nativeLocalHTLCFailureReason::ChannelBalanceOverdrawn => LocalHTLCFailureReason::ChannelBalanceOverdrawn,
		}
	}
}
/// Frees any resources used by the LocalHTLCFailureReason
#[no_mangle]
pub extern "C" fn LocalHTLCFailureReason_free(this_ptr: LocalHTLCFailureReason) { }
/// Creates a copy of the LocalHTLCFailureReason
#[no_mangle]
pub extern "C" fn LocalHTLCFailureReason_clone(orig: &LocalHTLCFailureReason) -> LocalHTLCFailureReason {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LocalHTLCFailureReason_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LocalHTLCFailureReason)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LocalHTLCFailureReason_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LocalHTLCFailureReason) };
}
#[no_mangle]
/// Utility method to constructs a new TemporaryNodeFailure-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_temporary_node_failure() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::TemporaryNodeFailure}
#[no_mangle]
/// Utility method to constructs a new PermanentNodeFailure-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_permanent_node_failure() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::PermanentNodeFailure}
#[no_mangle]
/// Utility method to constructs a new RequiredNodeFeature-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_required_node_feature() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::RequiredNodeFeature}
#[no_mangle]
/// Utility method to constructs a new InvalidOnionVersion-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_onion_version() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidOnionVersion}
#[no_mangle]
/// Utility method to constructs a new InvalidOnionHMAC-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_onion_hmac() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidOnionHMAC}
#[no_mangle]
/// Utility method to constructs a new InvalidOnionKey-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_onion_key() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidOnionKey}
#[no_mangle]
/// Utility method to constructs a new TemporaryChannelFailure-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_temporary_channel_failure() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::TemporaryChannelFailure}
#[no_mangle]
/// Utility method to constructs a new PermanentChannelFailure-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_permanent_channel_failure() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::PermanentChannelFailure}
#[no_mangle]
/// Utility method to constructs a new RequiredChannelFeature-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_required_channel_feature() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::RequiredChannelFeature}
#[no_mangle]
/// Utility method to constructs a new UnknownNextPeer-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_unknown_next_peer() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::UnknownNextPeer}
#[no_mangle]
/// Utility method to constructs a new AmountBelowMinimum-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_amount_below_minimum() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::AmountBelowMinimum}
#[no_mangle]
/// Utility method to constructs a new FeeInsufficient-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_fee_insufficient() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::FeeInsufficient}
#[no_mangle]
/// Utility method to constructs a new IncorrectCLTVExpiry-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_incorrect_cltvexpiry() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::IncorrectCLTVExpiry}
#[no_mangle]
/// Utility method to constructs a new CLTVExpiryTooSoon-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_cltvexpiry_too_soon() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::CLTVExpiryTooSoon}
#[no_mangle]
/// Utility method to constructs a new IncorrectPaymentDetails-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_incorrect_payment_details() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::IncorrectPaymentDetails}
#[no_mangle]
/// Utility method to constructs a new FinalIncorrectCLTVExpiry-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_final_incorrect_cltvexpiry() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::FinalIncorrectCLTVExpiry}
#[no_mangle]
/// Utility method to constructs a new FinalIncorrectHTLCAmount-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_final_incorrect_htlcamount() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::FinalIncorrectHTLCAmount}
#[no_mangle]
/// Utility method to constructs a new ChannelDisabled-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_channel_disabled() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::ChannelDisabled}
#[no_mangle]
/// Utility method to constructs a new CLTVExpiryTooFar-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_cltvexpiry_too_far() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::CLTVExpiryTooFar}
#[no_mangle]
/// Utility method to constructs a new InvalidOnionPayload-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_onion_payload() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidOnionPayload}
#[no_mangle]
/// Utility method to constructs a new MPPTimeout-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_mpptimeout() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::MPPTimeout}
#[no_mangle]
/// Utility method to constructs a new InvalidOnionBlinding-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_onion_blinding() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidOnionBlinding}
#[no_mangle]
/// Utility method to constructs a new UnknownFailureCode-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_unknown_failure_code(code: u16) -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::UnknownFailureCode {
		code,
	}
}
#[no_mangle]
/// Utility method to constructs a new ForwardExpiryBuffer-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_forward_expiry_buffer() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::ForwardExpiryBuffer}
#[no_mangle]
/// Utility method to constructs a new InvalidTrampolineForward-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_trampoline_forward() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidTrampolineForward}
#[no_mangle]
/// Utility method to constructs a new PaymentClaimBuffer-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_payment_claim_buffer() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::PaymentClaimBuffer}
#[no_mangle]
/// Utility method to constructs a new DustLimitHolder-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_dust_limit_holder() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::DustLimitHolder}
#[no_mangle]
/// Utility method to constructs a new DustLimitCounterparty-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_dust_limit_counterparty() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::DustLimitCounterparty}
#[no_mangle]
/// Utility method to constructs a new FeeSpikeBuffer-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_fee_spike_buffer() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::FeeSpikeBuffer}
#[no_mangle]
/// Utility method to constructs a new PrivateChannelForward-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_private_channel_forward() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::PrivateChannelForward}
#[no_mangle]
/// Utility method to constructs a new RealSCIDForward-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_real_scidforward() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::RealSCIDForward}
#[no_mangle]
/// Utility method to constructs a new ChannelNotReady-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_channel_not_ready() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::ChannelNotReady}
#[no_mangle]
/// Utility method to constructs a new InvalidKeysendPreimage-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_keysend_preimage() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidKeysendPreimage}
#[no_mangle]
/// Utility method to constructs a new InvalidTrampolinePayload-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_invalid_trampoline_payload() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::InvalidTrampolinePayload}
#[no_mangle]
/// Utility method to constructs a new PaymentSecretRequired-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_payment_secret_required() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::PaymentSecretRequired}
#[no_mangle]
/// Utility method to constructs a new OutgoingCLTVTooSoon-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_outgoing_cltvtoo_soon() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::OutgoingCLTVTooSoon}
#[no_mangle]
/// Utility method to constructs a new ChannelClosed-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_channel_closed() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::ChannelClosed}
#[no_mangle]
/// Utility method to constructs a new OnChainTimeout-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_on_chain_timeout() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::OnChainTimeout}
#[no_mangle]
/// Utility method to constructs a new ZeroAmount-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_zero_amount() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::ZeroAmount}
#[no_mangle]
/// Utility method to constructs a new HTLCMinimum-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_htlcminimum() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::HTLCMinimum}
#[no_mangle]
/// Utility method to constructs a new HTLCMaximum-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_htlcmaximum() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::HTLCMaximum}
#[no_mangle]
/// Utility method to constructs a new PeerOffline-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_peer_offline() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::PeerOffline}
#[no_mangle]
/// Utility method to constructs a new ChannelBalanceOverdrawn-variant LocalHTLCFailureReason
pub extern "C" fn LocalHTLCFailureReason_channel_balance_overdrawn() -> LocalHTLCFailureReason {
	LocalHTLCFailureReason::ChannelBalanceOverdrawn}
/// Get a string which allows debug introspection of a LocalHTLCFailureReason object
pub extern "C" fn LocalHTLCFailureReason_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::onion_utils::LocalHTLCFailureReason }).into()}
/// Generates a non-cryptographic 64-bit hash of the LocalHTLCFailureReason.
#[no_mangle]
pub extern "C" fn LocalHTLCFailureReason_hash(o: &LocalHTLCFailureReason) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two LocalHTLCFailureReasons contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LocalHTLCFailureReason_eq(a: &LocalHTLCFailureReason, b: &LocalHTLCFailureReason) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Build a LocalHTLCFailureReason from a u16
pub extern "C" fn LocalHTLCFailureReason_from_u16(f: u16) -> crate::lightning::ln::onion_utils::LocalHTLCFailureReason {
	let from_obj = f;
	crate::lightning::ln::onion_utils::LocalHTLCFailureReason::native_into((lightning::ln::onion_utils::LocalHTLCFailureReason::from(from_obj)))
}
#[no_mangle]
/// Read a LocalHTLCFailureReason from a byte array, created by LocalHTLCFailureReason_write
pub extern "C" fn LocalHTLCFailureReason_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_LocalHTLCFailureReasonDecodeErrorZ {
	let res: Result<lightning::ln::onion_utils::LocalHTLCFailureReason, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::onion_utils::LocalHTLCFailureReason::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the LocalHTLCFailureReason object into a byte array which can be read by LocalHTLCFailureReason_read
pub extern "C" fn LocalHTLCFailureReason_write(obj: &crate::lightning::ln::onion_utils::LocalHTLCFailureReason) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn LocalHTLCFailureReason_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	LocalHTLCFailureReason_write(unsafe { &*(obj as *const LocalHTLCFailureReason) })
}
/// Build a payment onion, returning the first hop msat and cltv values as well.
///
/// `cur_block_height` should be set to the best known block height + 1.
///
/// Note that invoice_request (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn create_payment_onion(path: &crate::lightning::routing::router::Path, session_priv: *const [u8; 32], mut total_msat: u64, recipient_onion: &crate::lightning::ln::outbound_payment::RecipientOnionFields, mut cur_block_height: u32, payment_hash: *const [u8; 32], mut keysend_preimage: crate::c_types::derived::COption_ThirtyTwoBytesZ, mut invoice_request: crate::lightning::offers::invoice_request::InvoiceRequest, mut prng_seed: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_C3Tuple_OnionPacketu64u32ZAPIErrorZ {
	let mut local_keysend_preimage = { /*keysend_preimage*/ let keysend_preimage_opt = keysend_preimage; if keysend_preimage_opt.is_none() { None } else { Some({ { ::lightning::types::payment::PaymentPreimage({ keysend_preimage_opt.take() }.data) }})} };
	let mut local_invoice_request = if invoice_request.inner.is_null() { None } else { Some( { invoice_request.get_native_ref() }) };
	let mut ret = lightning::ln::onion_utils::create_payment_onion(secp256k1::global::SECP256K1, path.get_native_ref(), &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *session_priv}[..]).unwrap(), total_msat, recipient_onion.get_native_ref(), cur_block_height, &::lightning::types::payment::PaymentHash(unsafe { *payment_hash }), &local_keysend_preimage, local_invoice_request, prng_seed.data);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = o; let mut local_ret_0 = (crate::lightning::ln::msgs::OnionPacket { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, orig_ret_0_1, orig_ret_0_2).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}


use lightning::ln::onion_utils::AttributionData as nativeAttributionDataImport;
pub(crate) type nativeAttributionData = nativeAttributionDataImport;

/// Attribution data allows the sender of an HTLC to identify which hop failed an HTLC robustly,
/// preventing earlier hops from corrupting the HTLC failure information (or at least allowing the
/// sender to identify the earliest hop which corrupted HTLC failure information).
///
/// Additionally, it allows a sender to identify how long each hop along a path held an HTLC, with
/// 100ms granularity.
#[must_use]
#[repr(C)]
pub struct AttributionData {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAttributionData,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for AttributionData {
	type Target = nativeAttributionData;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for AttributionData { }
unsafe impl core::marker::Sync for AttributionData { }
impl Drop for AttributionData {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeAttributionData>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the AttributionData, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn AttributionData_free(this_obj: AttributionData) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AttributionData_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeAttributionData) };
}
#[allow(unused)]
impl AttributionData {
	pub(crate) fn get_native_ref(&self) -> &'static nativeAttributionData {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeAttributionData {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeAttributionData {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for AttributionData {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeAttributionData>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AttributionData_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeAttributionData) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the AttributionData
pub extern "C" fn AttributionData_clone(orig: &AttributionData) -> AttributionData {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a AttributionData object
pub extern "C" fn AttributionData_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::onion_utils::AttributionData }).into()}
/// Generates a non-cryptographic 64-bit hash of the AttributionData.
#[no_mangle]
pub extern "C" fn AttributionData_hash(o: &AttributionData) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two AttributionDatas contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn AttributionData_eq(a: &AttributionData, b: &AttributionData) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the AttributionData object into a byte array which can be read by AttributionData_read
pub extern "C" fn AttributionData_write(obj: &crate::lightning::ln::onion_utils::AttributionData) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn AttributionData_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::onion_utils::nativeAttributionData) })
}
#[no_mangle]
/// Read a AttributionData from a byte array, created by AttributionData_write
pub extern "C" fn AttributionData_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_AttributionDataDecodeErrorZ {
	let res: Result<lightning::ln::onion_utils::AttributionData, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::onion_utils::AttributionData { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
