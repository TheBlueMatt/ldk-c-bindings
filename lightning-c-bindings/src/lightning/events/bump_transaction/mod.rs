// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for bumping transactions originating from [`Event`]s.
//!
//! [`Event`]: crate::events::Event

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod sync;

use lightning::events::bump_transaction::AnchorDescriptor as nativeAnchorDescriptorImport;
pub(crate) type nativeAnchorDescriptor = nativeAnchorDescriptorImport;

/// A descriptor used to sign for a commitment transaction's anchor output.
#[must_use]
#[repr(C)]
pub struct AnchorDescriptor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAnchorDescriptor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for AnchorDescriptor {
	type Target = nativeAnchorDescriptor;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for AnchorDescriptor { }
unsafe impl core::marker::Sync for AnchorDescriptor { }
impl Drop for AnchorDescriptor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeAnchorDescriptor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the AnchorDescriptor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_free(this_obj: AnchorDescriptor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AnchorDescriptor_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeAnchorDescriptor) };
}
#[allow(unused)]
impl AnchorDescriptor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeAnchorDescriptor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeAnchorDescriptor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeAnchorDescriptor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The parameters required to derive the signer for the anchor input.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_get_channel_derivation_parameters(this_ptr: &AnchorDescriptor) -> crate::lightning::sign::ChannelDerivationParameters {
	let mut inner_val = &mut AnchorDescriptor::get_native_mut_ref(this_ptr).channel_derivation_parameters;
	crate::lightning::sign::ChannelDerivationParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::sign::ChannelDerivationParameters<>) as *mut _) }, is_owned: false }
}
/// The parameters required to derive the signer for the anchor input.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_set_channel_derivation_parameters(this_ptr: &mut AnchorDescriptor, mut val: crate::lightning::sign::ChannelDerivationParameters) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_derivation_parameters = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The transaction input's outpoint corresponding to the commitment transaction's anchor
/// output.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_get_outpoint(this_ptr: &AnchorDescriptor) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut AnchorDescriptor::get_native_mut_ref(this_ptr).outpoint;
	crate::c_types::bitcoin_to_C_outpoint(inner_val)
}
/// The transaction input's outpoint corresponding to the commitment transaction's anchor
/// output.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_set_outpoint(this_ptr: &mut AnchorDescriptor, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = crate::c_types::C_to_bitcoin_outpoint(val);
}
/// Zero-fee-commitment anchors have variable value, which is tracked here.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_get_value(this_ptr: &AnchorDescriptor) -> u64 {
	let mut inner_val = &mut AnchorDescriptor::get_native_mut_ref(this_ptr).value;
	inner_val.to_sat()
}
/// Zero-fee-commitment anchors have variable value, which is tracked here.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_set_value(this_ptr: &mut AnchorDescriptor, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.value = ::bitcoin::amount::Amount::from_sat(val);
}
/// Constructs a new AnchorDescriptor given each field
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_new(mut channel_derivation_parameters_arg: crate::lightning::sign::ChannelDerivationParameters, mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut value_arg: u64) -> AnchorDescriptor {
	AnchorDescriptor { inner: ObjOps::heap_alloc(nativeAnchorDescriptor {
		channel_derivation_parameters: *unsafe { Box::from_raw(channel_derivation_parameters_arg.take_inner()) },
		outpoint: crate::c_types::C_to_bitcoin_outpoint(outpoint_arg),
		value: ::bitcoin::amount::Amount::from_sat(value_arg),
	}), is_owned: true }
}
impl Clone for AnchorDescriptor {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeAnchorDescriptor>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AnchorDescriptor_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeAnchorDescriptor) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the AnchorDescriptor
pub extern "C" fn AnchorDescriptor_clone(orig: &AnchorDescriptor) -> AnchorDescriptor {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a AnchorDescriptor object
pub extern "C" fn AnchorDescriptor_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::bump_transaction::AnchorDescriptor }).into()}
/// Checks if two AnchorDescriptors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_eq(a: &AnchorDescriptor, b: &AnchorDescriptor) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns the UTXO to be spent by the anchor input, which can be obtained via
/// [`Self::unsigned_tx_input`].
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_previous_utxo(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor) -> crate::c_types::TxOut {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.previous_utxo();
	crate::c_types::TxOut::from_rust(&ret)
}

/// Returns the unsigned transaction input spending the anchor output in the commitment
/// transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_unsigned_tx_input(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor) -> crate::c_types::TxIn {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.unsigned_tx_input();
	crate::c_types::TxIn::from_rust(&ret)
}

/// Returns the fully signed witness required to spend the anchor output in the commitment
/// transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_tx_input_witness(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor, mut signature: crate::c_types::ECDSASignature) -> crate::c_types::Witness {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tx_input_witness(&signature.into_rust());
	crate::c_types::Witness::from_bitcoin(&ret)
}

/// Represents the different types of transactions, originating from LDK, to be bumped.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum BumpTransactionEvent {
	/// Indicates that a channel featuring anchor outputs is to be closed by broadcasting the local
	/// commitment transaction. Since commitment transactions have a static feerate pre-agreed upon,
	/// they may need additional fees to be attached through a child transaction using the popular
	/// [Child-Pays-For-Parent](https://bitcoinops.org/en/topics/cpfp) fee bumping technique. This
	/// child transaction must include the anchor input described within `anchor_descriptor` along
	/// with additional inputs to meet the target feerate. Failure to meet the target feerate
	/// decreases the confirmation odds of the transaction package (which includes the commitment
	/// and child anchor transactions), possibly resulting in a loss of funds. Once the transaction
	/// is constructed, it must be fully signed for and broadcast by the consumer of the event
	/// along with the `commitment_tx` enclosed. Note that the `commitment_tx` must always be
	/// broadcast first, as the child anchor transaction depends on it. It is also possible that the
	/// feerate of the commitment transaction is already sufficient, in which case the child anchor
	/// transaction is not needed and only the commitment transaction should be broadcast.
	///
	/// In zero-fee commitment channels, the commitment transaction and the anchor transaction
	/// form a 1-parent-1-child package that conforms to BIP 431 (known as TRUC transactions).
	/// The anchor transaction must be version 3, and its size must be no more than 1000 vB.
	/// The anchor transaction is usually needed to bump the fee of the commitment transaction
	/// as the commitment transaction is not explicitly assigned any fees. In those cases the
	/// anchor transaction must be broadcast together with the commitment transaction as a
	/// `child-with-parents` package (usually using the Bitcoin Core `submitpackage` RPC).
	///
	/// The consumer should be able to sign for any of the additional inputs included within the
	/// child anchor transaction. To sign its keyed-anchor input, an [`EcdsaChannelSigner`] should
	/// be re-derived through [`SignerProvider::derive_channel_signer`]. The anchor input signature
	/// can be computed with [`EcdsaChannelSigner::sign_holder_keyed_anchor_input`], which can then
	/// be provided to [`build_keyed_anchor_input_witness`] along with the `funding_pubkey` to
	/// obtain the full witness required to spend. Note that no signature or witness data is
	/// required to spend the keyless anchor used in zero-fee commitment channels.
	///
	/// It is possible to receive more than one instance of this event if a valid child anchor
	/// transaction is never broadcast or is but not with a sufficient fee to be mined. Care should
	/// be taken by the consumer of the event to ensure any future iterations of the child anchor
	/// transaction adhere to the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if they are no longer
	/// able to commit external confirmed funds to the child anchor transaction.
	///
	/// The set of `pending_htlcs` on the commitment transaction to be broadcast can be inspected to
	/// determine whether a significant portion of the channel's funds are allocated to HTLCs,
	/// enabling users to make their own decisions regarding the importance of the commitment
	/// transaction's confirmation. Note that this is not required, but simply exists as an option
	/// for users to override LDK's behavior. On commitments with no HTLCs (indicated by those with
	/// an empty `pending_htlcs`), confirmation of the commitment transaction can be considered to
	/// be not urgent.
	///
	/// [`EcdsaChannelSigner`]: crate::sign::ecdsa::EcdsaChannelSigner
	/// [`EcdsaChannelSigner::sign_holder_keyed_anchor_input`]: crate::sign::ecdsa::EcdsaChannelSigner::sign_holder_keyed_anchor_input
	/// [`build_keyed_anchor_input_witness`]: crate::ln::chan_utils::build_keyed_anchor_input_witness
	ChannelClose {
		/// The `channel_id` of the channel which has been closed.
		channel_id: crate::lightning::ln::types::ChannelId,
		/// Counterparty in the closed channel.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The unique identifier for the claim of the anchor output in the commitment transaction.
		///
		/// The identifier must map to the set of external UTXOs assigned to the claim, such that
		/// they can be reused when a new claim with the same identifier needs to be made, resulting
		/// in a fee-bumping attempt.
		claim_id: crate::c_types::ThirtyTwoBytes,
		/// The target feerate that the transaction package, which consists of the commitment
		/// transaction and the to-be-crafted child anchor transaction, must meet.
		package_target_feerate_sat_per_1000_weight: u32,
		/// The channel's commitment transaction to bump the fee of. This transaction should be
		/// broadcast along with the anchor transaction constructed as a result of consuming this
		/// event.
		commitment_tx: crate::c_types::Transaction,
		/// The absolute fee in satoshis of the commitment transaction. This can be used along the
		/// with weight of the commitment transaction to determine its feerate.
		commitment_tx_fee_satoshis: u64,
		/// The descriptor to sign the anchor input of the anchor transaction constructed as a
		/// result of consuming this event.
		anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor,
		/// The set of pending HTLCs on the commitment transaction that need to be resolved once the
		/// commitment transaction confirms.
		pending_htlcs: crate::c_types::derived::CVec_HTLCOutputInCommitmentZ,
	},
	/// Indicates that a channel featuring anchor outputs has unilaterally closed on-chain by a
	/// holder commitment transaction and its HTLC(s) need to be resolved on-chain. In all such
	/// channels, the pre-signed HTLC transactions have a zero fee, thus requiring additional
	/// inputs and/or outputs to be attached for a timely confirmation within the chain. These
	/// additional inputs and/or outputs must be appended to the resulting HTLC transaction to
	/// meet the target feerate. Failure to meet the target feerate decreases the confirmation
	/// odds of the transaction, possibly resulting in a loss of funds. Once the transaction
	/// meets the target feerate, it must be signed for and broadcast by the consumer of the
	/// event.
	///
	/// In zero-fee commitment channels, you must set the version of the HTLC claim transaction
	/// to version 3 as the counterparty's signature commits to the version of
	/// the transaction. You must also make sure that this claim transaction does not grow
	/// bigger than 10,000 vB, the maximum vsize of any TRUC transaction as specified in
	/// BIP 431. It is possible for [`htlc_descriptors`] to be long enough such
	/// that claiming all the HTLCs therein in a single transaction would exceed this limit.
	/// In this case, you must claim all the HTLCs in [`htlc_descriptors`] using multiple
	/// transactions. Finally, note that while HTLCs in zero-fee commitment channels no
	/// longer have the 1 CSV lock, LDK will still emit this event only after the commitment
	/// transaction has 1 confirmation.
	///
	/// The consumer should be able to sign for any of the non-HTLC inputs added to the resulting
	/// HTLC transaction. To sign HTLC inputs, an [`EcdsaChannelSigner`] should be re-derived
	/// through [`SignerProvider::derive_channel_signer`]. Each HTLC input's signature can be
	/// computed with [`EcdsaChannelSigner::sign_holder_htlc_transaction`], which can then be
	/// provided to [`HTLCDescriptor::tx_input_witness`] to obtain the fully signed witness required
	/// to spend.
	///
	/// It is possible to receive more than one instance of this event if a valid HTLC transaction
	/// is never broadcast or is but not with a sufficient fee to be mined. Care should be taken by
	/// the consumer of the event to ensure any future iterations of the HTLC transaction adhere to
	/// the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if either they are no
	/// longer able to commit external confirmed funds to the HTLC transaction or the fee committed
	/// to the HTLC transaction is greater in value than the HTLCs being claimed.
	///
	/// [`EcdsaChannelSigner`]: crate::sign::ecdsa::EcdsaChannelSigner
	/// [`EcdsaChannelSigner::sign_holder_htlc_transaction`]: crate::sign::ecdsa::EcdsaChannelSigner::sign_holder_htlc_transaction
	/// [`htlc_descriptors`]: `BumpTransactionEvent::HTLCResolution::htlc_descriptors`
	HTLCResolution {
		/// The `channel_id` of the channel which has been closed.
		channel_id: crate::lightning::ln::types::ChannelId,
		/// Counterparty in the closed channel.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The unique identifier for the claim of the HTLCs in the confirmed commitment
		/// transaction.
		///
		/// The identifier must map to the set of external UTXOs assigned to the claim, such that
		/// they can be reused when a new claim with the same identifier needs to be made, resulting
		/// in a fee-bumping attempt.
		claim_id: crate::c_types::ThirtyTwoBytes,
		/// The target feerate that the resulting HTLC transaction must meet.
		target_feerate_sat_per_1000_weight: u32,
		/// The set of pending HTLCs on the confirmed commitment that need to be claimed, preferably
		/// by the same transaction.
		htlc_descriptors: crate::c_types::derived::CVec_HTLCDescriptorZ,
		/// The locktime required for the resulting HTLC transaction.
		tx_lock_time: u32,
	},
}
use lightning::events::bump_transaction::BumpTransactionEvent as BumpTransactionEventImport;
pub(crate) type nativeBumpTransactionEvent = BumpTransactionEventImport;

impl BumpTransactionEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeBumpTransactionEvent {
		match self {
			BumpTransactionEvent::ChannelClose {ref channel_id, ref counterparty_node_id, ref claim_id, ref package_target_feerate_sat_per_1000_weight, ref commitment_tx, ref commitment_tx_fee_satoshis, ref anchor_descriptor, ref pending_htlcs, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut package_target_feerate_sat_per_1000_weight_nonref = Clone::clone(package_target_feerate_sat_per_1000_weight);
				let mut commitment_tx_nonref = Clone::clone(commitment_tx);
				let mut commitment_tx_fee_satoshis_nonref = Clone::clone(commitment_tx_fee_satoshis);
				let mut anchor_descriptor_nonref = Clone::clone(anchor_descriptor);
				let mut pending_htlcs_nonref = Clone::clone(pending_htlcs);
				let mut local_pending_htlcs_nonref = Vec::new(); for mut item in pending_htlcs_nonref.into_rust().drain(..) { local_pending_htlcs_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeBumpTransactionEvent::ChannelClose {
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					claim_id: ::lightning::chain::ClaimId(claim_id_nonref.data),
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight_nonref,
					commitment_tx: commitment_tx_nonref.into_bitcoin(),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis_nonref,
					anchor_descriptor: *unsafe { Box::from_raw(anchor_descriptor_nonref.take_inner()) },
					pending_htlcs: local_pending_htlcs_nonref,
				}
			},
			BumpTransactionEvent::HTLCResolution {ref channel_id, ref counterparty_node_id, ref claim_id, ref target_feerate_sat_per_1000_weight, ref htlc_descriptors, ref tx_lock_time, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut target_feerate_sat_per_1000_weight_nonref = Clone::clone(target_feerate_sat_per_1000_weight);
				let mut htlc_descriptors_nonref = Clone::clone(htlc_descriptors);
				let mut local_htlc_descriptors_nonref = Vec::new(); for mut item in htlc_descriptors_nonref.into_rust().drain(..) { local_htlc_descriptors_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut tx_lock_time_nonref = Clone::clone(tx_lock_time);
				nativeBumpTransactionEvent::HTLCResolution {
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					claim_id: ::lightning::chain::ClaimId(claim_id_nonref.data),
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight_nonref,
					htlc_descriptors: local_htlc_descriptors_nonref,
					tx_lock_time: ::bitcoin::locktime::absolute::LockTime::from_consensus(tx_lock_time_nonref),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeBumpTransactionEvent {
		match self {
			BumpTransactionEvent::ChannelClose {mut channel_id, mut counterparty_node_id, mut claim_id, mut package_target_feerate_sat_per_1000_weight, mut commitment_tx, mut commitment_tx_fee_satoshis, mut anchor_descriptor, mut pending_htlcs, } => {
				let mut local_pending_htlcs = Vec::new(); for mut item in pending_htlcs.into_rust().drain(..) { local_pending_htlcs.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeBumpTransactionEvent::ChannelClose {
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					claim_id: ::lightning::chain::ClaimId(claim_id.data),
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight,
					commitment_tx: commitment_tx.into_bitcoin(),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis,
					anchor_descriptor: *unsafe { Box::from_raw(anchor_descriptor.take_inner()) },
					pending_htlcs: local_pending_htlcs,
				}
			},
			BumpTransactionEvent::HTLCResolution {mut channel_id, mut counterparty_node_id, mut claim_id, mut target_feerate_sat_per_1000_weight, mut htlc_descriptors, mut tx_lock_time, } => {
				let mut local_htlc_descriptors = Vec::new(); for mut item in htlc_descriptors.into_rust().drain(..) { local_htlc_descriptors.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeBumpTransactionEvent::HTLCResolution {
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					claim_id: ::lightning::chain::ClaimId(claim_id.data),
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight,
					htlc_descriptors: local_htlc_descriptors,
					tx_lock_time: ::bitcoin::locktime::absolute::LockTime::from_consensus(tx_lock_time),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &BumpTransactionEventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeBumpTransactionEvent) };
		match native {
			nativeBumpTransactionEvent::ChannelClose {ref channel_id, ref counterparty_node_id, ref claim_id, ref package_target_feerate_sat_per_1000_weight, ref commitment_tx, ref commitment_tx_fee_satoshis, ref anchor_descriptor, ref pending_htlcs, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut package_target_feerate_sat_per_1000_weight_nonref = Clone::clone(package_target_feerate_sat_per_1000_weight);
				let mut commitment_tx_nonref = Clone::clone(commitment_tx);
				let mut commitment_tx_fee_satoshis_nonref = Clone::clone(commitment_tx_fee_satoshis);
				let mut anchor_descriptor_nonref = Clone::clone(anchor_descriptor);
				let mut pending_htlcs_nonref = Clone::clone(pending_htlcs);
				let mut local_pending_htlcs_nonref = Vec::new(); for mut item in pending_htlcs_nonref.drain(..) { local_pending_htlcs_nonref.push( { crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				BumpTransactionEvent::ChannelClose {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id_nonref.0 },
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight_nonref,
					commitment_tx: crate::c_types::Transaction::from_bitcoin(&commitment_tx_nonref),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis_nonref,
					anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor { inner: ObjOps::heap_alloc(anchor_descriptor_nonref), is_owned: true },
					pending_htlcs: local_pending_htlcs_nonref.into(),
				}
			},
			nativeBumpTransactionEvent::HTLCResolution {ref channel_id, ref counterparty_node_id, ref claim_id, ref target_feerate_sat_per_1000_weight, ref htlc_descriptors, ref tx_lock_time, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut target_feerate_sat_per_1000_weight_nonref = Clone::clone(target_feerate_sat_per_1000_weight);
				let mut htlc_descriptors_nonref = Clone::clone(htlc_descriptors);
				let mut local_htlc_descriptors_nonref = Vec::new(); for mut item in htlc_descriptors_nonref.drain(..) { local_htlc_descriptors_nonref.push( { crate::lightning::sign::HTLCDescriptor { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut tx_lock_time_nonref = Clone::clone(tx_lock_time);
				BumpTransactionEvent::HTLCResolution {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id_nonref.0 },
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight_nonref,
					htlc_descriptors: local_htlc_descriptors_nonref.into(),
					tx_lock_time: tx_lock_time_nonref.to_consensus_u32(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeBumpTransactionEvent) -> Self {
		match native {
			nativeBumpTransactionEvent::ChannelClose {mut channel_id, mut counterparty_node_id, mut claim_id, mut package_target_feerate_sat_per_1000_weight, mut commitment_tx, mut commitment_tx_fee_satoshis, mut anchor_descriptor, mut pending_htlcs, } => {
				let mut local_pending_htlcs = Vec::new(); for mut item in pending_htlcs.drain(..) { local_pending_htlcs.push( { crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				BumpTransactionEvent::ChannelClose {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id.0 },
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight,
					commitment_tx: crate::c_types::Transaction::from_bitcoin(&commitment_tx),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis,
					anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor { inner: ObjOps::heap_alloc(anchor_descriptor), is_owned: true },
					pending_htlcs: local_pending_htlcs.into(),
				}
			},
			nativeBumpTransactionEvent::HTLCResolution {mut channel_id, mut counterparty_node_id, mut claim_id, mut target_feerate_sat_per_1000_weight, mut htlc_descriptors, mut tx_lock_time, } => {
				let mut local_htlc_descriptors = Vec::new(); for mut item in htlc_descriptors.drain(..) { local_htlc_descriptors.push( { crate::lightning::sign::HTLCDescriptor { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				BumpTransactionEvent::HTLCResolution {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id.0 },
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight,
					htlc_descriptors: local_htlc_descriptors.into(),
					tx_lock_time: tx_lock_time.to_consensus_u32(),
				}
			},
		}
	}
}
/// Frees any resources used by the BumpTransactionEvent
#[no_mangle]
pub extern "C" fn BumpTransactionEvent_free(this_ptr: BumpTransactionEvent) { }
/// Creates a copy of the BumpTransactionEvent
#[no_mangle]
pub extern "C" fn BumpTransactionEvent_clone(orig: &BumpTransactionEvent) -> BumpTransactionEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BumpTransactionEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const BumpTransactionEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BumpTransactionEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut BumpTransactionEvent) };
}
#[no_mangle]
/// Utility method to constructs a new ChannelClose-variant BumpTransactionEvent
pub extern "C" fn BumpTransactionEvent_channel_close(channel_id: crate::lightning::ln::types::ChannelId, counterparty_node_id: crate::c_types::PublicKey, claim_id: crate::c_types::ThirtyTwoBytes, package_target_feerate_sat_per_1000_weight: u32, commitment_tx: crate::c_types::Transaction, commitment_tx_fee_satoshis: u64, anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor, pending_htlcs: crate::c_types::derived::CVec_HTLCOutputInCommitmentZ) -> BumpTransactionEvent {
	BumpTransactionEvent::ChannelClose {
		channel_id,
		counterparty_node_id,
		claim_id,
		package_target_feerate_sat_per_1000_weight,
		commitment_tx,
		commitment_tx_fee_satoshis,
		anchor_descriptor,
		pending_htlcs,
	}
}
#[no_mangle]
/// Utility method to constructs a new HTLCResolution-variant BumpTransactionEvent
pub extern "C" fn BumpTransactionEvent_htlcresolution(channel_id: crate::lightning::ln::types::ChannelId, counterparty_node_id: crate::c_types::PublicKey, claim_id: crate::c_types::ThirtyTwoBytes, target_feerate_sat_per_1000_weight: u32, htlc_descriptors: crate::c_types::derived::CVec_HTLCDescriptorZ, tx_lock_time: u32) -> BumpTransactionEvent {
	BumpTransactionEvent::HTLCResolution {
		channel_id,
		counterparty_node_id,
		claim_id,
		target_feerate_sat_per_1000_weight,
		htlc_descriptors,
		tx_lock_time,
	}
}
/// Get a string which allows debug introspection of a BumpTransactionEvent object
pub extern "C" fn BumpTransactionEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::bump_transaction::BumpTransactionEvent }).into()}
/// Checks if two BumpTransactionEvents contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn BumpTransactionEvent_eq(a: &BumpTransactionEvent, b: &BumpTransactionEvent) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning::events::bump_transaction::Input as nativeInputImport;
pub(crate) type nativeInput = nativeInputImport;

/// An input that must be included in a transaction when performing coin selection through
/// [`CoinSelectionSource::select_confirmed_utxos`]. It is guaranteed to be a SegWit input, so it
/// must have an empty [`TxIn::script_sig`] when spent.
#[must_use]
#[repr(C)]
pub struct Input {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInput,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Input {
	type Target = nativeInput;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Input { }
unsafe impl core::marker::Sync for Input { }
impl Drop for Input {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInput>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Input, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Input_free(this_obj: Input) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Input_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInput) };
}
#[allow(unused)]
impl Input {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInput {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInput {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInput {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The unique identifier of the input.
#[no_mangle]
pub extern "C" fn Input_get_outpoint(this_ptr: &Input) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut Input::get_native_mut_ref(this_ptr).outpoint;
	crate::c_types::bitcoin_to_C_outpoint(inner_val)
}
/// The unique identifier of the input.
#[no_mangle]
pub extern "C" fn Input_set_outpoint(this_ptr: &mut Input, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = crate::c_types::C_to_bitcoin_outpoint(val);
}
/// The UTXO being spent by the input.
#[no_mangle]
pub extern "C" fn Input_get_previous_utxo(this_ptr: &Input) -> crate::c_types::TxOut {
	let mut inner_val = &mut Input::get_native_mut_ref(this_ptr).previous_utxo;
	crate::c_types::TxOut::from_rust(inner_val)
}
/// The UTXO being spent by the input.
#[no_mangle]
pub extern "C" fn Input_set_previous_utxo(this_ptr: &mut Input, mut val: crate::c_types::TxOut) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.previous_utxo = val.into_rust();
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and
/// [`TxIn::witness`], each with their lengths included, required to satisfy the output's
/// script.
#[no_mangle]
pub extern "C" fn Input_get_satisfaction_weight(this_ptr: &Input) -> u64 {
	let mut inner_val = &mut Input::get_native_mut_ref(this_ptr).satisfaction_weight;
	*inner_val
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and
/// [`TxIn::witness`], each with their lengths included, required to satisfy the output's
/// script.
#[no_mangle]
pub extern "C" fn Input_set_satisfaction_weight(this_ptr: &mut Input, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.satisfaction_weight = val;
}
/// Constructs a new Input given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Input_new(mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut previous_utxo_arg: crate::c_types::TxOut, mut satisfaction_weight_arg: u64) -> Input {
	Input { inner: ObjOps::heap_alloc(nativeInput {
		outpoint: crate::c_types::C_to_bitcoin_outpoint(outpoint_arg),
		previous_utxo: previous_utxo_arg.into_rust(),
		satisfaction_weight: satisfaction_weight_arg,
	}), is_owned: true }
}
impl Clone for Input {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInput>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Input_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeInput) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Input
pub extern "C" fn Input_clone(orig: &Input) -> Input {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a Input object
pub extern "C" fn Input_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::bump_transaction::Input }).into()}
/// Generates a non-cryptographic 64-bit hash of the Input.
#[no_mangle]
pub extern "C" fn Input_hash(o: &Input) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Inputs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Input_eq(a: &Input, b: &Input) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::events::bump_transaction::Utxo as nativeUtxoImport;
pub(crate) type nativeUtxo = nativeUtxoImport;

/// An unspent transaction output that is available to spend resulting from a successful
/// [`CoinSelection`] attempt.
#[must_use]
#[repr(C)]
pub struct Utxo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUtxo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Utxo {
	type Target = nativeUtxo;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Utxo { }
unsafe impl core::marker::Sync for Utxo { }
impl Drop for Utxo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUtxo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Utxo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Utxo_free(this_obj: Utxo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Utxo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUtxo) };
}
#[allow(unused)]
impl Utxo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUtxo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUtxo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUtxo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The unique identifier of the output.
#[no_mangle]
pub extern "C" fn Utxo_get_outpoint(this_ptr: &Utxo) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut Utxo::get_native_mut_ref(this_ptr).outpoint;
	crate::c_types::bitcoin_to_C_outpoint(inner_val)
}
/// The unique identifier of the output.
#[no_mangle]
pub extern "C" fn Utxo_set_outpoint(this_ptr: &mut Utxo, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = crate::c_types::C_to_bitcoin_outpoint(val);
}
/// The output to spend.
#[no_mangle]
pub extern "C" fn Utxo_get_output(this_ptr: &Utxo) -> crate::c_types::TxOut {
	let mut inner_val = &mut Utxo::get_native_mut_ref(this_ptr).output;
	crate::c_types::TxOut::from_rust(inner_val)
}
/// The output to spend.
#[no_mangle]
pub extern "C" fn Utxo_set_output(this_ptr: &mut Utxo, mut val: crate::c_types::TxOut) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.output = val.into_rust();
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and [`TxIn::witness`], each
/// with their lengths included, required to satisfy the output's script. The weight consumed by
/// the input's `script_sig` must account for [`WITNESS_SCALE_FACTOR`].
#[no_mangle]
pub extern "C" fn Utxo_get_satisfaction_weight(this_ptr: &Utxo) -> u64 {
	let mut inner_val = &mut Utxo::get_native_mut_ref(this_ptr).satisfaction_weight;
	*inner_val
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and [`TxIn::witness`], each
/// with their lengths included, required to satisfy the output's script. The weight consumed by
/// the input's `script_sig` must account for [`WITNESS_SCALE_FACTOR`].
#[no_mangle]
pub extern "C" fn Utxo_set_satisfaction_weight(this_ptr: &mut Utxo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.satisfaction_weight = val;
}
/// Constructs a new Utxo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Utxo_new(mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut output_arg: crate::c_types::TxOut, mut satisfaction_weight_arg: u64) -> Utxo {
	Utxo { inner: ObjOps::heap_alloc(nativeUtxo {
		outpoint: crate::c_types::C_to_bitcoin_outpoint(outpoint_arg),
		output: output_arg.into_rust(),
		satisfaction_weight: satisfaction_weight_arg,
	}), is_owned: true }
}
impl Clone for Utxo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUtxo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Utxo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeUtxo) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Utxo
pub extern "C" fn Utxo_clone(orig: &Utxo) -> Utxo {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a Utxo object
pub extern "C" fn Utxo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::bump_transaction::Utxo }).into()}
/// Generates a non-cryptographic 64-bit hash of the Utxo.
#[no_mangle]
pub extern "C" fn Utxo_hash(o: &Utxo) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Utxos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Utxo_eq(a: &Utxo, b: &Utxo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the Utxo object into a byte array which can be read by Utxo_read
pub extern "C" fn Utxo_write(obj: &crate::lightning::events::bump_transaction::Utxo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Utxo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::events::bump_transaction::nativeUtxo) })
}
#[no_mangle]
/// Read a Utxo from a byte array, created by Utxo_write
pub extern "C" fn Utxo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UtxoDecodeErrorZ {
	let res: Result<lightning::events::bump_transaction::Utxo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::events::bump_transaction::Utxo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Returns a `Utxo` with the `satisfaction_weight` estimate for a legacy P2PKH output.
#[must_use]
#[no_mangle]
pub extern "C" fn Utxo_new_p2pkh(mut outpoint: crate::lightning::chain::transaction::OutPoint, mut value: u64, pubkey_hash: *const [u8; 20]) -> crate::lightning::events::bump_transaction::Utxo {
	let mut ret = lightning::events::bump_transaction::Utxo::new_p2pkh(crate::c_types::C_to_bitcoin_outpoint(outpoint), ::bitcoin::amount::Amount::from_sat(value), &bitcoin::PubkeyHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(unsafe { *pubkey_hash }.clone())));
	crate::lightning::events::bump_transaction::Utxo { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::events::bump_transaction::CoinSelection as nativeCoinSelectionImport;
pub(crate) type nativeCoinSelection = nativeCoinSelectionImport;

/// The result of a successful coin selection attempt for a transaction requiring additional UTXOs
/// to cover its fees.
#[must_use]
#[repr(C)]
pub struct CoinSelection {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCoinSelection,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for CoinSelection {
	type Target = nativeCoinSelection;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for CoinSelection { }
unsafe impl core::marker::Sync for CoinSelection { }
impl Drop for CoinSelection {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCoinSelection>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CoinSelection, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CoinSelection_free(this_obj: CoinSelection) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CoinSelection_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeCoinSelection) };
}
#[allow(unused)]
impl CoinSelection {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCoinSelection {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCoinSelection {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCoinSelection {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The set of UTXOs (with at least 1 confirmation) to spend and use within a transaction
/// requiring additional fees.
#[no_mangle]
pub extern "C" fn CoinSelection_get_confirmed_utxos(this_ptr: &CoinSelection) -> crate::c_types::derived::CVec_UtxoZ {
	let mut inner_val = &mut CoinSelection::get_native_mut_ref(this_ptr).confirmed_utxos;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::events::bump_transaction::Utxo { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::events::bump_transaction::Utxo<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The set of UTXOs (with at least 1 confirmation) to spend and use within a transaction
/// requiring additional fees.
#[no_mangle]
pub extern "C" fn CoinSelection_set_confirmed_utxos(this_ptr: &mut CoinSelection, mut val: crate::c_types::derived::CVec_UtxoZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.confirmed_utxos = local_val;
}
/// An additional output tracking whether any change remained after coin selection. This output
/// should always have a value above dust for its given `script_pubkey`. It should not be
/// spent until the transaction it belongs to confirms to ensure mempool descendant limits are
/// not met. This implies no other party should be able to spend it except us.
#[no_mangle]
pub extern "C" fn CoinSelection_get_change_output(this_ptr: &CoinSelection) -> crate::c_types::derived::COption_TxOutZ {
	let mut inner_val = &mut CoinSelection::get_native_mut_ref(this_ptr).change_output;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_TxOutZ::None } else { crate::c_types::derived::COption_TxOutZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::TxOut::from_rust(&(*inner_val.as_ref().unwrap()).clone()) }) };
	local_inner_val
}
/// An additional output tracking whether any change remained after coin selection. This output
/// should always have a value above dust for its given `script_pubkey`. It should not be
/// spent until the transaction it belongs to confirms to ensure mempool descendant limits are
/// not met. This implies no other party should be able to spend it except us.
#[no_mangle]
pub extern "C" fn CoinSelection_set_change_output(this_ptr: &mut CoinSelection, mut val: crate::c_types::derived::COption_TxOutZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_rust() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.change_output = local_val;
}
/// Constructs a new CoinSelection given each field
#[must_use]
#[no_mangle]
pub extern "C" fn CoinSelection_new(mut confirmed_utxos_arg: crate::c_types::derived::CVec_UtxoZ, mut change_output_arg: crate::c_types::derived::COption_TxOutZ) -> CoinSelection {
	let mut local_confirmed_utxos_arg = Vec::new(); for mut item in confirmed_utxos_arg.into_rust().drain(..) { local_confirmed_utxos_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_change_output_arg = { /*change_output_arg*/ let change_output_arg_opt = change_output_arg; if change_output_arg_opt.is_none() { None } else { Some({ { { change_output_arg_opt.take() }.into_rust() }})} };
	CoinSelection { inner: ObjOps::heap_alloc(nativeCoinSelection {
		confirmed_utxos: local_confirmed_utxos_arg,
		change_output: local_change_output_arg,
	}), is_owned: true }
}
impl Clone for CoinSelection {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeCoinSelection>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CoinSelection_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeCoinSelection) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the CoinSelection
pub extern "C" fn CoinSelection_clone(orig: &CoinSelection) -> CoinSelection {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a CoinSelection object
pub extern "C" fn CoinSelection_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::bump_transaction::CoinSelection }).into()}
