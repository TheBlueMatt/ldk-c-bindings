// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This module contains an [`OutputSweeper`] utility that keeps track of
//! [`SpendableOutputDescriptor`]s, i.e., persists them in a given [`KVStore`] and regularly retries
//! sweeping them.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// The number of blocks we wait before we prune the tracked spendable outputs.

#[no_mangle]
pub static PRUNE_DELAY_BLOCKS: u32 = lightning::util::sweep::PRUNE_DELAY_BLOCKS;

use lightning::util::sweep::TrackedSpendableOutput as nativeTrackedSpendableOutputImport;
pub(crate) type nativeTrackedSpendableOutput = nativeTrackedSpendableOutputImport;

/// The state of a spendable output currently tracked by an [`OutputSweeper`].
#[must_use]
#[repr(C)]
pub struct TrackedSpendableOutput {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTrackedSpendableOutput,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for TrackedSpendableOutput {
	type Target = nativeTrackedSpendableOutput;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for TrackedSpendableOutput { }
unsafe impl core::marker::Sync for TrackedSpendableOutput { }
impl Drop for TrackedSpendableOutput {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeTrackedSpendableOutput>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the TrackedSpendableOutput, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_free(this_obj: TrackedSpendableOutput) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TrackedSpendableOutput_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeTrackedSpendableOutput) };
}
#[allow(unused)]
impl TrackedSpendableOutput {
	pub(crate) fn get_native_ref(&self) -> &'static nativeTrackedSpendableOutput {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeTrackedSpendableOutput {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeTrackedSpendableOutput {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The tracked output descriptor.
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_get_descriptor(this_ptr: &TrackedSpendableOutput) -> crate::lightning::sign::SpendableOutputDescriptor {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().descriptor;
	crate::lightning::sign::SpendableOutputDescriptor::from_native(inner_val)
}
/// The tracked output descriptor.
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_set_descriptor(this_ptr: &mut TrackedSpendableOutput, mut val: crate::lightning::sign::SpendableOutputDescriptor) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.descriptor = val.into_native();
}
/// The channel this output belongs to.
///
/// Will be `None` if no `channel_id` was given to [`OutputSweeper::track_spendable_outputs`]
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_get_channel_id(this_ptr: &TrackedSpendableOutput) -> crate::lightning::ln::types::ChannelId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_id;
	let mut local_inner_val = crate::lightning::ln::types::ChannelId { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::types::ChannelId<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The channel this output belongs to.
///
/// Will be `None` if no `channel_id` was given to [`OutputSweeper::track_spendable_outputs`]
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_set_channel_id(this_ptr: &mut TrackedSpendableOutput, mut val: crate::lightning::ln::types::ChannelId) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_id = local_val;
}
/// The current status of the output spend.
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_get_status(this_ptr: &TrackedSpendableOutput) -> crate::lightning::util::sweep::OutputSpendStatus {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().status;
	crate::lightning::util::sweep::OutputSpendStatus::from_native(inner_val)
}
/// The current status of the output spend.
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_set_status(this_ptr: &mut TrackedSpendableOutput, mut val: crate::lightning::util::sweep::OutputSpendStatus) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.status = val.into_native();
}
/// Constructs a new TrackedSpendableOutput given each field
///
/// Note that channel_id_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_new(mut descriptor_arg: crate::lightning::sign::SpendableOutputDescriptor, mut channel_id_arg: crate::lightning::ln::types::ChannelId, mut status_arg: crate::lightning::util::sweep::OutputSpendStatus) -> TrackedSpendableOutput {
	let mut local_channel_id_arg = if channel_id_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_id_arg.take_inner()) } }) };
	TrackedSpendableOutput { inner: ObjOps::heap_alloc(nativeTrackedSpendableOutput {
		descriptor: descriptor_arg.into_native(),
		channel_id: local_channel_id_arg,
		status: status_arg.into_native(),
	}), is_owned: true }
}
impl Clone for TrackedSpendableOutput {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeTrackedSpendableOutput>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TrackedSpendableOutput_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeTrackedSpendableOutput)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the TrackedSpendableOutput
pub extern "C" fn TrackedSpendableOutput_clone(orig: &TrackedSpendableOutput) -> TrackedSpendableOutput {
	orig.clone()
}
/// Get a string which allows debug introspection of a TrackedSpendableOutput object
pub extern "C" fn TrackedSpendableOutput_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::sweep::TrackedSpendableOutput }).into()}
/// Checks if two TrackedSpendableOutputs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_eq(a: &TrackedSpendableOutput, b: &TrackedSpendableOutput) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns whether the output is spent in the given transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn TrackedSpendableOutput_is_spent_in(this_arg: &crate::lightning::util::sweep::TrackedSpendableOutput, mut tx: crate::c_types::Transaction) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_spent_in(&tx.into_bitcoin());
	ret
}

#[no_mangle]
/// Serialize the TrackedSpendableOutput object into a byte array which can be read by TrackedSpendableOutput_read
pub extern "C" fn TrackedSpendableOutput_write(obj: &crate::lightning::util::sweep::TrackedSpendableOutput) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn TrackedSpendableOutput_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::util::sweep::nativeTrackedSpendableOutput) })
}
#[no_mangle]
/// Read a TrackedSpendableOutput from a byte array, created by TrackedSpendableOutput_write
pub extern "C" fn TrackedSpendableOutput_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_TrackedSpendableOutputDecodeErrorZ {
	let res: Result<lightning::util::sweep::TrackedSpendableOutput, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::sweep::TrackedSpendableOutput { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// The current status of the output spend.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum OutputSpendStatus {
	/// The output is tracked but an initial spending transaction hasn't been generated and
	/// broadcasted yet.
	PendingInitialBroadcast {
		/// The height at which we will first generate and broadcast a spending transaction.
		delayed_until_height: crate::c_types::derived::COption_u32Z,
	},
	/// A transaction spending the output has been broadcasted but is pending its first confirmation on-chain.
	PendingFirstConfirmation {
		/// The hash of the chain tip when we first broadcast a transaction spending this output.
		first_broadcast_hash: crate::c_types::ThirtyTwoBytes,
		/// The best height when we last broadcast a transaction spending this output.
		latest_broadcast_height: u32,
		/// The transaction spending this output we last broadcasted.
		latest_spending_tx: crate::c_types::Transaction,
	},
	/// A transaction spending the output has been confirmed on-chain but will be tracked until it
	/// reaches at least [`PRUNE_DELAY_BLOCKS`] confirmations to ensure [`Event::SpendableOutputs`]
	/// stemming from lingering [`ChannelMonitor`]s can safely be replayed.
	///
	/// [`Event::SpendableOutputs`]: crate::events::Event::SpendableOutputs
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	PendingThresholdConfirmations {
		/// The hash of the chain tip when we first broadcast a transaction spending this output.
		first_broadcast_hash: crate::c_types::ThirtyTwoBytes,
		/// The best height when we last broadcast a transaction spending this output.
		latest_broadcast_height: u32,
		/// The transaction spending this output we saw confirmed on-chain.
		latest_spending_tx: crate::c_types::Transaction,
		/// The height at which the spending transaction was confirmed.
		confirmation_height: u32,
		/// The hash of the block in which the spending transaction was confirmed.
		confirmation_hash: crate::c_types::ThirtyTwoBytes,
	},
}
use lightning::util::sweep::OutputSpendStatus as OutputSpendStatusImport;
pub(crate) type nativeOutputSpendStatus = OutputSpendStatusImport;

impl OutputSpendStatus {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeOutputSpendStatus {
		match self {
			OutputSpendStatus::PendingInitialBroadcast {ref delayed_until_height, } => {
				let mut delayed_until_height_nonref = Clone::clone(delayed_until_height);
				let mut local_delayed_until_height_nonref = if delayed_until_height_nonref.is_some() { Some( { delayed_until_height_nonref.take() }) } else { None };
				nativeOutputSpendStatus::PendingInitialBroadcast {
					delayed_until_height: local_delayed_until_height_nonref,
				}
			},
			OutputSpendStatus::PendingFirstConfirmation {ref first_broadcast_hash, ref latest_broadcast_height, ref latest_spending_tx, } => {
				let mut first_broadcast_hash_nonref = Clone::clone(first_broadcast_hash);
				let mut latest_broadcast_height_nonref = Clone::clone(latest_broadcast_height);
				let mut latest_spending_tx_nonref = Clone::clone(latest_spending_tx);
				nativeOutputSpendStatus::PendingFirstConfirmation {
					first_broadcast_hash: ::bitcoin::hash_types::BlockHash::from_slice(&first_broadcast_hash_nonref.data[..]).unwrap(),
					latest_broadcast_height: latest_broadcast_height_nonref,
					latest_spending_tx: latest_spending_tx_nonref.into_bitcoin(),
				}
			},
			OutputSpendStatus::PendingThresholdConfirmations {ref first_broadcast_hash, ref latest_broadcast_height, ref latest_spending_tx, ref confirmation_height, ref confirmation_hash, } => {
				let mut first_broadcast_hash_nonref = Clone::clone(first_broadcast_hash);
				let mut latest_broadcast_height_nonref = Clone::clone(latest_broadcast_height);
				let mut latest_spending_tx_nonref = Clone::clone(latest_spending_tx);
				let mut confirmation_height_nonref = Clone::clone(confirmation_height);
				let mut confirmation_hash_nonref = Clone::clone(confirmation_hash);
				nativeOutputSpendStatus::PendingThresholdConfirmations {
					first_broadcast_hash: ::bitcoin::hash_types::BlockHash::from_slice(&first_broadcast_hash_nonref.data[..]).unwrap(),
					latest_broadcast_height: latest_broadcast_height_nonref,
					latest_spending_tx: latest_spending_tx_nonref.into_bitcoin(),
					confirmation_height: confirmation_height_nonref,
					confirmation_hash: ::bitcoin::hash_types::BlockHash::from_slice(&confirmation_hash_nonref.data[..]).unwrap(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeOutputSpendStatus {
		match self {
			OutputSpendStatus::PendingInitialBroadcast {mut delayed_until_height, } => {
				let mut local_delayed_until_height = if delayed_until_height.is_some() { Some( { delayed_until_height.take() }) } else { None };
				nativeOutputSpendStatus::PendingInitialBroadcast {
					delayed_until_height: local_delayed_until_height,
				}
			},
			OutputSpendStatus::PendingFirstConfirmation {mut first_broadcast_hash, mut latest_broadcast_height, mut latest_spending_tx, } => {
				nativeOutputSpendStatus::PendingFirstConfirmation {
					first_broadcast_hash: ::bitcoin::hash_types::BlockHash::from_slice(&first_broadcast_hash.data[..]).unwrap(),
					latest_broadcast_height: latest_broadcast_height,
					latest_spending_tx: latest_spending_tx.into_bitcoin(),
				}
			},
			OutputSpendStatus::PendingThresholdConfirmations {mut first_broadcast_hash, mut latest_broadcast_height, mut latest_spending_tx, mut confirmation_height, mut confirmation_hash, } => {
				nativeOutputSpendStatus::PendingThresholdConfirmations {
					first_broadcast_hash: ::bitcoin::hash_types::BlockHash::from_slice(&first_broadcast_hash.data[..]).unwrap(),
					latest_broadcast_height: latest_broadcast_height,
					latest_spending_tx: latest_spending_tx.into_bitcoin(),
					confirmation_height: confirmation_height,
					confirmation_hash: ::bitcoin::hash_types::BlockHash::from_slice(&confirmation_hash.data[..]).unwrap(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &OutputSpendStatusImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeOutputSpendStatus) };
		match native {
			nativeOutputSpendStatus::PendingInitialBroadcast {ref delayed_until_height, } => {
				let mut delayed_until_height_nonref = Clone::clone(delayed_until_height);
				let mut local_delayed_until_height_nonref = if delayed_until_height_nonref.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { delayed_until_height_nonref.unwrap() }) };
				OutputSpendStatus::PendingInitialBroadcast {
					delayed_until_height: local_delayed_until_height_nonref,
				}
			},
			nativeOutputSpendStatus::PendingFirstConfirmation {ref first_broadcast_hash, ref latest_broadcast_height, ref latest_spending_tx, } => {
				let mut first_broadcast_hash_nonref = Clone::clone(first_broadcast_hash);
				let mut latest_broadcast_height_nonref = Clone::clone(latest_broadcast_height);
				let mut latest_spending_tx_nonref = Clone::clone(latest_spending_tx);
				OutputSpendStatus::PendingFirstConfirmation {
					first_broadcast_hash: crate::c_types::ThirtyTwoBytes { data: *first_broadcast_hash_nonref.as_ref() },
					latest_broadcast_height: latest_broadcast_height_nonref,
					latest_spending_tx: crate::c_types::Transaction::from_bitcoin(&latest_spending_tx_nonref),
				}
			},
			nativeOutputSpendStatus::PendingThresholdConfirmations {ref first_broadcast_hash, ref latest_broadcast_height, ref latest_spending_tx, ref confirmation_height, ref confirmation_hash, } => {
				let mut first_broadcast_hash_nonref = Clone::clone(first_broadcast_hash);
				let mut latest_broadcast_height_nonref = Clone::clone(latest_broadcast_height);
				let mut latest_spending_tx_nonref = Clone::clone(latest_spending_tx);
				let mut confirmation_height_nonref = Clone::clone(confirmation_height);
				let mut confirmation_hash_nonref = Clone::clone(confirmation_hash);
				OutputSpendStatus::PendingThresholdConfirmations {
					first_broadcast_hash: crate::c_types::ThirtyTwoBytes { data: *first_broadcast_hash_nonref.as_ref() },
					latest_broadcast_height: latest_broadcast_height_nonref,
					latest_spending_tx: crate::c_types::Transaction::from_bitcoin(&latest_spending_tx_nonref),
					confirmation_height: confirmation_height_nonref,
					confirmation_hash: crate::c_types::ThirtyTwoBytes { data: *confirmation_hash_nonref.as_ref() },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeOutputSpendStatus) -> Self {
		match native {
			nativeOutputSpendStatus::PendingInitialBroadcast {mut delayed_until_height, } => {
				let mut local_delayed_until_height = if delayed_until_height.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { delayed_until_height.unwrap() }) };
				OutputSpendStatus::PendingInitialBroadcast {
					delayed_until_height: local_delayed_until_height,
				}
			},
			nativeOutputSpendStatus::PendingFirstConfirmation {mut first_broadcast_hash, mut latest_broadcast_height, mut latest_spending_tx, } => {
				OutputSpendStatus::PendingFirstConfirmation {
					first_broadcast_hash: crate::c_types::ThirtyTwoBytes { data: *first_broadcast_hash.as_ref() },
					latest_broadcast_height: latest_broadcast_height,
					latest_spending_tx: crate::c_types::Transaction::from_bitcoin(&latest_spending_tx),
				}
			},
			nativeOutputSpendStatus::PendingThresholdConfirmations {mut first_broadcast_hash, mut latest_broadcast_height, mut latest_spending_tx, mut confirmation_height, mut confirmation_hash, } => {
				OutputSpendStatus::PendingThresholdConfirmations {
					first_broadcast_hash: crate::c_types::ThirtyTwoBytes { data: *first_broadcast_hash.as_ref() },
					latest_broadcast_height: latest_broadcast_height,
					latest_spending_tx: crate::c_types::Transaction::from_bitcoin(&latest_spending_tx),
					confirmation_height: confirmation_height,
					confirmation_hash: crate::c_types::ThirtyTwoBytes { data: *confirmation_hash.as_ref() },
				}
			},
		}
	}
}
/// Frees any resources used by the OutputSpendStatus
#[no_mangle]
pub extern "C" fn OutputSpendStatus_free(this_ptr: OutputSpendStatus) { }
/// Creates a copy of the OutputSpendStatus
#[no_mangle]
pub extern "C" fn OutputSpendStatus_clone(orig: &OutputSpendStatus) -> OutputSpendStatus {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutputSpendStatus_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const OutputSpendStatus)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutputSpendStatus_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut OutputSpendStatus) };
}
#[no_mangle]
/// Utility method to constructs a new PendingInitialBroadcast-variant OutputSpendStatus
pub extern "C" fn OutputSpendStatus_pending_initial_broadcast(delayed_until_height: crate::c_types::derived::COption_u32Z) -> OutputSpendStatus {
	OutputSpendStatus::PendingInitialBroadcast {
		delayed_until_height,
	}
}
#[no_mangle]
/// Utility method to constructs a new PendingFirstConfirmation-variant OutputSpendStatus
pub extern "C" fn OutputSpendStatus_pending_first_confirmation(first_broadcast_hash: crate::c_types::ThirtyTwoBytes, latest_broadcast_height: u32, latest_spending_tx: crate::c_types::Transaction) -> OutputSpendStatus {
	OutputSpendStatus::PendingFirstConfirmation {
		first_broadcast_hash,
		latest_broadcast_height,
		latest_spending_tx,
	}
}
#[no_mangle]
/// Utility method to constructs a new PendingThresholdConfirmations-variant OutputSpendStatus
pub extern "C" fn OutputSpendStatus_pending_threshold_confirmations(first_broadcast_hash: crate::c_types::ThirtyTwoBytes, latest_broadcast_height: u32, latest_spending_tx: crate::c_types::Transaction, confirmation_height: u32, confirmation_hash: crate::c_types::ThirtyTwoBytes) -> OutputSpendStatus {
	OutputSpendStatus::PendingThresholdConfirmations {
		first_broadcast_hash,
		latest_broadcast_height,
		latest_spending_tx,
		confirmation_height,
		confirmation_hash,
	}
}
/// Get a string which allows debug introspection of a OutputSpendStatus object
pub extern "C" fn OutputSpendStatus_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::sweep::OutputSpendStatus }).into()}
/// Checks if two OutputSpendStatuss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn OutputSpendStatus_eq(a: &OutputSpendStatus, b: &OutputSpendStatus) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the OutputSpendStatus object into a byte array which can be read by OutputSpendStatus_read
pub extern "C" fn OutputSpendStatus_write(obj: &crate::lightning::util::sweep::OutputSpendStatus) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn OutputSpendStatus_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	OutputSpendStatus_write(unsafe { &*(obj as *const OutputSpendStatus) })
}
#[no_mangle]
/// Read a OutputSpendStatus from a byte array, created by OutputSpendStatus_write
pub extern "C" fn OutputSpendStatus_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OutputSpendStatusDecodeErrorZ {
	let res: Result<lightning::util::sweep::OutputSpendStatus, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::sweep::OutputSpendStatus::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::util::sweep::OutputSweeper as nativeOutputSweeperImport;
pub(crate) type nativeOutputSweeper = nativeOutputSweeperImport<crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::ChangeDestinationSource, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::chain::Filter, crate::lightning::util::persist::KVStore, crate::lightning::util::logger::Logger, crate::lightning::sign::OutputSpender, >;

/// A utility that keeps track of [`SpendableOutputDescriptor`]s, persists them in a given
/// [`KVStore`] and regularly retries sweeping them based on a callback given to the constructor
/// methods.
///
/// Users should call [`Self::track_spendable_outputs`] for any [`SpendableOutputDescriptor`]s received via [`Event::SpendableOutputs`].
///
/// This needs to be notified of chain state changes either via its [`Listen`] or [`Confirm`]
/// implementation and hence has to be connected with the utilized chain data sources.
///
/// If chain data is provided via the [`Confirm`] interface or via filtered blocks, users are
/// required to give their chain data sources (i.e., [`Filter`] implementation) to the respective
/// constructor.
///
/// [`Event::SpendableOutputs`]: crate::events::Event::SpendableOutputs
#[must_use]
#[repr(C)]
pub struct OutputSweeper {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOutputSweeper,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OutputSweeper {
	type Target = nativeOutputSweeper;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OutputSweeper { }
unsafe impl core::marker::Sync for OutputSweeper { }
impl Drop for OutputSweeper {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOutputSweeper>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OutputSweeper, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OutputSweeper_free(this_obj: OutputSweeper) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutputSweeper_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOutputSweeper) };
}
#[allow(unused)]
impl OutputSweeper {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOutputSweeper {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOutputSweeper {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOutputSweeper {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new [`OutputSweeper`].
///
/// If chain data is provided via the [`Confirm`] interface or via filtered blocks, users also
/// need to register their [`Filter`] implementation via the given `chain_data_source`.
#[must_use]
#[no_mangle]
pub extern "C" fn OutputSweeper_new(mut best_block: crate::lightning::chain::BestBlock, mut broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut fee_estimator: crate::lightning::chain::chaininterface::FeeEstimator, mut chain_data_source: crate::c_types::derived::COption_FilterZ, mut output_spender: crate::lightning::sign::OutputSpender, mut change_destination_source: crate::lightning::sign::ChangeDestinationSource, mut kv_store: crate::lightning::util::persist::KVStore, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::util::sweep::OutputSweeper {
	let mut local_chain_data_source = { /*chain_data_source*/ let chain_data_source_opt = chain_data_source; if chain_data_source_opt.is_none() { None } else { Some({ { { chain_data_source_opt.take() } }})} };
	let mut ret = lightning::util::sweep::OutputSweeper::new(*unsafe { Box::from_raw(best_block.take_inner()) }, broadcaster, fee_estimator, local_chain_data_source, output_spender, change_destination_source, kv_store, logger);
	crate::lightning::util::sweep::OutputSweeper { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Tells the sweeper to track the given outputs descriptors.
///
/// Usually, this should be called based on the values emitted by the
/// [`Event::SpendableOutputs`].
///
/// The given `exclude_static_outputs` flag controls whether the sweeper will filter out
/// [`SpendableOutputDescriptor::StaticOutput`]s, which may be handled directly by the on-chain
/// wallet implementation.
///
/// If `delay_until_height` is set, we will delay the spending until the respective block
/// height is reached. This can be used to batch spends, e.g., to reduce on-chain fees.
///
/// Returns `Err` on persistence failure, in which case the call may be safely retried.
///
/// [`Event::SpendableOutputs`]: crate::events::Event::SpendableOutputs
///
/// Note that channel_id (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn OutputSweeper_track_spendable_outputs(this_arg: &crate::lightning::util::sweep::OutputSweeper, mut output_descriptors: crate::c_types::derived::CVec_SpendableOutputDescriptorZ, mut channel_id: crate::lightning::ln::types::ChannelId, mut exclude_static_outputs: bool, mut delay_until_height: crate::c_types::derived::COption_u32Z) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut local_output_descriptors = Vec::new(); for mut item in output_descriptors.into_rust().drain(..) { local_output_descriptors.push( { item.into_native() }); };
	let mut local_channel_id = if channel_id.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_id.take_inner()) } }) };
	let mut local_delay_until_height = if delay_until_height.is_some() { Some( { delay_until_height.take() }) } else { None };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.track_spendable_outputs(local_output_descriptors, local_channel_id, exclude_static_outputs, local_delay_until_height);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Returns a list of the currently tracked spendable outputs.
#[must_use]
#[no_mangle]
pub extern "C" fn OutputSweeper_tracked_spendable_outputs(this_arg: &crate::lightning::util::sweep::OutputSweeper) -> crate::c_types::derived::CVec_TrackedSpendableOutputZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tracked_spendable_outputs();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::util::sweep::TrackedSpendableOutput { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Gets the latest best block which was connected either via the [`Listen`] or
/// [`Confirm`] interfaces.
#[must_use]
#[no_mangle]
pub extern "C" fn OutputSweeper_current_best_block(this_arg: &crate::lightning::util::sweep::OutputSweeper) -> crate::lightning::chain::BestBlock {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.current_best_block();
	crate::lightning::chain::BestBlock { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeOutputSweeper> for crate::lightning::chain::Listen {
	fn from(obj: nativeOutputSweeper) -> Self {
		let rust_obj = crate::lightning::util::sweep::OutputSweeper { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OutputSweeper_as_Listen(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(OutputSweeper_free_void);
		ret
	}
}
/// Constructs a new Listen which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Listen must be freed before this_arg is
#[no_mangle]
pub extern "C" fn OutputSweeper_as_Listen(this_arg: &OutputSweeper) -> crate::lightning::chain::Listen {
	crate::lightning::chain::Listen {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		filtered_block_connected: OutputSweeper_Listen_filtered_block_connected,
		block_connected: OutputSweeper_Listen_block_connected,
		block_disconnected: OutputSweeper_Listen_block_disconnected,
	}
}

extern "C" fn OutputSweeper_Listen_filtered_block_connected(this_arg: *const c_void, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32) {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	<nativeOutputSweeper as lightning::chain::Listen>::filtered_block_connected(unsafe { &mut *(this_arg as *mut nativeOutputSweeper) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height)
}
extern "C" fn OutputSweeper_Listen_block_connected(this_arg: *const c_void, mut block: crate::c_types::u8slice, mut height: u32) {
	<nativeOutputSweeper as lightning::chain::Listen>::block_connected(unsafe { &mut *(this_arg as *mut nativeOutputSweeper) }, &::bitcoin::consensus::encode::deserialize(block.to_slice()).unwrap(), height)
}
extern "C" fn OutputSweeper_Listen_block_disconnected(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeOutputSweeper as lightning::chain::Listen>::block_disconnected(unsafe { &mut *(this_arg as *mut nativeOutputSweeper) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}

impl From<nativeOutputSweeper> for crate::lightning::chain::Confirm {
	fn from(obj: nativeOutputSweeper) -> Self {
		let rust_obj = crate::lightning::util::sweep::OutputSweeper { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OutputSweeper_as_Confirm(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(OutputSweeper_free_void);
		ret
	}
}
/// Constructs a new Confirm which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Confirm must be freed before this_arg is
#[no_mangle]
pub extern "C" fn OutputSweeper_as_Confirm(this_arg: &OutputSweeper) -> crate::lightning::chain::Confirm {
	crate::lightning::chain::Confirm {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		transactions_confirmed: OutputSweeper_Confirm_transactions_confirmed,
		transaction_unconfirmed: OutputSweeper_Confirm_transaction_unconfirmed,
		best_block_updated: OutputSweeper_Confirm_best_block_updated,
		get_relevant_txids: OutputSweeper_Confirm_get_relevant_txids,
	}
}

extern "C" fn OutputSweeper_Confirm_transactions_confirmed(this_arg: *const c_void, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32) {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	<nativeOutputSweeper as lightning::chain::Confirm>::transactions_confirmed(unsafe { &mut *(this_arg as *mut nativeOutputSweeper) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height)
}
extern "C" fn OutputSweeper_Confirm_transaction_unconfirmed(this_arg: *const c_void, txid: *const [u8; 32]) {
	<nativeOutputSweeper as lightning::chain::Confirm>::transaction_unconfirmed(unsafe { &mut *(this_arg as *mut nativeOutputSweeper) }, &::bitcoin::hash_types::Txid::from_slice(&unsafe { &*txid }[..]).unwrap())
}
extern "C" fn OutputSweeper_Confirm_best_block_updated(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeOutputSweeper as lightning::chain::Confirm>::best_block_updated(unsafe { &mut *(this_arg as *mut nativeOutputSweeper) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}
#[must_use]
extern "C" fn OutputSweeper_Confirm_get_relevant_txids(this_arg: *const c_void) -> crate::c_types::derived::CVec_C3Tuple_ThirtyTwoBytesu32COption_ThirtyTwoBytesZZZ {
	let mut ret = <nativeOutputSweeper as lightning::chain::Confirm>::get_relevant_txids(unsafe { &mut *(this_arg as *mut nativeOutputSweeper) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item; let mut local_orig_ret_0_2 = if orig_ret_0_2.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: *orig_ret_0_2.unwrap().as_ref() } }) }; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: *orig_ret_0_0.as_ref() }, orig_ret_0_1, local_orig_ret_0_2).into(); local_ret_0 }); };
	local_ret.into()
}

/// A `enum` signalling to the [`OutputSweeper`] that it should delay spending an output until a
/// future block height is reached.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SpendingDelay {
	/// A relative delay indicating we shouldn't spend the output before `cur_height + num_blocks`
	/// is reached.
	Relative {
		/// The number of blocks until we'll generate and broadcast the spending transaction.
		num_blocks: u32,
	},
	/// An absolute delay indicating we shouldn't spend the output before `height` is reached.
	Absolute {
		/// The height at which we'll generate and broadcast the spending transaction.
		height: u32,
	},
}
use lightning::util::sweep::SpendingDelay as SpendingDelayImport;
pub(crate) type nativeSpendingDelay = SpendingDelayImport;

impl SpendingDelay {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSpendingDelay {
		match self {
			SpendingDelay::Relative {ref num_blocks, } => {
				let mut num_blocks_nonref = Clone::clone(num_blocks);
				nativeSpendingDelay::Relative {
					num_blocks: num_blocks_nonref,
				}
			},
			SpendingDelay::Absolute {ref height, } => {
				let mut height_nonref = Clone::clone(height);
				nativeSpendingDelay::Absolute {
					height: height_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSpendingDelay {
		match self {
			SpendingDelay::Relative {mut num_blocks, } => {
				nativeSpendingDelay::Relative {
					num_blocks: num_blocks,
				}
			},
			SpendingDelay::Absolute {mut height, } => {
				nativeSpendingDelay::Absolute {
					height: height,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &SpendingDelayImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeSpendingDelay) };
		match native {
			nativeSpendingDelay::Relative {ref num_blocks, } => {
				let mut num_blocks_nonref = Clone::clone(num_blocks);
				SpendingDelay::Relative {
					num_blocks: num_blocks_nonref,
				}
			},
			nativeSpendingDelay::Absolute {ref height, } => {
				let mut height_nonref = Clone::clone(height);
				SpendingDelay::Absolute {
					height: height_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSpendingDelay) -> Self {
		match native {
			nativeSpendingDelay::Relative {mut num_blocks, } => {
				SpendingDelay::Relative {
					num_blocks: num_blocks,
				}
			},
			nativeSpendingDelay::Absolute {mut height, } => {
				SpendingDelay::Absolute {
					height: height,
				}
			},
		}
	}
}
/// Frees any resources used by the SpendingDelay
#[no_mangle]
pub extern "C" fn SpendingDelay_free(this_ptr: SpendingDelay) { }
/// Creates a copy of the SpendingDelay
#[no_mangle]
pub extern "C" fn SpendingDelay_clone(orig: &SpendingDelay) -> SpendingDelay {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SpendingDelay_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const SpendingDelay)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SpendingDelay_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut SpendingDelay) };
}
#[no_mangle]
/// Utility method to constructs a new Relative-variant SpendingDelay
pub extern "C" fn SpendingDelay_relative(num_blocks: u32) -> SpendingDelay {
	SpendingDelay::Relative {
		num_blocks,
	}
}
#[no_mangle]
/// Utility method to constructs a new Absolute-variant SpendingDelay
pub extern "C" fn SpendingDelay_absolute(height: u32) -> SpendingDelay {
	SpendingDelay::Absolute {
		height,
	}
}
/// Get a string which allows debug introspection of a SpendingDelay object
pub extern "C" fn SpendingDelay_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::sweep::SpendingDelay }).into()}
#[no_mangle]
/// Read a OutputSweeper from a byte array, created by OutputSweeper_write
pub extern "C" fn OutputSweeper_read(ser: crate::c_types::u8slice, arg_a: crate::lightning::chain::chaininterface::BroadcasterInterface, arg_b: crate::lightning::chain::chaininterface::FeeEstimator, arg_c: crate::c_types::derived::COption_FilterZ, arg_d: crate::lightning::sign::OutputSpender, arg_e: crate::lightning::sign::ChangeDestinationSource, arg_f: crate::lightning::util::persist::KVStore, arg_g: crate::lightning::util::logger::Logger) -> crate::c_types::derived::CResult_OutputSweeperDecodeErrorZ {
	let arg_a_conv = arg_a;
	let arg_b_conv = arg_b;
	let mut local_arg_c = { /*arg_c*/ let arg_c_opt = arg_c; if arg_c_opt.is_none() { None } else { Some({ { { arg_c_opt.take() } }})} };
	let arg_c_conv = local_arg_c;
	let arg_d_conv = arg_d;
	let arg_e_conv = arg_e;
	let arg_f_conv = arg_f;
	let arg_g_conv = arg_g;
	let arg_conv = (arg_a_conv, arg_b_conv, arg_c_conv, arg_d_conv, arg_e_conv, arg_f_conv, arg_g_conv);
	let res: Result<lightning::util::sweep::OutputSweeper<crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::ChangeDestinationSource, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::chain::Filter, crate::lightning::util::persist::KVStore, crate::lightning::util::logger::Logger, crate::lightning::sign::OutputSpender>, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::sweep::OutputSweeper { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Read a C2Tuple_BestBlockOutputSweeperZ from a byte array, created by C2Tuple_BestBlockOutputSweeperZ_write
pub extern "C" fn C2Tuple_BestBlockOutputSweeperZ_read(ser: crate::c_types::u8slice, arg_a: crate::lightning::chain::chaininterface::BroadcasterInterface, arg_b: crate::lightning::chain::chaininterface::FeeEstimator, arg_c: crate::c_types::derived::COption_FilterZ, arg_d: crate::lightning::sign::OutputSpender, arg_e: crate::lightning::sign::ChangeDestinationSource, arg_f: crate::lightning::util::persist::KVStore, arg_g: crate::lightning::util::logger::Logger) -> crate::c_types::derived::CResult_C2Tuple_BestBlockOutputSweeperZDecodeErrorZ {
	let arg_a_conv = arg_a;
	let arg_b_conv = arg_b;
	let mut local_arg_c = { /*arg_c*/ let arg_c_opt = arg_c; if arg_c_opt.is_none() { None } else { Some({ { { arg_c_opt.take() } }})} };
	let arg_c_conv = local_arg_c;
	let arg_d_conv = arg_d;
	let arg_e_conv = arg_e;
	let arg_f_conv = arg_f;
	let arg_g_conv = arg_g;
	let arg_conv = (arg_a_conv, arg_b_conv, arg_c_conv, arg_d_conv, arg_e_conv, arg_f_conv, arg_g_conv);
	let res: Result<(lightning::chain::BestBlock, lightning::util::sweep::OutputSweeper<crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::ChangeDestinationSource, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::chain::Filter, crate::lightning::util::persist::KVStore, crate::lightning::util::logger::Logger, crate::lightning::sign::OutputSpender>), lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_res_0_0, mut orig_res_0_1) = o; let mut local_res_0 = (crate::lightning::chain::BestBlock { inner: ObjOps::heap_alloc(orig_res_0_0), is_owned: true }, crate::lightning::util::sweep::OutputSweeper { inner: ObjOps::heap_alloc(orig_res_0_1), is_owned: true }).into(); local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
