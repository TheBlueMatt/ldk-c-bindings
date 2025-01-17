// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Information about the state of a channel.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Exposes the state of pending inbound HTLCs.
///
/// At a high level, an HTLC being forwarded from one Lightning node to another Lightning node goes
/// through the following states in the state machine:
/// - Announced for addition by the originating node through the update_add_htlc message.
/// - Added to the commitment transaction of the receiving node and originating node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
/// - Announced for resolution (fulfillment or failure) by the receiving node through either one of
///   the update_fulfill_htlc, update_fail_htlc, and update_fail_malformed_htlc messages.
/// - Removed from the commitment transaction of the originating node and receiving node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
///
/// This can be used to inspect what next message an HTLC is waiting for to advance its state.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum InboundHTLCStateDetails {
	/// We have added this HTLC in our commitment transaction by receiving commitment_signed and
	/// returning revoke_and_ack. We are awaiting the appropriate revoke_and_ack's from the remote
	/// before this HTLC is included on the remote commitment transaction.
	AwaitingRemoteRevokeToAdd,
	/// This HTLC has been included in the commitment_signed and revoke_and_ack messages on both sides
	/// and is included in both commitment transactions.
	///
	/// This HTLC is now safe to either forward or be claimed as a payment by us. The HTLC will
	/// remain in this state until the forwarded upstream HTLC has been resolved and we resolve this
	/// HTLC correspondingly, or until we claim it as a payment. If it is part of a multipart
	/// payment, it will only be claimed together with other required parts.
	Committed,
	/// We have received the preimage for this HTLC and it is being removed by fulfilling it with
	/// update_fulfill_htlc. This HTLC is still on both commitment transactions, but we are awaiting
	/// the appropriate revoke_and_ack's from the remote before this HTLC is removed from the remote
	/// commitment transaction after update_fulfill_htlc.
	AwaitingRemoteRevokeToRemoveFulfill,
	/// The HTLC is being removed by failing it with update_fail_htlc or update_fail_malformed_htlc.
	/// This HTLC is still on both commitment transactions, but we are awaiting the appropriate
	/// revoke_and_ack's from the remote before this HTLC is removed from the remote commitment
	/// transaction.
	AwaitingRemoteRevokeToRemoveFail,
}
use lightning::ln::channel_state::InboundHTLCStateDetails as InboundHTLCStateDetailsImport;
pub(crate) type nativeInboundHTLCStateDetails = InboundHTLCStateDetailsImport;

impl InboundHTLCStateDetails {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeInboundHTLCStateDetails {
		match self {
			InboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			InboundHTLCStateDetails::Committed => nativeInboundHTLCStateDetails::Committed,
			InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill => nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill,
			InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail => nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeInboundHTLCStateDetails {
		match self {
			InboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			InboundHTLCStateDetails::Committed => nativeInboundHTLCStateDetails::Committed,
			InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill => nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill,
			InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail => nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &InboundHTLCStateDetailsImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeInboundHTLCStateDetails) };
		match native {
			nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => InboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			nativeInboundHTLCStateDetails::Committed => InboundHTLCStateDetails::Committed,
			nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill => InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill,
			nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail => InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeInboundHTLCStateDetails) -> Self {
		match native {
			nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => InboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			nativeInboundHTLCStateDetails::Committed => InboundHTLCStateDetails::Committed,
			nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill => InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill,
			nativeInboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail => InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail,
		}
	}
}
/// Creates a copy of the InboundHTLCStateDetails
#[no_mangle]
pub extern "C" fn InboundHTLCStateDetails_clone(orig: &InboundHTLCStateDetails) -> InboundHTLCStateDetails {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InboundHTLCStateDetails_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const InboundHTLCStateDetails)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InboundHTLCStateDetails_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut InboundHTLCStateDetails) };
}
#[no_mangle]
/// Utility method to constructs a new AwaitingRemoteRevokeToAdd-variant InboundHTLCStateDetails
pub extern "C" fn InboundHTLCStateDetails_awaiting_remote_revoke_to_add() -> InboundHTLCStateDetails {
	InboundHTLCStateDetails::AwaitingRemoteRevokeToAdd}
#[no_mangle]
/// Utility method to constructs a new Committed-variant InboundHTLCStateDetails
pub extern "C" fn InboundHTLCStateDetails_committed() -> InboundHTLCStateDetails {
	InboundHTLCStateDetails::Committed}
#[no_mangle]
/// Utility method to constructs a new AwaitingRemoteRevokeToRemoveFulfill-variant InboundHTLCStateDetails
pub extern "C" fn InboundHTLCStateDetails_awaiting_remote_revoke_to_remove_fulfill() -> InboundHTLCStateDetails {
	InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill}
#[no_mangle]
/// Utility method to constructs a new AwaitingRemoteRevokeToRemoveFail-variant InboundHTLCStateDetails
pub extern "C" fn InboundHTLCStateDetails_awaiting_remote_revoke_to_remove_fail() -> InboundHTLCStateDetails {
	InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail}
/// Get a string which allows debug introspection of a InboundHTLCStateDetails object
pub extern "C" fn InboundHTLCStateDetails_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::InboundHTLCStateDetails }).into()}
#[no_mangle]
/// Serialize the InboundHTLCStateDetails object into a byte array which can be read by InboundHTLCStateDetails_read
pub extern "C" fn InboundHTLCStateDetails_write(obj: &crate::lightning::ln::channel_state::InboundHTLCStateDetails) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn InboundHTLCStateDetails_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	InboundHTLCStateDetails_write(unsafe { &*(obj as *const InboundHTLCStateDetails) })
}
#[no_mangle]
/// Read a InboundHTLCStateDetails from a byte array, created by InboundHTLCStateDetails_write
pub extern "C" fn InboundHTLCStateDetails_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_InboundHTLCStateDetailsZDecodeErrorZ {
	let res: Result<Option<lightning::ln::channel_state::InboundHTLCStateDetails>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_InboundHTLCStateDetailsZ::None } else { crate::c_types::derived::COption_InboundHTLCStateDetailsZ::Some( { crate::lightning::ln::channel_state::InboundHTLCStateDetails::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_state::InboundHTLCDetails as nativeInboundHTLCDetailsImport;
pub(crate) type nativeInboundHTLCDetails = nativeInboundHTLCDetailsImport;

/// Exposes details around pending inbound HTLCs.
#[must_use]
#[repr(C)]
pub struct InboundHTLCDetails {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInboundHTLCDetails,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for InboundHTLCDetails {
	type Target = nativeInboundHTLCDetails;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for InboundHTLCDetails { }
unsafe impl core::marker::Sync for InboundHTLCDetails { }
impl Drop for InboundHTLCDetails {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInboundHTLCDetails>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InboundHTLCDetails, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_free(this_obj: InboundHTLCDetails) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InboundHTLCDetails_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInboundHTLCDetails) };
}
#[allow(unused)]
impl InboundHTLCDetails {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInboundHTLCDetails {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInboundHTLCDetails {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInboundHTLCDetails {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The HTLC ID.
/// The IDs are incremented by 1 starting from 0 for each offered HTLC.
/// They are unique per channel and inbound/outbound direction, unless an HTLC was only announced
/// and not part of any commitment transaction.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_get_htlc_id(this_ptr: &InboundHTLCDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_id;
	*inner_val
}
/// The HTLC ID.
/// The IDs are incremented by 1 starting from 0 for each offered HTLC.
/// They are unique per channel and inbound/outbound direction, unless an HTLC was only announced
/// and not part of any commitment transaction.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_set_htlc_id(this_ptr: &mut InboundHTLCDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_id = val;
}
/// The amount in msat.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_get_amount_msat(this_ptr: &InboundHTLCDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().amount_msat;
	*inner_val
}
/// The amount in msat.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_set_amount_msat(this_ptr: &mut InboundHTLCDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.amount_msat = val;
}
/// The block height at which this HTLC expires.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_get_cltv_expiry(this_ptr: &InboundHTLCDetails) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry;
	*inner_val
}
/// The block height at which this HTLC expires.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_set_cltv_expiry(this_ptr: &mut InboundHTLCDetails, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry = val;
}
/// The payment hash.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_get_payment_hash(this_ptr: &InboundHTLCDetails) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_hash;
	&inner_val.0
}
/// The payment hash.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_set_payment_hash(this_ptr: &mut InboundHTLCDetails, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_hash = ::lightning::types::payment::PaymentHash(val.data);
}
/// The state of the HTLC in the state machine.
///
/// Determines on which commitment transactions the HTLC is included and what message the HTLC is
/// waiting for to advance to the next state.
///
/// See [`InboundHTLCStateDetails`] for information on the specific states.
///
/// LDK will always fill this field in, but when downgrading to prior versions of LDK, new
/// states may result in `None` here.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_get_state(this_ptr: &InboundHTLCDetails) -> crate::c_types::derived::COption_InboundHTLCStateDetailsZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().state;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_InboundHTLCStateDetailsZ::None } else { crate::c_types::derived::COption_InboundHTLCStateDetailsZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::lightning::ln::channel_state::InboundHTLCStateDetails::native_into((*inner_val.as_ref().unwrap()).clone()) }) };
	local_inner_val
}
/// The state of the HTLC in the state machine.
///
/// Determines on which commitment transactions the HTLC is included and what message the HTLC is
/// waiting for to advance to the next state.
///
/// See [`InboundHTLCStateDetails`] for information on the specific states.
///
/// LDK will always fill this field in, but when downgrading to prior versions of LDK, new
/// states may result in `None` here.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_set_state(this_ptr: &mut InboundHTLCDetails, mut val: crate::c_types::derived::COption_InboundHTLCStateDetailsZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_native() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.state = local_val;
}
/// Whether the HTLC has an output below the local dust limit. If so, the output will be trimmed
/// from the local commitment transaction and added to the commitment transaction fee.
/// For non-anchor channels, this takes into account the cost of the second-stage HTLC
/// transactions as well.
///
/// When the local commitment transaction is broadcasted as part of a unilateral closure,
/// the value of this HTLC will therefore not be claimable but instead burned as a transaction
/// fee.
///
/// Note that dust limits are specific to each party. An HTLC can be dust for the local
/// commitment transaction but not for the counterparty's commitment transaction and vice versa.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_get_is_dust(this_ptr: &InboundHTLCDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_dust;
	*inner_val
}
/// Whether the HTLC has an output below the local dust limit. If so, the output will be trimmed
/// from the local commitment transaction and added to the commitment transaction fee.
/// For non-anchor channels, this takes into account the cost of the second-stage HTLC
/// transactions as well.
///
/// When the local commitment transaction is broadcasted as part of a unilateral closure,
/// the value of this HTLC will therefore not be claimable but instead burned as a transaction
/// fee.
///
/// Note that dust limits are specific to each party. An HTLC can be dust for the local
/// commitment transaction but not for the counterparty's commitment transaction and vice versa.
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_set_is_dust(this_ptr: &mut InboundHTLCDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_dust = val;
}
/// Constructs a new InboundHTLCDetails given each field
#[must_use]
#[no_mangle]
pub extern "C" fn InboundHTLCDetails_new(mut htlc_id_arg: u64, mut amount_msat_arg: u64, mut cltv_expiry_arg: u32, mut payment_hash_arg: crate::c_types::ThirtyTwoBytes, mut state_arg: crate::c_types::derived::COption_InboundHTLCStateDetailsZ, mut is_dust_arg: bool) -> InboundHTLCDetails {
	let mut local_state_arg = { /*state_arg*/ let state_arg_opt = state_arg; if state_arg_opt.is_none() { None } else { Some({ { { state_arg_opt.take() }.into_native() }})} };
	InboundHTLCDetails { inner: ObjOps::heap_alloc(nativeInboundHTLCDetails {
		htlc_id: htlc_id_arg,
		amount_msat: amount_msat_arg,
		cltv_expiry: cltv_expiry_arg,
		payment_hash: ::lightning::types::payment::PaymentHash(payment_hash_arg.data),
		state: local_state_arg,
		is_dust: is_dust_arg,
	}), is_owned: true }
}
impl Clone for InboundHTLCDetails {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInboundHTLCDetails>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InboundHTLCDetails_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInboundHTLCDetails)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InboundHTLCDetails
pub extern "C" fn InboundHTLCDetails_clone(orig: &InboundHTLCDetails) -> InboundHTLCDetails {
	orig.clone()
}
/// Get a string which allows debug introspection of a InboundHTLCDetails object
pub extern "C" fn InboundHTLCDetails_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::InboundHTLCDetails }).into()}
#[no_mangle]
/// Serialize the InboundHTLCDetails object into a byte array which can be read by InboundHTLCDetails_read
pub extern "C" fn InboundHTLCDetails_write(obj: &crate::lightning::ln::channel_state::InboundHTLCDetails) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn InboundHTLCDetails_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::channel_state::nativeInboundHTLCDetails) })
}
#[no_mangle]
/// Read a InboundHTLCDetails from a byte array, created by InboundHTLCDetails_write
pub extern "C" fn InboundHTLCDetails_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InboundHTLCDetailsDecodeErrorZ {
	let res: Result<lightning::ln::channel_state::InboundHTLCDetails, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_state::InboundHTLCDetails { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Exposes the state of pending outbound HTLCs.
///
/// At a high level, an HTLC being forwarded from one Lightning node to another Lightning node goes
/// through the following states in the state machine:
/// - Announced for addition by the originating node through the update_add_htlc message.
/// - Added to the commitment transaction of the receiving node and originating node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
/// - Announced for resolution (fulfillment or failure) by the receiving node through either one of
///   the update_fulfill_htlc, update_fail_htlc, and update_fail_malformed_htlc messages.
/// - Removed from the commitment transaction of the originating node and receiving node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
///
/// This can be used to inspect what next message an HTLC is waiting for to advance its state.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum OutboundHTLCStateDetails {
	/// We are awaiting the appropriate revoke_and_ack's from the remote before the HTLC is added
	/// on the remote's commitment transaction after update_add_htlc.
	AwaitingRemoteRevokeToAdd,
	/// The HTLC has been added to the remote's commitment transaction by sending commitment_signed
	/// and receiving revoke_and_ack in return.
	///
	/// The HTLC will remain in this state until the remote node resolves the HTLC, or until we
	/// unilaterally close the channel due to a timeout with an uncooperative remote node.
	Committed,
	/// The HTLC has been fulfilled successfully by the remote with a preimage in update_fulfill_htlc,
	/// and we removed the HTLC from our commitment transaction by receiving commitment_signed and
	/// returning revoke_and_ack. We are awaiting the appropriate revoke_and_ack's from the remote
	/// for the removal from its commitment transaction.
	AwaitingRemoteRevokeToRemoveSuccess,
	/// The HTLC has been failed by the remote with update_fail_htlc or update_fail_malformed_htlc,
	/// and we removed the HTLC from our commitment transaction by receiving commitment_signed and
	/// returning revoke_and_ack. We are awaiting the appropriate revoke_and_ack's from the remote
	/// for the removal from its commitment transaction.
	AwaitingRemoteRevokeToRemoveFailure,
}
use lightning::ln::channel_state::OutboundHTLCStateDetails as OutboundHTLCStateDetailsImport;
pub(crate) type nativeOutboundHTLCStateDetails = OutboundHTLCStateDetailsImport;

impl OutboundHTLCStateDetails {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeOutboundHTLCStateDetails {
		match self {
			OutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			OutboundHTLCStateDetails::Committed => nativeOutboundHTLCStateDetails::Committed,
			OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess => nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess,
			OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure => nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeOutboundHTLCStateDetails {
		match self {
			OutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			OutboundHTLCStateDetails::Committed => nativeOutboundHTLCStateDetails::Committed,
			OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess => nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess,
			OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure => nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &OutboundHTLCStateDetailsImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeOutboundHTLCStateDetails) };
		match native {
			nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => OutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			nativeOutboundHTLCStateDetails::Committed => OutboundHTLCStateDetails::Committed,
			nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess => OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess,
			nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure => OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeOutboundHTLCStateDetails) -> Self {
		match native {
			nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd => OutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd,
			nativeOutboundHTLCStateDetails::Committed => OutboundHTLCStateDetails::Committed,
			nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess => OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess,
			nativeOutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure => OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure,
		}
	}
}
/// Creates a copy of the OutboundHTLCStateDetails
#[no_mangle]
pub extern "C" fn OutboundHTLCStateDetails_clone(orig: &OutboundHTLCStateDetails) -> OutboundHTLCStateDetails {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutboundHTLCStateDetails_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const OutboundHTLCStateDetails)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutboundHTLCStateDetails_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut OutboundHTLCStateDetails) };
}
#[no_mangle]
/// Utility method to constructs a new AwaitingRemoteRevokeToAdd-variant OutboundHTLCStateDetails
pub extern "C" fn OutboundHTLCStateDetails_awaiting_remote_revoke_to_add() -> OutboundHTLCStateDetails {
	OutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd}
#[no_mangle]
/// Utility method to constructs a new Committed-variant OutboundHTLCStateDetails
pub extern "C" fn OutboundHTLCStateDetails_committed() -> OutboundHTLCStateDetails {
	OutboundHTLCStateDetails::Committed}
#[no_mangle]
/// Utility method to constructs a new AwaitingRemoteRevokeToRemoveSuccess-variant OutboundHTLCStateDetails
pub extern "C" fn OutboundHTLCStateDetails_awaiting_remote_revoke_to_remove_success() -> OutboundHTLCStateDetails {
	OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess}
#[no_mangle]
/// Utility method to constructs a new AwaitingRemoteRevokeToRemoveFailure-variant OutboundHTLCStateDetails
pub extern "C" fn OutboundHTLCStateDetails_awaiting_remote_revoke_to_remove_failure() -> OutboundHTLCStateDetails {
	OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure}
/// Get a string which allows debug introspection of a OutboundHTLCStateDetails object
pub extern "C" fn OutboundHTLCStateDetails_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::OutboundHTLCStateDetails }).into()}
#[no_mangle]
/// Serialize the OutboundHTLCStateDetails object into a byte array which can be read by OutboundHTLCStateDetails_read
pub extern "C" fn OutboundHTLCStateDetails_write(obj: &crate::lightning::ln::channel_state::OutboundHTLCStateDetails) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn OutboundHTLCStateDetails_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	OutboundHTLCStateDetails_write(unsafe { &*(obj as *const OutboundHTLCStateDetails) })
}
#[no_mangle]
/// Read a OutboundHTLCStateDetails from a byte array, created by OutboundHTLCStateDetails_write
pub extern "C" fn OutboundHTLCStateDetails_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_OutboundHTLCStateDetailsZDecodeErrorZ {
	let res: Result<Option<lightning::ln::channel_state::OutboundHTLCStateDetails>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_OutboundHTLCStateDetailsZ::None } else { crate::c_types::derived::COption_OutboundHTLCStateDetailsZ::Some( { crate::lightning::ln::channel_state::OutboundHTLCStateDetails::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_state::OutboundHTLCDetails as nativeOutboundHTLCDetailsImport;
pub(crate) type nativeOutboundHTLCDetails = nativeOutboundHTLCDetailsImport;

/// Exposes details around pending outbound HTLCs.
#[must_use]
#[repr(C)]
pub struct OutboundHTLCDetails {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOutboundHTLCDetails,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OutboundHTLCDetails {
	type Target = nativeOutboundHTLCDetails;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OutboundHTLCDetails { }
unsafe impl core::marker::Sync for OutboundHTLCDetails { }
impl Drop for OutboundHTLCDetails {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOutboundHTLCDetails>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OutboundHTLCDetails, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_free(this_obj: OutboundHTLCDetails) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutboundHTLCDetails_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOutboundHTLCDetails) };
}
#[allow(unused)]
impl OutboundHTLCDetails {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOutboundHTLCDetails {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOutboundHTLCDetails {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOutboundHTLCDetails {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The HTLC ID.
/// The IDs are incremented by 1 starting from 0 for each offered HTLC.
/// They are unique per channel and inbound/outbound direction, unless an HTLC was only announced
/// and not part of any commitment transaction.
///
/// Not present when we are awaiting a remote revocation and the HTLC is not added yet.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_get_htlc_id(this_ptr: &OutboundHTLCDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_id;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The HTLC ID.
/// The IDs are incremented by 1 starting from 0 for each offered HTLC.
/// They are unique per channel and inbound/outbound direction, unless an HTLC was only announced
/// and not part of any commitment transaction.
///
/// Not present when we are awaiting a remote revocation and the HTLC is not added yet.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_set_htlc_id(this_ptr: &mut OutboundHTLCDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_id = local_val;
}
/// The amount in msat.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_get_amount_msat(this_ptr: &OutboundHTLCDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().amount_msat;
	*inner_val
}
/// The amount in msat.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_set_amount_msat(this_ptr: &mut OutboundHTLCDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.amount_msat = val;
}
/// The block height at which this HTLC expires.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_get_cltv_expiry(this_ptr: &OutboundHTLCDetails) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry;
	*inner_val
}
/// The block height at which this HTLC expires.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_set_cltv_expiry(this_ptr: &mut OutboundHTLCDetails, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry = val;
}
/// The payment hash.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_get_payment_hash(this_ptr: &OutboundHTLCDetails) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_hash;
	&inner_val.0
}
/// The payment hash.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_set_payment_hash(this_ptr: &mut OutboundHTLCDetails, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_hash = ::lightning::types::payment::PaymentHash(val.data);
}
/// The state of the HTLC in the state machine.
///
/// Determines on which commitment transactions the HTLC is included and what message the HTLC is
/// waiting for to advance to the next state.
///
/// See [`OutboundHTLCStateDetails`] for information on the specific states.
///
/// LDK will always fill this field in, but when downgrading to prior versions of LDK, new
/// states may result in `None` here.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_get_state(this_ptr: &OutboundHTLCDetails) -> crate::c_types::derived::COption_OutboundHTLCStateDetailsZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().state;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_OutboundHTLCStateDetailsZ::None } else { crate::c_types::derived::COption_OutboundHTLCStateDetailsZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::lightning::ln::channel_state::OutboundHTLCStateDetails::native_into((*inner_val.as_ref().unwrap()).clone()) }) };
	local_inner_val
}
/// The state of the HTLC in the state machine.
///
/// Determines on which commitment transactions the HTLC is included and what message the HTLC is
/// waiting for to advance to the next state.
///
/// See [`OutboundHTLCStateDetails`] for information on the specific states.
///
/// LDK will always fill this field in, but when downgrading to prior versions of LDK, new
/// states may result in `None` here.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_set_state(this_ptr: &mut OutboundHTLCDetails, mut val: crate::c_types::derived::COption_OutboundHTLCStateDetailsZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_native() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.state = local_val;
}
/// The extra fee being skimmed off the top of this HTLC.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_get_skimmed_fee_msat(this_ptr: &OutboundHTLCDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().skimmed_fee_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The extra fee being skimmed off the top of this HTLC.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_set_skimmed_fee_msat(this_ptr: &mut OutboundHTLCDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.skimmed_fee_msat = local_val;
}
/// Whether the HTLC has an output below the local dust limit. If so, the output will be trimmed
/// from the local commitment transaction and added to the commitment transaction fee.
/// For non-anchor channels, this takes into account the cost of the second-stage HTLC
/// transactions as well.
///
/// When the local commitment transaction is broadcasted as part of a unilateral closure,
/// the value of this HTLC will therefore not be claimable but instead burned as a transaction
/// fee.
///
/// Note that dust limits are specific to each party. An HTLC can be dust for the local
/// commitment transaction but not for the counterparty's commitment transaction and vice versa.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_get_is_dust(this_ptr: &OutboundHTLCDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_dust;
	*inner_val
}
/// Whether the HTLC has an output below the local dust limit. If so, the output will be trimmed
/// from the local commitment transaction and added to the commitment transaction fee.
/// For non-anchor channels, this takes into account the cost of the second-stage HTLC
/// transactions as well.
///
/// When the local commitment transaction is broadcasted as part of a unilateral closure,
/// the value of this HTLC will therefore not be claimable but instead burned as a transaction
/// fee.
///
/// Note that dust limits are specific to each party. An HTLC can be dust for the local
/// commitment transaction but not for the counterparty's commitment transaction and vice versa.
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_set_is_dust(this_ptr: &mut OutboundHTLCDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_dust = val;
}
/// Constructs a new OutboundHTLCDetails given each field
#[must_use]
#[no_mangle]
pub extern "C" fn OutboundHTLCDetails_new(mut htlc_id_arg: crate::c_types::derived::COption_u64Z, mut amount_msat_arg: u64, mut cltv_expiry_arg: u32, mut payment_hash_arg: crate::c_types::ThirtyTwoBytes, mut state_arg: crate::c_types::derived::COption_OutboundHTLCStateDetailsZ, mut skimmed_fee_msat_arg: crate::c_types::derived::COption_u64Z, mut is_dust_arg: bool) -> OutboundHTLCDetails {
	let mut local_htlc_id_arg = if htlc_id_arg.is_some() { Some( { htlc_id_arg.take() }) } else { None };
	let mut local_state_arg = { /*state_arg*/ let state_arg_opt = state_arg; if state_arg_opt.is_none() { None } else { Some({ { { state_arg_opt.take() }.into_native() }})} };
	let mut local_skimmed_fee_msat_arg = if skimmed_fee_msat_arg.is_some() { Some( { skimmed_fee_msat_arg.take() }) } else { None };
	OutboundHTLCDetails { inner: ObjOps::heap_alloc(nativeOutboundHTLCDetails {
		htlc_id: local_htlc_id_arg,
		amount_msat: amount_msat_arg,
		cltv_expiry: cltv_expiry_arg,
		payment_hash: ::lightning::types::payment::PaymentHash(payment_hash_arg.data),
		state: local_state_arg,
		skimmed_fee_msat: local_skimmed_fee_msat_arg,
		is_dust: is_dust_arg,
	}), is_owned: true }
}
impl Clone for OutboundHTLCDetails {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOutboundHTLCDetails>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutboundHTLCDetails_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOutboundHTLCDetails)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OutboundHTLCDetails
pub extern "C" fn OutboundHTLCDetails_clone(orig: &OutboundHTLCDetails) -> OutboundHTLCDetails {
	orig.clone()
}
/// Get a string which allows debug introspection of a OutboundHTLCDetails object
pub extern "C" fn OutboundHTLCDetails_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::OutboundHTLCDetails }).into()}
#[no_mangle]
/// Serialize the OutboundHTLCDetails object into a byte array which can be read by OutboundHTLCDetails_read
pub extern "C" fn OutboundHTLCDetails_write(obj: &crate::lightning::ln::channel_state::OutboundHTLCDetails) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn OutboundHTLCDetails_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::channel_state::nativeOutboundHTLCDetails) })
}
#[no_mangle]
/// Read a OutboundHTLCDetails from a byte array, created by OutboundHTLCDetails_write
pub extern "C" fn OutboundHTLCDetails_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OutboundHTLCDetailsDecodeErrorZ {
	let res: Result<lightning::ln::channel_state::OutboundHTLCDetails, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_state::OutboundHTLCDetails { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_state::CounterpartyForwardingInfo as nativeCounterpartyForwardingInfoImport;
pub(crate) type nativeCounterpartyForwardingInfo = nativeCounterpartyForwardingInfoImport;

/// Information needed for constructing an invoice route hint for this channel.
#[must_use]
#[repr(C)]
pub struct CounterpartyForwardingInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCounterpartyForwardingInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for CounterpartyForwardingInfo {
	type Target = nativeCounterpartyForwardingInfo;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for CounterpartyForwardingInfo { }
unsafe impl core::marker::Sync for CounterpartyForwardingInfo { }
impl Drop for CounterpartyForwardingInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCounterpartyForwardingInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CounterpartyForwardingInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_free(this_obj: CounterpartyForwardingInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyForwardingInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeCounterpartyForwardingInfo) };
}
#[allow(unused)]
impl CounterpartyForwardingInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCounterpartyForwardingInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCounterpartyForwardingInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCounterpartyForwardingInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Base routing fee in millisatoshis.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_get_fee_base_msat(this_ptr: &CounterpartyForwardingInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_base_msat;
	*inner_val
}
/// Base routing fee in millisatoshis.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_set_fee_base_msat(this_ptr: &mut CounterpartyForwardingInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_base_msat = val;
}
/// Amount in millionths of a satoshi the channel will charge per transferred satoshi.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_get_fee_proportional_millionths(this_ptr: &CounterpartyForwardingInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_proportional_millionths;
	*inner_val
}
/// Amount in millionths of a satoshi the channel will charge per transferred satoshi.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_set_fee_proportional_millionths(this_ptr: &mut CounterpartyForwardingInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_proportional_millionths = val;
}
/// The minimum difference in cltv_expiry between an ingoing HTLC and its outgoing counterpart,
/// such that the outgoing HTLC is forwardable to this counterparty. See `msgs::ChannelUpdate`'s
/// `cltv_expiry_delta` for more details.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_get_cltv_expiry_delta(this_ptr: &CounterpartyForwardingInfo) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The minimum difference in cltv_expiry between an ingoing HTLC and its outgoing counterpart,
/// such that the outgoing HTLC is forwardable to this counterparty. See `msgs::ChannelUpdate`'s
/// `cltv_expiry_delta` for more details.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_set_cltv_expiry_delta(this_ptr: &mut CounterpartyForwardingInfo, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Constructs a new CounterpartyForwardingInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_new(mut fee_base_msat_arg: u32, mut fee_proportional_millionths_arg: u32, mut cltv_expiry_delta_arg: u16) -> CounterpartyForwardingInfo {
	CounterpartyForwardingInfo { inner: ObjOps::heap_alloc(nativeCounterpartyForwardingInfo {
		fee_base_msat: fee_base_msat_arg,
		fee_proportional_millionths: fee_proportional_millionths_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
	}), is_owned: true }
}
impl Clone for CounterpartyForwardingInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeCounterpartyForwardingInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyForwardingInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeCounterpartyForwardingInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the CounterpartyForwardingInfo
pub extern "C" fn CounterpartyForwardingInfo_clone(orig: &CounterpartyForwardingInfo) -> CounterpartyForwardingInfo {
	orig.clone()
}
/// Get a string which allows debug introspection of a CounterpartyForwardingInfo object
pub extern "C" fn CounterpartyForwardingInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::CounterpartyForwardingInfo }).into()}
#[no_mangle]
/// Serialize the CounterpartyForwardingInfo object into a byte array which can be read by CounterpartyForwardingInfo_read
pub extern "C" fn CounterpartyForwardingInfo_write(obj: &crate::lightning::ln::channel_state::CounterpartyForwardingInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn CounterpartyForwardingInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::channel_state::nativeCounterpartyForwardingInfo) })
}
#[no_mangle]
/// Read a CounterpartyForwardingInfo from a byte array, created by CounterpartyForwardingInfo_write
pub extern "C" fn CounterpartyForwardingInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CounterpartyForwardingInfoDecodeErrorZ {
	let res: Result<lightning::ln::channel_state::CounterpartyForwardingInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_state::CounterpartyForwardingInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_state::ChannelCounterparty as nativeChannelCounterpartyImport;
pub(crate) type nativeChannelCounterparty = nativeChannelCounterpartyImport;

/// Channel parameters which apply to our counterparty. These are split out from [`ChannelDetails`]
/// to better separate parameters.
#[must_use]
#[repr(C)]
pub struct ChannelCounterparty {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelCounterparty,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ChannelCounterparty {
	type Target = nativeChannelCounterparty;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ChannelCounterparty { }
unsafe impl core::marker::Sync for ChannelCounterparty { }
impl Drop for ChannelCounterparty {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelCounterparty>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelCounterparty, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_free(this_obj: ChannelCounterparty) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelCounterparty_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelCounterparty) };
}
#[allow(unused)]
impl ChannelCounterparty {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelCounterparty {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelCounterparty {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelCounterparty {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The node_id of our counterparty
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_node_id(this_ptr: &ChannelCounterparty) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of our counterparty
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_node_id(this_ptr: &mut ChannelCounterparty, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_id = val.into_rust();
}
/// The Features the channel counterparty provided upon last connection.
/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
/// many routing-relevant features are present in the init context.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_features(this_ptr: &ChannelCounterparty) -> crate::lightning_types::features::InitFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning_types::features::InitFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_types::features::InitFeatures<>) as *mut _) }, is_owned: false }
}
/// The Features the channel counterparty provided upon last connection.
/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
/// many routing-relevant features are present in the init context.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_features(this_ptr: &mut ChannelCounterparty, mut val: crate::lightning_types::features::InitFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The value, in satoshis, that must always be held in the channel for our counterparty. This
/// value ensures that if our counterparty broadcasts a revoked state, we can punish them by
/// claiming at least this value on chain.
///
/// This value is not included in [`inbound_capacity_msat`] as it can never be spent.
///
/// [`inbound_capacity_msat`]: ChannelDetails::inbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_unspendable_punishment_reserve(this_ptr: &ChannelCounterparty) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().unspendable_punishment_reserve;
	*inner_val
}
/// The value, in satoshis, that must always be held in the channel for our counterparty. This
/// value ensures that if our counterparty broadcasts a revoked state, we can punish them by
/// claiming at least this value on chain.
///
/// This value is not included in [`inbound_capacity_msat`] as it can never be spent.
///
/// [`inbound_capacity_msat`]: ChannelDetails::inbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_unspendable_punishment_reserve(this_ptr: &mut ChannelCounterparty, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.unspendable_punishment_reserve = val;
}
/// Information on the fees and requirements that the counterparty requires when forwarding
/// payments to us through this channel.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_forwarding_info(this_ptr: &ChannelCounterparty) -> crate::lightning::ln::channel_state::CounterpartyForwardingInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().forwarding_info;
	let mut local_inner_val = crate::lightning::ln::channel_state::CounterpartyForwardingInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::channel_state::CounterpartyForwardingInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Information on the fees and requirements that the counterparty requires when forwarding
/// payments to us through this channel.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_forwarding_info(this_ptr: &mut ChannelCounterparty, mut val: crate::lightning::ln::channel_state::CounterpartyForwardingInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.forwarding_info = local_val;
}
/// The smallest value HTLC (in msat) the remote peer will accept, for this channel. This field
/// is only `None` before we have received either the `OpenChannel` or `AcceptChannel` message
/// from the remote peer, or for `ChannelCounterparty` objects serialized prior to LDK 0.0.107.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_outbound_htlc_minimum_msat(this_ptr: &ChannelCounterparty) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outbound_htlc_minimum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The smallest value HTLC (in msat) the remote peer will accept, for this channel. This field
/// is only `None` before we have received either the `OpenChannel` or `AcceptChannel` message
/// from the remote peer, or for `ChannelCounterparty` objects serialized prior to LDK 0.0.107.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_outbound_htlc_minimum_msat(this_ptr: &mut ChannelCounterparty, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outbound_htlc_minimum_msat = local_val;
}
/// The largest value HTLC (in msat) the remote peer currently will accept, for this channel.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_outbound_htlc_maximum_msat(this_ptr: &ChannelCounterparty) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outbound_htlc_maximum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The largest value HTLC (in msat) the remote peer currently will accept, for this channel.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_outbound_htlc_maximum_msat(this_ptr: &mut ChannelCounterparty, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outbound_htlc_maximum_msat = local_val;
}
/// Constructs a new ChannelCounterparty given each field
///
/// Note that forwarding_info_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelCounterparty_new(mut node_id_arg: crate::c_types::PublicKey, mut features_arg: crate::lightning_types::features::InitFeatures, mut unspendable_punishment_reserve_arg: u64, mut forwarding_info_arg: crate::lightning::ln::channel_state::CounterpartyForwardingInfo, mut outbound_htlc_minimum_msat_arg: crate::c_types::derived::COption_u64Z, mut outbound_htlc_maximum_msat_arg: crate::c_types::derived::COption_u64Z) -> ChannelCounterparty {
	let mut local_forwarding_info_arg = if forwarding_info_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(forwarding_info_arg.take_inner()) } }) };
	let mut local_outbound_htlc_minimum_msat_arg = if outbound_htlc_minimum_msat_arg.is_some() { Some( { outbound_htlc_minimum_msat_arg.take() }) } else { None };
	let mut local_outbound_htlc_maximum_msat_arg = if outbound_htlc_maximum_msat_arg.is_some() { Some( { outbound_htlc_maximum_msat_arg.take() }) } else { None };
	ChannelCounterparty { inner: ObjOps::heap_alloc(nativeChannelCounterparty {
		node_id: node_id_arg.into_rust(),
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
		unspendable_punishment_reserve: unspendable_punishment_reserve_arg,
		forwarding_info: local_forwarding_info_arg,
		outbound_htlc_minimum_msat: local_outbound_htlc_minimum_msat_arg,
		outbound_htlc_maximum_msat: local_outbound_htlc_maximum_msat_arg,
	}), is_owned: true }
}
impl Clone for ChannelCounterparty {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelCounterparty>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelCounterparty_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelCounterparty)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelCounterparty
pub extern "C" fn ChannelCounterparty_clone(orig: &ChannelCounterparty) -> ChannelCounterparty {
	orig.clone()
}
/// Get a string which allows debug introspection of a ChannelCounterparty object
pub extern "C" fn ChannelCounterparty_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::ChannelCounterparty }).into()}
#[no_mangle]
/// Serialize the ChannelCounterparty object into a byte array which can be read by ChannelCounterparty_read
pub extern "C" fn ChannelCounterparty_write(obj: &crate::lightning::ln::channel_state::ChannelCounterparty) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelCounterparty_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::channel_state::nativeChannelCounterparty) })
}
#[no_mangle]
/// Read a ChannelCounterparty from a byte array, created by ChannelCounterparty_write
pub extern "C" fn ChannelCounterparty_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelCounterpartyDecodeErrorZ {
	let res: Result<lightning::ln::channel_state::ChannelCounterparty, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_state::ChannelCounterparty { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_state::ChannelDetails as nativeChannelDetailsImport;
pub(crate) type nativeChannelDetails = nativeChannelDetailsImport;

/// Details of a channel, as returned by [`ChannelManager::list_channels`] and [`ChannelManager::list_usable_channels`]
///
/// Balances of a channel are available through [`ChainMonitor::get_claimable_balances`] and
/// [`ChannelMonitor::get_claimable_balances`], calculated with respect to the corresponding on-chain
/// transactions.
///
/// [`ChannelManager::list_channels`]: crate::ln::channelmanager::ChannelManager::list_channels
/// [`ChannelManager::list_usable_channels`]: crate::ln::channelmanager::ChannelManager::list_usable_channels
/// [`ChainMonitor::get_claimable_balances`]: crate::chain::chainmonitor::ChainMonitor::get_claimable_balances
/// [`ChannelMonitor::get_claimable_balances`]: crate::chain::channelmonitor::ChannelMonitor::get_claimable_balances
#[must_use]
#[repr(C)]
pub struct ChannelDetails {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelDetails,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ChannelDetails {
	type Target = nativeChannelDetails;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ChannelDetails { }
unsafe impl core::marker::Sync for ChannelDetails { }
impl Drop for ChannelDetails {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelDetails>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelDetails, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelDetails_free(this_obj: ChannelDetails) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelDetails_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelDetails) };
}
#[allow(unused)]
impl ChannelDetails {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelDetails {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelDetails {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelDetails {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
/// thereafter this is the txid of the funding transaction xor the funding transaction output).
/// Note that this means this value is *not* persistent - it can change once during the
/// lifetime of the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_id(this_ptr: &ChannelDetails) -> crate::lightning::ln::types::ChannelId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_id;
	crate::lightning::ln::types::ChannelId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::types::ChannelId<>) as *mut _) }, is_owned: false }
}
/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
/// thereafter this is the txid of the funding transaction xor the funding transaction output).
/// Note that this means this value is *not* persistent - it can change once during the
/// lifetime of the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_id(this_ptr: &mut ChannelDetails, mut val: crate::lightning::ln::types::ChannelId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_id = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Parameters which apply to our counterparty. See individual fields for more information.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_counterparty(this_ptr: &ChannelDetails) -> crate::lightning::ln::channel_state::ChannelCounterparty {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().counterparty;
	crate::lightning::ln::channel_state::ChannelCounterparty { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::channel_state::ChannelCounterparty<>) as *mut _) }, is_owned: false }
}
/// Parameters which apply to our counterparty. See individual fields for more information.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_counterparty(this_ptr: &mut ChannelDetails, mut val: crate::lightning::ln::channel_state::ChannelCounterparty) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.counterparty = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The Channel's funding transaction output, if we've negotiated the funding transaction with
/// our counterparty already.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_get_funding_txo(this_ptr: &ChannelDetails) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funding_txo;
	let mut local_inner_val = crate::lightning::chain::transaction::OutPoint { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::chain::transaction::OutPoint<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The Channel's funding transaction output, if we've negotiated the funding transaction with
/// our counterparty already.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_set_funding_txo(this_ptr: &mut ChannelDetails, mut val: crate::lightning::chain::transaction::OutPoint) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funding_txo = local_val;
}
/// The features which this channel operates with. See individual features for more info.
///
/// `None` until negotiation completes and the channel type is finalized.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_type(this_ptr: &ChannelDetails) -> crate::lightning_types::features::ChannelTypeFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_type;
	let mut local_inner_val = crate::lightning_types::features::ChannelTypeFeatures { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning_types::features::ChannelTypeFeatures<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The features which this channel operates with. See individual features for more info.
///
/// `None` until negotiation completes and the channel type is finalized.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_type(this_ptr: &mut ChannelDetails, mut val: crate::lightning_types::features::ChannelTypeFeatures) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_type = local_val;
}
/// The position of the funding transaction in the chain. None if the funding transaction has
/// not yet been confirmed and the channel fully opened.
///
/// Note that if [`inbound_scid_alias`] is set, it must be used for invoices and inbound
/// payments instead of this. See [`get_inbound_payment_scid`].
///
/// For channels with [`confirmations_required`] set to `Some(0)`, [`outbound_scid_alias`] may
/// be used in place of this in outbound routes. See [`get_outbound_payment_scid`].
///
/// [`inbound_scid_alias`]: Self::inbound_scid_alias
/// [`outbound_scid_alias`]: Self::outbound_scid_alias
/// [`get_inbound_payment_scid`]: Self::get_inbound_payment_scid
/// [`get_outbound_payment_scid`]: Self::get_outbound_payment_scid
/// [`confirmations_required`]: Self::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_get_short_channel_id(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The position of the funding transaction in the chain. None if the funding transaction has
/// not yet been confirmed and the channel fully opened.
///
/// Note that if [`inbound_scid_alias`] is set, it must be used for invoices and inbound
/// payments instead of this. See [`get_inbound_payment_scid`].
///
/// For channels with [`confirmations_required`] set to `Some(0)`, [`outbound_scid_alias`] may
/// be used in place of this in outbound routes. See [`get_outbound_payment_scid`].
///
/// [`inbound_scid_alias`]: Self::inbound_scid_alias
/// [`outbound_scid_alias`]: Self::outbound_scid_alias
/// [`get_inbound_payment_scid`]: Self::get_inbound_payment_scid
/// [`get_outbound_payment_scid`]: Self::get_outbound_payment_scid
/// [`confirmations_required`]: Self::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_set_short_channel_id(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = local_val;
}
/// An optional [`short_channel_id`] alias for this channel, randomly generated by us and
/// usable in place of [`short_channel_id`] to reference the channel in outbound routes when
/// the channel has not yet been confirmed (as long as [`confirmations_required`] is
/// `Some(0)`).
///
/// This will be `None` as long as the channel is not available for routing outbound payments.
///
/// [`short_channel_id`]: Self::short_channel_id
/// [`confirmations_required`]: Self::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_get_outbound_scid_alias(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outbound_scid_alias;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// An optional [`short_channel_id`] alias for this channel, randomly generated by us and
/// usable in place of [`short_channel_id`] to reference the channel in outbound routes when
/// the channel has not yet been confirmed (as long as [`confirmations_required`] is
/// `Some(0)`).
///
/// This will be `None` as long as the channel is not available for routing outbound payments.
///
/// [`short_channel_id`]: Self::short_channel_id
/// [`confirmations_required`]: Self::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_set_outbound_scid_alias(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outbound_scid_alias = local_val;
}
/// An optional [`short_channel_id`] alias for this channel, randomly generated by our
/// counterparty and usable in place of [`short_channel_id`] in invoice route hints. Our
/// counterparty will recognize the alias provided here in place of the [`short_channel_id`]
/// when they see a payment to be routed to us.
///
/// Our counterparty may choose to rotate this value at any time, though will always recognize
/// previous values for inbound payment forwarding.
///
/// [`short_channel_id`]: Self::short_channel_id
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_scid_alias(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().inbound_scid_alias;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// An optional [`short_channel_id`] alias for this channel, randomly generated by our
/// counterparty and usable in place of [`short_channel_id`] in invoice route hints. Our
/// counterparty will recognize the alias provided here in place of the [`short_channel_id`]
/// when they see a payment to be routed to us.
///
/// Our counterparty may choose to rotate this value at any time, though will always recognize
/// previous values for inbound payment forwarding.
///
/// [`short_channel_id`]: Self::short_channel_id
#[no_mangle]
pub extern "C" fn ChannelDetails_set_inbound_scid_alias(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.inbound_scid_alias = local_val;
}
/// The value, in satoshis, of this channel as appears in the funding output
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_value_satoshis(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_value_satoshis;
	*inner_val
}
/// The value, in satoshis, of this channel as appears in the funding output
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_value_satoshis(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_value_satoshis = val;
}
/// The value, in satoshis, that must always be held in the channel for us. This value ensures
/// that if we broadcast a revoked state, our counterparty can punish us by claiming at least
/// this value on chain.
///
/// This value is not included in [`outbound_capacity_msat`] as it can never be spent.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`outbound_capacity_msat`]: ChannelDetails::outbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelDetails_get_unspendable_punishment_reserve(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().unspendable_punishment_reserve;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The value, in satoshis, that must always be held in the channel for us. This value ensures
/// that if we broadcast a revoked state, our counterparty can punish us by claiming at least
/// this value on chain.
///
/// This value is not included in [`outbound_capacity_msat`] as it can never be spent.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`outbound_capacity_msat`]: ChannelDetails::outbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelDetails_set_unspendable_punishment_reserve(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.unspendable_punishment_reserve = local_val;
}
/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
/// `user_channel_id` will be randomized for an inbound channel.  This may be zero for objects
/// serialized with LDK versions prior to 0.0.113.
///
/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
#[no_mangle]
pub extern "C" fn ChannelDetails_get_user_channel_id(this_ptr: &ChannelDetails) -> crate::c_types::U128 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().user_channel_id;
	inner_val.into()
}
/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
/// `user_channel_id` will be randomized for an inbound channel.  This may be zero for objects
/// serialized with LDK versions prior to 0.0.113.
///
/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
#[no_mangle]
pub extern "C" fn ChannelDetails_set_user_channel_id(this_ptr: &mut ChannelDetails, mut val: crate::c_types::U128) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.user_channel_id = val.into();
}
/// The currently negotiated fee rate denominated in satoshi per 1000 weight units,
/// which is applied to commitment and HTLC transactions.
///
/// This value will be `None` for objects serialized with LDK versions prior to 0.0.115.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_feerate_sat_per_1000_weight(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u32Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().feerate_sat_per_1000_weight;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The currently negotiated fee rate denominated in satoshi per 1000 weight units,
/// which is applied to commitment and HTLC transactions.
///
/// This value will be `None` for objects serialized with LDK versions prior to 0.0.115.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_feerate_sat_per_1000_weight(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u32Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.feerate_sat_per_1000_weight = local_val;
}
/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
/// any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new outbound HTLCs). This further does not include any pending
/// outgoing HTLCs which are awaiting some other resolution to be sent.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
/// should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_outbound_capacity_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outbound_capacity_msat;
	*inner_val
}
/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
/// any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new outbound HTLCs). This further does not include any pending
/// outgoing HTLCs which are awaiting some other resolution to be sent.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
/// should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_outbound_capacity_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outbound_capacity_msat = val;
}
/// The available outbound capacity for sending a single HTLC to the remote peer. This is
/// similar to [`ChannelDetails::outbound_capacity_msat`] but it may be further restricted by
/// the current state and per-HTLC limit(s). This is intended for use when routing, allowing us
/// to use a limit as close as possible to the HTLC limit we can currently send.
///
/// See also [`ChannelDetails::next_outbound_htlc_minimum_msat`] and
/// [`ChannelDetails::outbound_capacity_msat`].
#[no_mangle]
pub extern "C" fn ChannelDetails_get_next_outbound_htlc_limit_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().next_outbound_htlc_limit_msat;
	*inner_val
}
/// The available outbound capacity for sending a single HTLC to the remote peer. This is
/// similar to [`ChannelDetails::outbound_capacity_msat`] but it may be further restricted by
/// the current state and per-HTLC limit(s). This is intended for use when routing, allowing us
/// to use a limit as close as possible to the HTLC limit we can currently send.
///
/// See also [`ChannelDetails::next_outbound_htlc_minimum_msat`] and
/// [`ChannelDetails::outbound_capacity_msat`].
#[no_mangle]
pub extern "C" fn ChannelDetails_set_next_outbound_htlc_limit_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.next_outbound_htlc_limit_msat = val;
}
/// The minimum value for sending a single HTLC to the remote peer. This is the equivalent of
/// [`ChannelDetails::next_outbound_htlc_limit_msat`] but represents a lower-bound, rather than
/// an upper-bound. This is intended for use when routing, allowing us to ensure we pick a
/// route which is valid.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_next_outbound_htlc_minimum_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().next_outbound_htlc_minimum_msat;
	*inner_val
}
/// The minimum value for sending a single HTLC to the remote peer. This is the equivalent of
/// [`ChannelDetails::next_outbound_htlc_limit_msat`] but represents a lower-bound, rather than
/// an upper-bound. This is intended for use when routing, allowing us to ensure we pick a
/// route which is valid.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_next_outbound_htlc_minimum_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.next_outbound_htlc_minimum_msat = val;
}
/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
/// include any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new inbound HTLCs).
/// Note that there are some corner cases not fully handled here, so the actual available
/// inbound capacity may be slightly higher than this.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
/// However, our counterparty should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_capacity_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().inbound_capacity_msat;
	*inner_val
}
/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
/// include any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new inbound HTLCs).
/// Note that there are some corner cases not fully handled here, so the actual available
/// inbound capacity may be slightly higher than this.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
/// However, our counterparty should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_inbound_capacity_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.inbound_capacity_msat = val;
}
/// The number of required confirmations on the funding transaction before the funding will be
/// considered \"locked\". This number is selected by the channel fundee (i.e. us if
/// [`is_outbound`] is *not* set), and can be selected for inbound channels with
/// [`ChannelHandshakeConfig::minimum_depth`] or limited for outbound channels with
/// [`ChannelHandshakeLimits::max_minimum_depth`].
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`is_outbound`]: ChannelDetails::is_outbound
/// [`ChannelHandshakeConfig::minimum_depth`]: crate::util::config::ChannelHandshakeConfig::minimum_depth
/// [`ChannelHandshakeLimits::max_minimum_depth`]: crate::util::config::ChannelHandshakeLimits::max_minimum_depth
#[no_mangle]
pub extern "C" fn ChannelDetails_get_confirmations_required(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u32Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().confirmations_required;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The number of required confirmations on the funding transaction before the funding will be
/// considered \"locked\". This number is selected by the channel fundee (i.e. us if
/// [`is_outbound`] is *not* set), and can be selected for inbound channels with
/// [`ChannelHandshakeConfig::minimum_depth`] or limited for outbound channels with
/// [`ChannelHandshakeLimits::max_minimum_depth`].
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`is_outbound`]: ChannelDetails::is_outbound
/// [`ChannelHandshakeConfig::minimum_depth`]: crate::util::config::ChannelHandshakeConfig::minimum_depth
/// [`ChannelHandshakeLimits::max_minimum_depth`]: crate::util::config::ChannelHandshakeLimits::max_minimum_depth
#[no_mangle]
pub extern "C" fn ChannelDetails_set_confirmations_required(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u32Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.confirmations_required = local_val;
}
/// The current number of confirmations on the funding transaction.
///
/// This value will be `None` for objects serialized with LDK versions prior to 0.0.113.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_confirmations(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u32Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().confirmations;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The current number of confirmations on the funding transaction.
///
/// This value will be `None` for objects serialized with LDK versions prior to 0.0.113.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_confirmations(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u32Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.confirmations = local_val;
}
/// The number of blocks (after our commitment transaction confirms) that we will need to wait
/// until we can claim our funds after we force-close the channel. During this time our
/// counterparty is allowed to punish us if we broadcasted a stale state. If our counterparty
/// force-closes the channel and broadcasts a commitment transaction we do not have to wait any
/// time to claim our non-HTLC-encumbered funds.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_force_close_spend_delay(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u16Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().force_close_spend_delay;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u16Z::None } else { crate::c_types::derived::COption_u16Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The number of blocks (after our commitment transaction confirms) that we will need to wait
/// until we can claim our funds after we force-close the channel. During this time our
/// counterparty is allowed to punish us if we broadcasted a stale state. If our counterparty
/// force-closes the channel and broadcasts a commitment transaction we do not have to wait any
/// time to claim our non-HTLC-encumbered funds.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_force_close_spend_delay(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u16Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.force_close_spend_delay = local_val;
}
/// True if the channel was initiated (and thus funded) by us.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_outbound(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_outbound;
	*inner_val
}
/// True if the channel was initiated (and thus funded) by us.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_outbound(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_outbound = val;
}
/// True if the channel is confirmed, channel_ready messages have been exchanged, and the
/// channel is not currently being shut down. `channel_ready` message exchange implies the
/// required confirmation count has been reached (and we were connected to the peer at some
/// point after the funding transaction received enough confirmations). The required
/// confirmation count is provided in [`confirmations_required`].
///
/// [`confirmations_required`]: ChannelDetails::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_channel_ready(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_channel_ready;
	*inner_val
}
/// True if the channel is confirmed, channel_ready messages have been exchanged, and the
/// channel is not currently being shut down. `channel_ready` message exchange implies the
/// required confirmation count has been reached (and we were connected to the peer at some
/// point after the funding transaction received enough confirmations). The required
/// confirmation count is provided in [`confirmations_required`].
///
/// [`confirmations_required`]: ChannelDetails::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_channel_ready(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_channel_ready = val;
}
/// The stage of the channel's shutdown.
/// `None` for `ChannelDetails` serialized on LDK versions prior to 0.0.116.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_shutdown_state(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_ChannelShutdownStateZ {
	let mut inner_val = this_ptr.get_native_mut_ref().channel_shutdown_state.clone();
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_ChannelShutdownStateZ::None } else { crate::c_types::derived::COption_ChannelShutdownStateZ::Some( { crate::lightning::ln::channel_state::ChannelShutdownState::native_into(inner_val.unwrap()) }) };
	local_inner_val
}
/// The stage of the channel's shutdown.
/// `None` for `ChannelDetails` serialized on LDK versions prior to 0.0.116.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_shutdown_state(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_ChannelShutdownStateZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_native() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_shutdown_state = local_val;
}
/// True if the channel is (a) confirmed and channel_ready messages have been exchanged, (b)
/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
///
/// This is a strict superset of `is_channel_ready`.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_usable(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_usable;
	*inner_val
}
/// True if the channel is (a) confirmed and channel_ready messages have been exchanged, (b)
/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
///
/// This is a strict superset of `is_channel_ready`.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_usable(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_usable = val;
}
/// True if this channel is (or will be) publicly-announced.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_announced(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_announced;
	*inner_val
}
/// True if this channel is (or will be) publicly-announced.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_announced(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_announced = val;
}
/// The smallest value HTLC (in msat) we will accept, for this channel. This field
/// is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.107
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_htlc_minimum_msat(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().inbound_htlc_minimum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The smallest value HTLC (in msat) we will accept, for this channel. This field
/// is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.107
#[no_mangle]
pub extern "C" fn ChannelDetails_set_inbound_htlc_minimum_msat(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.inbound_htlc_minimum_msat = local_val;
}
/// The largest value HTLC (in msat) we currently will accept, for this channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_htlc_maximum_msat(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().inbound_htlc_maximum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The largest value HTLC (in msat) we currently will accept, for this channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_inbound_htlc_maximum_msat(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.inbound_htlc_maximum_msat = local_val;
}
/// Set of configurable parameters that affect channel operation.
///
/// This field is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.109.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_get_config(this_ptr: &ChannelDetails) -> crate::lightning::util::config::ChannelConfig {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().config;
	let mut local_inner_val = crate::lightning::util::config::ChannelConfig { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::util::config::ChannelConfig<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Set of configurable parameters that affect channel operation.
///
/// This field is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.109.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_set_config(this_ptr: &mut ChannelDetails, mut val: crate::lightning::util::config::ChannelConfig) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.config = local_val;
}
/// Pending inbound HTLCs.
///
/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_pending_inbound_htlcs(this_ptr: &ChannelDetails) -> crate::c_types::derived::CVec_InboundHTLCDetailsZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().pending_inbound_htlcs;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::ln::channel_state::InboundHTLCDetails { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::ln::channel_state::InboundHTLCDetails<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// Pending inbound HTLCs.
///
/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_pending_inbound_htlcs(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::CVec_InboundHTLCDetailsZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.pending_inbound_htlcs = local_val;
}
/// Pending outbound HTLCs.
///
/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_pending_outbound_htlcs(this_ptr: &ChannelDetails) -> crate::c_types::derived::CVec_OutboundHTLCDetailsZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().pending_outbound_htlcs;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::ln::channel_state::OutboundHTLCDetails { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::ln::channel_state::OutboundHTLCDetails<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// Pending outbound HTLCs.
///
/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_pending_outbound_htlcs(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::CVec_OutboundHTLCDetailsZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.pending_outbound_htlcs = local_val;
}
/// Constructs a new ChannelDetails given each field
///
/// Note that funding_txo_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
/// Note that channel_type_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
/// Note that config_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelDetails_new(mut channel_id_arg: crate::lightning::ln::types::ChannelId, mut counterparty_arg: crate::lightning::ln::channel_state::ChannelCounterparty, mut funding_txo_arg: crate::lightning::chain::transaction::OutPoint, mut channel_type_arg: crate::lightning_types::features::ChannelTypeFeatures, mut short_channel_id_arg: crate::c_types::derived::COption_u64Z, mut outbound_scid_alias_arg: crate::c_types::derived::COption_u64Z, mut inbound_scid_alias_arg: crate::c_types::derived::COption_u64Z, mut channel_value_satoshis_arg: u64, mut unspendable_punishment_reserve_arg: crate::c_types::derived::COption_u64Z, mut user_channel_id_arg: crate::c_types::U128, mut feerate_sat_per_1000_weight_arg: crate::c_types::derived::COption_u32Z, mut outbound_capacity_msat_arg: u64, mut next_outbound_htlc_limit_msat_arg: u64, mut next_outbound_htlc_minimum_msat_arg: u64, mut inbound_capacity_msat_arg: u64, mut confirmations_required_arg: crate::c_types::derived::COption_u32Z, mut confirmations_arg: crate::c_types::derived::COption_u32Z, mut force_close_spend_delay_arg: crate::c_types::derived::COption_u16Z, mut is_outbound_arg: bool, mut is_channel_ready_arg: bool, mut channel_shutdown_state_arg: crate::c_types::derived::COption_ChannelShutdownStateZ, mut is_usable_arg: bool, mut is_announced_arg: bool, mut inbound_htlc_minimum_msat_arg: crate::c_types::derived::COption_u64Z, mut inbound_htlc_maximum_msat_arg: crate::c_types::derived::COption_u64Z, mut config_arg: crate::lightning::util::config::ChannelConfig, mut pending_inbound_htlcs_arg: crate::c_types::derived::CVec_InboundHTLCDetailsZ, mut pending_outbound_htlcs_arg: crate::c_types::derived::CVec_OutboundHTLCDetailsZ) -> ChannelDetails {
	let mut local_funding_txo_arg = if funding_txo_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(funding_txo_arg.take_inner()) } }) };
	let mut local_channel_type_arg = if channel_type_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_type_arg.take_inner()) } }) };
	let mut local_short_channel_id_arg = if short_channel_id_arg.is_some() { Some( { short_channel_id_arg.take() }) } else { None };
	let mut local_outbound_scid_alias_arg = if outbound_scid_alias_arg.is_some() { Some( { outbound_scid_alias_arg.take() }) } else { None };
	let mut local_inbound_scid_alias_arg = if inbound_scid_alias_arg.is_some() { Some( { inbound_scid_alias_arg.take() }) } else { None };
	let mut local_unspendable_punishment_reserve_arg = if unspendable_punishment_reserve_arg.is_some() { Some( { unspendable_punishment_reserve_arg.take() }) } else { None };
	let mut local_feerate_sat_per_1000_weight_arg = if feerate_sat_per_1000_weight_arg.is_some() { Some( { feerate_sat_per_1000_weight_arg.take() }) } else { None };
	let mut local_confirmations_required_arg = if confirmations_required_arg.is_some() { Some( { confirmations_required_arg.take() }) } else { None };
	let mut local_confirmations_arg = if confirmations_arg.is_some() { Some( { confirmations_arg.take() }) } else { None };
	let mut local_force_close_spend_delay_arg = if force_close_spend_delay_arg.is_some() { Some( { force_close_spend_delay_arg.take() }) } else { None };
	let mut local_channel_shutdown_state_arg = { /*channel_shutdown_state_arg*/ let channel_shutdown_state_arg_opt = channel_shutdown_state_arg; if channel_shutdown_state_arg_opt.is_none() { None } else { Some({ { { channel_shutdown_state_arg_opt.take() }.into_native() }})} };
	let mut local_inbound_htlc_minimum_msat_arg = if inbound_htlc_minimum_msat_arg.is_some() { Some( { inbound_htlc_minimum_msat_arg.take() }) } else { None };
	let mut local_inbound_htlc_maximum_msat_arg = if inbound_htlc_maximum_msat_arg.is_some() { Some( { inbound_htlc_maximum_msat_arg.take() }) } else { None };
	let mut local_config_arg = if config_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(config_arg.take_inner()) } }) };
	let mut local_pending_inbound_htlcs_arg = Vec::new(); for mut item in pending_inbound_htlcs_arg.into_rust().drain(..) { local_pending_inbound_htlcs_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_pending_outbound_htlcs_arg = Vec::new(); for mut item in pending_outbound_htlcs_arg.into_rust().drain(..) { local_pending_outbound_htlcs_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	ChannelDetails { inner: ObjOps::heap_alloc(nativeChannelDetails {
		channel_id: *unsafe { Box::from_raw(channel_id_arg.take_inner()) },
		counterparty: *unsafe { Box::from_raw(counterparty_arg.take_inner()) },
		funding_txo: local_funding_txo_arg,
		channel_type: local_channel_type_arg,
		short_channel_id: local_short_channel_id_arg,
		outbound_scid_alias: local_outbound_scid_alias_arg,
		inbound_scid_alias: local_inbound_scid_alias_arg,
		channel_value_satoshis: channel_value_satoshis_arg,
		unspendable_punishment_reserve: local_unspendable_punishment_reserve_arg,
		user_channel_id: user_channel_id_arg.into(),
		feerate_sat_per_1000_weight: local_feerate_sat_per_1000_weight_arg,
		outbound_capacity_msat: outbound_capacity_msat_arg,
		next_outbound_htlc_limit_msat: next_outbound_htlc_limit_msat_arg,
		next_outbound_htlc_minimum_msat: next_outbound_htlc_minimum_msat_arg,
		inbound_capacity_msat: inbound_capacity_msat_arg,
		confirmations_required: local_confirmations_required_arg,
		confirmations: local_confirmations_arg,
		force_close_spend_delay: local_force_close_spend_delay_arg,
		is_outbound: is_outbound_arg,
		is_channel_ready: is_channel_ready_arg,
		channel_shutdown_state: local_channel_shutdown_state_arg,
		is_usable: is_usable_arg,
		is_announced: is_announced_arg,
		inbound_htlc_minimum_msat: local_inbound_htlc_minimum_msat_arg,
		inbound_htlc_maximum_msat: local_inbound_htlc_maximum_msat_arg,
		config: local_config_arg,
		pending_inbound_htlcs: local_pending_inbound_htlcs_arg,
		pending_outbound_htlcs: local_pending_outbound_htlcs_arg,
	}), is_owned: true }
}
impl Clone for ChannelDetails {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelDetails>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelDetails_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelDetails)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelDetails
pub extern "C" fn ChannelDetails_clone(orig: &ChannelDetails) -> ChannelDetails {
	orig.clone()
}
/// Get a string which allows debug introspection of a ChannelDetails object
pub extern "C" fn ChannelDetails_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::ChannelDetails }).into()}
/// Gets the current SCID which should be used to identify this channel for inbound payments.
/// This should be used for providing invoice hints or in any other context where our
/// counterparty will forward a payment to us.
///
/// This is either the [`ChannelDetails::inbound_scid_alias`], if set, or the
/// [`ChannelDetails::short_channel_id`]. See those for more information.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_payment_scid(this_arg: &crate::lightning::ln::channel_state::ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_inbound_payment_scid();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Gets the current SCID which should be used to identify this channel for outbound payments.
/// This should be used in [`Route`]s to describe the first hop or in other contexts where
/// we're sending or forwarding a payment outbound over this channel.
///
/// This is either the [`ChannelDetails::short_channel_id`], if set, or the
/// [`ChannelDetails::outbound_scid_alias`]. See those for more information.
///
/// [`Route`]: crate::routing::router::Route
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelDetails_get_outbound_payment_scid(this_arg: &crate::lightning::ln::channel_state::ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_outbound_payment_scid();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

#[no_mangle]
/// Serialize the ChannelDetails object into a byte array which can be read by ChannelDetails_read
pub extern "C" fn ChannelDetails_write(obj: &crate::lightning::ln::channel_state::ChannelDetails) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelDetails_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::channel_state::nativeChannelDetails) })
}
#[no_mangle]
/// Read a ChannelDetails from a byte array, created by ChannelDetails_write
pub extern "C" fn ChannelDetails_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelDetailsDecodeErrorZ {
	let res: Result<lightning::ln::channel_state::ChannelDetails, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_state::ChannelDetails { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Further information on the details of the channel shutdown.
/// Upon channels being forced closed (i.e. commitment transaction confirmation detected
/// by `ChainMonitor`), ChannelShutdownState will be set to `ShutdownComplete` or
/// the channel will be removed shortly.
/// Also note, that in normal operation, peers could disconnect at any of these states
/// and require peer re-connection before making progress onto other states
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ChannelShutdownState {
	/// Channel has not sent or received a shutdown message.
	NotShuttingDown,
	/// Local node has sent a shutdown message for this channel.
	ShutdownInitiated,
	/// Shutdown message exchanges have concluded and the channels are in the midst of
	/// resolving all existing open HTLCs before closing can continue.
	ResolvingHTLCs,
	/// All HTLCs have been resolved, nodes are currently negotiating channel close onchain fee rates.
	NegotiatingClosingFee,
	/// We've successfully negotiated a closing_signed dance. At this point `ChannelManager` is about
	/// to drop the channel.
	ShutdownComplete,
}
use lightning::ln::channel_state::ChannelShutdownState as ChannelShutdownStateImport;
pub(crate) type nativeChannelShutdownState = ChannelShutdownStateImport;

impl ChannelShutdownState {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeChannelShutdownState {
		match self {
			ChannelShutdownState::NotShuttingDown => nativeChannelShutdownState::NotShuttingDown,
			ChannelShutdownState::ShutdownInitiated => nativeChannelShutdownState::ShutdownInitiated,
			ChannelShutdownState::ResolvingHTLCs => nativeChannelShutdownState::ResolvingHTLCs,
			ChannelShutdownState::NegotiatingClosingFee => nativeChannelShutdownState::NegotiatingClosingFee,
			ChannelShutdownState::ShutdownComplete => nativeChannelShutdownState::ShutdownComplete,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeChannelShutdownState {
		match self {
			ChannelShutdownState::NotShuttingDown => nativeChannelShutdownState::NotShuttingDown,
			ChannelShutdownState::ShutdownInitiated => nativeChannelShutdownState::ShutdownInitiated,
			ChannelShutdownState::ResolvingHTLCs => nativeChannelShutdownState::ResolvingHTLCs,
			ChannelShutdownState::NegotiatingClosingFee => nativeChannelShutdownState::NegotiatingClosingFee,
			ChannelShutdownState::ShutdownComplete => nativeChannelShutdownState::ShutdownComplete,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &ChannelShutdownStateImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeChannelShutdownState) };
		match native {
			nativeChannelShutdownState::NotShuttingDown => ChannelShutdownState::NotShuttingDown,
			nativeChannelShutdownState::ShutdownInitiated => ChannelShutdownState::ShutdownInitiated,
			nativeChannelShutdownState::ResolvingHTLCs => ChannelShutdownState::ResolvingHTLCs,
			nativeChannelShutdownState::NegotiatingClosingFee => ChannelShutdownState::NegotiatingClosingFee,
			nativeChannelShutdownState::ShutdownComplete => ChannelShutdownState::ShutdownComplete,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeChannelShutdownState) -> Self {
		match native {
			nativeChannelShutdownState::NotShuttingDown => ChannelShutdownState::NotShuttingDown,
			nativeChannelShutdownState::ShutdownInitiated => ChannelShutdownState::ShutdownInitiated,
			nativeChannelShutdownState::ResolvingHTLCs => ChannelShutdownState::ResolvingHTLCs,
			nativeChannelShutdownState::NegotiatingClosingFee => ChannelShutdownState::NegotiatingClosingFee,
			nativeChannelShutdownState::ShutdownComplete => ChannelShutdownState::ShutdownComplete,
		}
	}
}
/// Creates a copy of the ChannelShutdownState
#[no_mangle]
pub extern "C" fn ChannelShutdownState_clone(orig: &ChannelShutdownState) -> ChannelShutdownState {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelShutdownState_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const ChannelShutdownState)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelShutdownState_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut ChannelShutdownState) };
}
#[no_mangle]
/// Utility method to constructs a new NotShuttingDown-variant ChannelShutdownState
pub extern "C" fn ChannelShutdownState_not_shutting_down() -> ChannelShutdownState {
	ChannelShutdownState::NotShuttingDown}
#[no_mangle]
/// Utility method to constructs a new ShutdownInitiated-variant ChannelShutdownState
pub extern "C" fn ChannelShutdownState_shutdown_initiated() -> ChannelShutdownState {
	ChannelShutdownState::ShutdownInitiated}
#[no_mangle]
/// Utility method to constructs a new ResolvingHTLCs-variant ChannelShutdownState
pub extern "C" fn ChannelShutdownState_resolving_htlcs() -> ChannelShutdownState {
	ChannelShutdownState::ResolvingHTLCs}
#[no_mangle]
/// Utility method to constructs a new NegotiatingClosingFee-variant ChannelShutdownState
pub extern "C" fn ChannelShutdownState_negotiating_closing_fee() -> ChannelShutdownState {
	ChannelShutdownState::NegotiatingClosingFee}
#[no_mangle]
/// Utility method to constructs a new ShutdownComplete-variant ChannelShutdownState
pub extern "C" fn ChannelShutdownState_shutdown_complete() -> ChannelShutdownState {
	ChannelShutdownState::ShutdownComplete}
/// Get a string which allows debug introspection of a ChannelShutdownState object
pub extern "C" fn ChannelShutdownState_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_state::ChannelShutdownState }).into()}
/// Checks if two ChannelShutdownStates contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ChannelShutdownState_eq(a: &ChannelShutdownState, b: &ChannelShutdownState) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the ChannelShutdownState object into a byte array which can be read by ChannelShutdownState_read
pub extern "C" fn ChannelShutdownState_write(obj: &crate::lightning::ln::channel_state::ChannelShutdownState) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelShutdownState_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	ChannelShutdownState_write(unsafe { &*(obj as *const ChannelShutdownState) })
}
#[no_mangle]
/// Read a ChannelShutdownState from a byte array, created by ChannelShutdownState_write
pub extern "C" fn ChannelShutdownState_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelShutdownStateDecodeErrorZ {
	let res: Result<lightning::ln::channel_state::ChannelShutdownState, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_state::ChannelShutdownState::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
