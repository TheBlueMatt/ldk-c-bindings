// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and methods for constructing [`BlindedPaymentPath`]s to send a payment over.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::blinded_path::payment::BlindedPayInfo as nativeBlindedPayInfoImport;
pub(crate) type nativeBlindedPayInfo = nativeBlindedPayInfoImport;

/// Information needed to route a payment across a [`BlindedPaymentPath`].
#[must_use]
#[repr(C)]
pub struct BlindedPayInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedPayInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for BlindedPayInfo {
	type Target = nativeBlindedPayInfo;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for BlindedPayInfo { }
unsafe impl core::marker::Sync for BlindedPayInfo { }
impl Drop for BlindedPayInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedPayInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedPayInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_free(this_obj: BlindedPayInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPayInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedPayInfo) };
}
#[allow(unused)]
impl BlindedPayInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedPayInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedPayInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedPayInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Base fee charged (in millisatoshi) for the entire blinded path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_fee_base_msat(this_ptr: &BlindedPayInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_base_msat;
	*inner_val
}
/// Base fee charged (in millisatoshi) for the entire blinded path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_fee_base_msat(this_ptr: &mut BlindedPayInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_base_msat = val;
}
/// Liquidity fee charged (in millionths of the amount transferred) for the entire blinded path
/// (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_fee_proportional_millionths(this_ptr: &BlindedPayInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_proportional_millionths;
	*inner_val
}
/// Liquidity fee charged (in millionths of the amount transferred) for the entire blinded path
/// (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_fee_proportional_millionths(this_ptr: &mut BlindedPayInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_proportional_millionths = val;
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for the entire blinded
/// path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_cltv_expiry_delta(this_ptr: &BlindedPayInfo) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for the entire blinded
/// path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_cltv_expiry_delta(this_ptr: &mut BlindedPayInfo, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// The minimum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_htlc_minimum_msat(this_ptr: &BlindedPayInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	*inner_val
}
/// The minimum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_htlc_minimum_msat(this_ptr: &mut BlindedPayInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = val;
}
/// The maximum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_htlc_maximum_msat(this_ptr: &BlindedPayInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	*inner_val
}
/// The maximum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_htlc_maximum_msat(this_ptr: &mut BlindedPayInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = val;
}
/// Features set in `encrypted_data_tlv` for the `encrypted_recipient_data` TLV record in an
/// onion payload.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_features(this_ptr: &BlindedPayInfo) -> crate::lightning_types::features::BlindedHopFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning_types::features::BlindedHopFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_types::features::BlindedHopFeatures<>) as *mut _) }, is_owned: false }
}
/// Features set in `encrypted_data_tlv` for the `encrypted_recipient_data` TLV record in an
/// onion payload.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_features(this_ptr: &mut BlindedPayInfo, mut val: crate::lightning_types::features::BlindedHopFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new BlindedPayInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPayInfo_new(mut fee_base_msat_arg: u32, mut fee_proportional_millionths_arg: u32, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: u64, mut htlc_maximum_msat_arg: u64, mut features_arg: crate::lightning_types::features::BlindedHopFeatures) -> BlindedPayInfo {
	BlindedPayInfo { inner: ObjOps::heap_alloc(nativeBlindedPayInfo {
		fee_base_msat: fee_base_msat_arg,
		fee_proportional_millionths: fee_proportional_millionths_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: htlc_minimum_msat_arg,
		htlc_maximum_msat: htlc_maximum_msat_arg,
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for BlindedPayInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedPayInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPayInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedPayInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedPayInfo
pub extern "C" fn BlindedPayInfo_clone(orig: &BlindedPayInfo) -> BlindedPayInfo {
	orig.clone()
}
/// Get a string which allows debug introspection of a BlindedPayInfo object
pub extern "C" fn BlindedPayInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::BlindedPayInfo }).into()}
/// Generates a non-cryptographic 64-bit hash of the BlindedPayInfo.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_hash(o: &BlindedPayInfo) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedPayInfos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_eq(a: &BlindedPayInfo, b: &BlindedPayInfo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the BlindedPayInfo object into a byte array which can be read by BlindedPayInfo_read
pub extern "C" fn BlindedPayInfo_write(obj: &crate::lightning::blinded_path::payment::BlindedPayInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedPayInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativeBlindedPayInfo) })
}
#[no_mangle]
/// Read a BlindedPayInfo from a byte array, created by BlindedPayInfo_write
pub extern "C" fn BlindedPayInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedPayInfoDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::BlindedPayInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::BlindedPayInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::blinded_path::payment::BlindedPaymentPath as nativeBlindedPaymentPathImport;
pub(crate) type nativeBlindedPaymentPath = nativeBlindedPaymentPathImport;

/// A blinded path to be used for sending or receiving a payment, hiding the identity of the
/// recipient.
#[must_use]
#[repr(C)]
pub struct BlindedPaymentPath {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedPaymentPath,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for BlindedPaymentPath {
	type Target = nativeBlindedPaymentPath;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for BlindedPaymentPath { }
unsafe impl core::marker::Sync for BlindedPaymentPath { }
impl Drop for BlindedPaymentPath {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedPaymentPath>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedPaymentPath, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_free(this_obj: BlindedPaymentPath) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPaymentPath_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedPaymentPath) };
}
#[allow(unused)]
impl BlindedPaymentPath {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedPaymentPath {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedPaymentPath {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedPaymentPath {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The [`BlindedPayInfo`] used to pay this blinded path.
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_get_payinfo(this_ptr: &BlindedPaymentPath) -> crate::lightning::blinded_path::payment::BlindedPayInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payinfo;
	crate::lightning::blinded_path::payment::BlindedPayInfo { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::BlindedPayInfo<>) as *mut _) }, is_owned: false }
}
/// The [`BlindedPayInfo`] used to pay this blinded path.
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_set_payinfo(this_ptr: &mut BlindedPaymentPath, mut val: crate::lightning::blinded_path::payment::BlindedPayInfo) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payinfo = *unsafe { Box::from_raw(val.take_inner()) };
}
impl Clone for BlindedPaymentPath {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedPaymentPath>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPaymentPath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedPaymentPath)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedPaymentPath
pub extern "C" fn BlindedPaymentPath_clone(orig: &BlindedPaymentPath) -> BlindedPaymentPath {
	orig.clone()
}
/// Get a string which allows debug introspection of a BlindedPaymentPath object
pub extern "C" fn BlindedPaymentPath_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::BlindedPaymentPath }).into()}
/// Generates a non-cryptographic 64-bit hash of the BlindedPaymentPath.
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_hash(o: &BlindedPaymentPath) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedPaymentPaths contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_eq(a: &BlindedPaymentPath, b: &BlindedPaymentPath) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Create a one-hop blinded path for a payment.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_one_hop(mut payee_node_id: crate::c_types::PublicKey, mut payee_tlvs: crate::lightning::blinded_path::payment::ReceiveTlvs, mut min_final_cltv_expiry_delta: u16, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_BlindedPaymentPathNoneZ {
	let mut ret = lightning::blinded_path::payment::BlindedPaymentPath::one_hop(payee_node_id.into_rust(), *unsafe { Box::from_raw(payee_tlvs.take_inner()) }, min_final_cltv_expiry_delta, entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::BlindedPaymentPath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blinded path for a payment, to be forwarded along `intermediate_nodes`.
///
/// Errors if:
/// * a provided node id is invalid
/// * [`BlindedPayInfo`] calculation results in an integer overflow
/// * any unknown features are required in the provided [`ForwardTlvs`]
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_new(mut intermediate_nodes: crate::c_types::derived::CVec_PaymentForwardNodeZ, mut payee_node_id: crate::c_types::PublicKey, mut payee_tlvs: crate::lightning::blinded_path::payment::ReceiveTlvs, mut htlc_maximum_msat: u64, mut min_final_cltv_expiry_delta: u16, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_BlindedPaymentPathNoneZ {
	let mut local_intermediate_nodes = Vec::new(); for mut item in intermediate_nodes.into_rust().drain(..) { local_intermediate_nodes.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::blinded_path::payment::BlindedPaymentPath::new(local_intermediate_nodes, payee_node_id.into_rust(), *unsafe { Box::from_raw(payee_tlvs.take_inner()) }, htlc_maximum_msat, min_final_cltv_expiry_delta, entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::BlindedPaymentPath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Returns the introduction [`NodeId`] of the blinded path, if it is publicly reachable (i.e.,
/// it is found in the network graph).
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_public_introduction_node_id(this_arg: &crate::lightning::blinded_path::payment::BlindedPaymentPath, network_graph: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph) -> crate::lightning::routing::gossip::NodeId {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.public_introduction_node_id(network_graph.get_native_ref());
	let mut local_ret = crate::lightning::routing::gossip::NodeId { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::routing::gossip::NodeId<>) as *mut _ }, is_owned: false };
	local_ret
}

/// The [`IntroductionNode`] of the blinded path.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_introduction_node(this_arg: &crate::lightning::blinded_path::payment::BlindedPaymentPath) -> crate::lightning::blinded_path::IntroductionNode {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.introduction_node();
	crate::lightning::blinded_path::IntroductionNode::from_native(ret)
}

/// Used by the [`IntroductionNode`] to decrypt its [`encrypted_payload`] to forward the payment.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_blinding_point(this_arg: &crate::lightning::blinded_path::payment::BlindedPaymentPath) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.blinding_point();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// The [`BlindedHop`]s within the blinded path.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_blinded_hops(this_arg: &crate::lightning::blinded_path::payment::BlindedPaymentPath) -> crate::c_types::derived::CVec_BlindedHopZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.blinded_hops();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::BlindedHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Advance the blinded onion payment path by one hop, making the second hop into the new
/// introduction node.
///
/// Will only modify `self` when returning `Ok`.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPaymentPath_advance_path_by_one(this_arg: &mut crate::lightning::blinded_path::payment::BlindedPaymentPath, node_signer: &crate::lightning::sign::NodeSigner, node_id_lookup: &crate::lightning::blinded_path::NodeIdLookUp) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::blinded_path::payment::nativeBlindedPaymentPath)) }.advance_path_by_one(node_signer, node_id_lookup, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}


use lightning::blinded_path::payment::PaymentForwardNode as nativePaymentForwardNodeImport;
pub(crate) type nativePaymentForwardNode = nativePaymentForwardNodeImport;

/// An intermediate node, its outbound channel, and relay parameters.
#[must_use]
#[repr(C)]
pub struct PaymentForwardNode {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePaymentForwardNode,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for PaymentForwardNode {
	type Target = nativePaymentForwardNode;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for PaymentForwardNode { }
unsafe impl core::marker::Sync for PaymentForwardNode { }
impl Drop for PaymentForwardNode {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePaymentForwardNode>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PaymentForwardNode, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PaymentForwardNode_free(this_obj: PaymentForwardNode) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentForwardNode_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePaymentForwardNode) };
}
#[allow(unused)]
impl PaymentForwardNode {
	pub(crate) fn get_native_ref(&self) -> &'static nativePaymentForwardNode {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePaymentForwardNode {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePaymentForwardNode {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The TLVs for this node's [`BlindedHop`], where the fee parameters contained within are also
/// used for [`BlindedPayInfo`] construction.
#[no_mangle]
pub extern "C" fn PaymentForwardNode_get_tlvs(this_ptr: &PaymentForwardNode) -> crate::lightning::blinded_path::payment::ForwardTlvs {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().tlvs;
	crate::lightning::blinded_path::payment::ForwardTlvs { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::ForwardTlvs<>) as *mut _) }, is_owned: false }
}
/// The TLVs for this node's [`BlindedHop`], where the fee parameters contained within are also
/// used for [`BlindedPayInfo`] construction.
#[no_mangle]
pub extern "C" fn PaymentForwardNode_set_tlvs(this_ptr: &mut PaymentForwardNode, mut val: crate::lightning::blinded_path::payment::ForwardTlvs) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.tlvs = *unsafe { Box::from_raw(val.take_inner()) };
}
/// This node's pubkey.
#[no_mangle]
pub extern "C" fn PaymentForwardNode_get_node_id(this_ptr: &PaymentForwardNode) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// This node's pubkey.
#[no_mangle]
pub extern "C" fn PaymentForwardNode_set_node_id(this_ptr: &mut PaymentForwardNode, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_id = val.into_rust();
}
/// The maximum value, in msat, that may be accepted by this node.
#[no_mangle]
pub extern "C" fn PaymentForwardNode_get_htlc_maximum_msat(this_ptr: &PaymentForwardNode) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	*inner_val
}
/// The maximum value, in msat, that may be accepted by this node.
#[no_mangle]
pub extern "C" fn PaymentForwardNode_set_htlc_maximum_msat(this_ptr: &mut PaymentForwardNode, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = val;
}
/// Constructs a new PaymentForwardNode given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentForwardNode_new(mut tlvs_arg: crate::lightning::blinded_path::payment::ForwardTlvs, mut node_id_arg: crate::c_types::PublicKey, mut htlc_maximum_msat_arg: u64) -> PaymentForwardNode {
	PaymentForwardNode { inner: ObjOps::heap_alloc(nativePaymentForwardNode {
		tlvs: *unsafe { Box::from_raw(tlvs_arg.take_inner()) },
		node_id: node_id_arg.into_rust(),
		htlc_maximum_msat: htlc_maximum_msat_arg,
	}), is_owned: true }
}
impl Clone for PaymentForwardNode {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePaymentForwardNode>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentForwardNode_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePaymentForwardNode)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PaymentForwardNode
pub extern "C" fn PaymentForwardNode_clone(orig: &PaymentForwardNode) -> PaymentForwardNode {
	orig.clone()
}
/// Get a string which allows debug introspection of a PaymentForwardNode object
pub extern "C" fn PaymentForwardNode_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::PaymentForwardNode }).into()}

use lightning::blinded_path::payment::ForwardTlvs as nativeForwardTlvsImport;
pub(crate) type nativeForwardTlvs = nativeForwardTlvsImport;

/// Data to construct a [`BlindedHop`] for forwarding a payment.
#[must_use]
#[repr(C)]
pub struct ForwardTlvs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeForwardTlvs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ForwardTlvs {
	type Target = nativeForwardTlvs;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ForwardTlvs { }
unsafe impl core::marker::Sync for ForwardTlvs { }
impl Drop for ForwardTlvs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeForwardTlvs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ForwardTlvs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ForwardTlvs_free(this_obj: ForwardTlvs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ForwardTlvs_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeForwardTlvs) };
}
#[allow(unused)]
impl ForwardTlvs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeForwardTlvs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeForwardTlvs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeForwardTlvs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The short channel id this payment should be forwarded out over.
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_short_channel_id(this_ptr: &ForwardTlvs) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The short channel id this payment should be forwarded out over.
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_short_channel_id(this_ptr: &mut ForwardTlvs, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
/// Payment parameters for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_payment_relay(this_ptr: &ForwardTlvs) -> crate::lightning::blinded_path::payment::PaymentRelay {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_relay;
	crate::lightning::blinded_path::payment::PaymentRelay { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::PaymentRelay<>) as *mut _) }, is_owned: false }
}
/// Payment parameters for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_payment_relay(this_ptr: &mut ForwardTlvs, mut val: crate::lightning::blinded_path::payment::PaymentRelay) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_relay = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Payment constraints for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_payment_constraints(this_ptr: &ForwardTlvs) -> crate::lightning::blinded_path::payment::PaymentConstraints {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_constraints;
	crate::lightning::blinded_path::payment::PaymentConstraints { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::PaymentConstraints<>) as *mut _) }, is_owned: false }
}
/// Payment constraints for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_payment_constraints(this_ptr: &mut ForwardTlvs, mut val: crate::lightning::blinded_path::payment::PaymentConstraints) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_constraints = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Supported and required features when relaying a payment onion containing this object's
/// corresponding [`BlindedHop::encrypted_payload`].
///
/// [`BlindedHop::encrypted_payload`]: crate::blinded_path::BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_features(this_ptr: &ForwardTlvs) -> crate::lightning_types::features::BlindedHopFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning_types::features::BlindedHopFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_types::features::BlindedHopFeatures<>) as *mut _) }, is_owned: false }
}
/// Supported and required features when relaying a payment onion containing this object's
/// corresponding [`BlindedHop::encrypted_payload`].
///
/// [`BlindedHop::encrypted_payload`]: crate::blinded_path::BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_features(this_ptr: &mut ForwardTlvs, mut val: crate::lightning_types::features::BlindedHopFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Set if this [`BlindedPaymentPath`] is concatenated to another, to indicate the
/// [`BlindedPaymentPath::blinding_point`] of the appended blinded path.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_next_blinding_override(this_ptr: &ForwardTlvs) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().next_blinding_override;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(inner_val.unwrap())) } };
	local_inner_val
}
/// Set if this [`BlindedPaymentPath`] is concatenated to another, to indicate the
/// [`BlindedPaymentPath::blinding_point`] of the appended blinded path.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_next_blinding_override(this_ptr: &mut ForwardTlvs, mut val: crate::c_types::PublicKey) {
	let mut local_val = if val.is_null() { None } else { Some( { val.into_rust() }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.next_blinding_override = local_val;
}
/// Constructs a new ForwardTlvs given each field
///
/// Note that next_blinding_override_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ForwardTlvs_new(mut short_channel_id_arg: u64, mut payment_relay_arg: crate::lightning::blinded_path::payment::PaymentRelay, mut payment_constraints_arg: crate::lightning::blinded_path::payment::PaymentConstraints, mut features_arg: crate::lightning_types::features::BlindedHopFeatures, mut next_blinding_override_arg: crate::c_types::PublicKey) -> ForwardTlvs {
	let mut local_next_blinding_override_arg = if next_blinding_override_arg.is_null() { None } else { Some( { next_blinding_override_arg.into_rust() }) };
	ForwardTlvs { inner: ObjOps::heap_alloc(nativeForwardTlvs {
		short_channel_id: short_channel_id_arg,
		payment_relay: *unsafe { Box::from_raw(payment_relay_arg.take_inner()) },
		payment_constraints: *unsafe { Box::from_raw(payment_constraints_arg.take_inner()) },
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
		next_blinding_override: local_next_blinding_override_arg,
	}), is_owned: true }
}
impl Clone for ForwardTlvs {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeForwardTlvs>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ForwardTlvs_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeForwardTlvs)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ForwardTlvs
pub extern "C" fn ForwardTlvs_clone(orig: &ForwardTlvs) -> ForwardTlvs {
	orig.clone()
}
/// Get a string which allows debug introspection of a ForwardTlvs object
pub extern "C" fn ForwardTlvs_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::ForwardTlvs }).into()}

use lightning::blinded_path::payment::ReceiveTlvs as nativeReceiveTlvsImport;
pub(crate) type nativeReceiveTlvs = nativeReceiveTlvsImport;

/// Data to construct a [`BlindedHop`] for receiving a payment. This payload is custom to LDK and
/// may not be valid if received by another lightning implementation.
///
/// Can only be constructed by calling [`UnauthenticatedReceiveTlvs::authenticate`].
#[must_use]
#[repr(C)]
pub struct ReceiveTlvs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeReceiveTlvs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ReceiveTlvs {
	type Target = nativeReceiveTlvs;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ReceiveTlvs { }
unsafe impl core::marker::Sync for ReceiveTlvs { }
impl Drop for ReceiveTlvs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeReceiveTlvs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ReceiveTlvs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ReceiveTlvs_free(this_obj: ReceiveTlvs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReceiveTlvs_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeReceiveTlvs) };
}
#[allow(unused)]
impl ReceiveTlvs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeReceiveTlvs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeReceiveTlvs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeReceiveTlvs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for ReceiveTlvs {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeReceiveTlvs>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReceiveTlvs_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeReceiveTlvs)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ReceiveTlvs
pub extern "C" fn ReceiveTlvs_clone(orig: &ReceiveTlvs) -> ReceiveTlvs {
	orig.clone()
}
/// Get a string which allows debug introspection of a ReceiveTlvs object
pub extern "C" fn ReceiveTlvs_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::ReceiveTlvs }).into()}
/// Returns the underlying TLVs.
#[must_use]
#[no_mangle]
pub extern "C" fn ReceiveTlvs_tlvs(this_arg: &crate::lightning::blinded_path::payment::ReceiveTlvs) -> crate::lightning::blinded_path::payment::UnauthenticatedReceiveTlvs {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tlvs();
	crate::lightning::blinded_path::payment::UnauthenticatedReceiveTlvs { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::blinded_path::payment::UnauthenticatedReceiveTlvs<>) as *mut _) }, is_owned: false }
}


use lightning::blinded_path::payment::UnauthenticatedReceiveTlvs as nativeUnauthenticatedReceiveTlvsImport;
pub(crate) type nativeUnauthenticatedReceiveTlvs = nativeUnauthenticatedReceiveTlvsImport;

/// An unauthenticated [`ReceiveTlvs`].
#[must_use]
#[repr(C)]
pub struct UnauthenticatedReceiveTlvs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnauthenticatedReceiveTlvs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for UnauthenticatedReceiveTlvs {
	type Target = nativeUnauthenticatedReceiveTlvs;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for UnauthenticatedReceiveTlvs { }
unsafe impl core::marker::Sync for UnauthenticatedReceiveTlvs { }
impl Drop for UnauthenticatedReceiveTlvs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUnauthenticatedReceiveTlvs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UnauthenticatedReceiveTlvs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_free(this_obj: UnauthenticatedReceiveTlvs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnauthenticatedReceiveTlvs_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUnauthenticatedReceiveTlvs) };
}
#[allow(unused)]
impl UnauthenticatedReceiveTlvs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUnauthenticatedReceiveTlvs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUnauthenticatedReceiveTlvs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUnauthenticatedReceiveTlvs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_get_payment_secret(this_ptr: &UnauthenticatedReceiveTlvs) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_secret;
	&inner_val.0
}
/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_set_payment_secret(this_ptr: &mut UnauthenticatedReceiveTlvs, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_secret = ::lightning::types::payment::PaymentSecret(val.data);
}
/// Constraints for the receiver of this payment.
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_get_payment_constraints(this_ptr: &UnauthenticatedReceiveTlvs) -> crate::lightning::blinded_path::payment::PaymentConstraints {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_constraints;
	crate::lightning::blinded_path::payment::PaymentConstraints { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::PaymentConstraints<>) as *mut _) }, is_owned: false }
}
/// Constraints for the receiver of this payment.
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_set_payment_constraints(this_ptr: &mut UnauthenticatedReceiveTlvs, mut val: crate::lightning::blinded_path::payment::PaymentConstraints) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_constraints = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Context for the receiver of this payment.
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_get_payment_context(this_ptr: &UnauthenticatedReceiveTlvs) -> crate::lightning::blinded_path::payment::PaymentContext {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_context;
	crate::lightning::blinded_path::payment::PaymentContext::from_native(inner_val)
}
/// Context for the receiver of this payment.
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_set_payment_context(this_ptr: &mut UnauthenticatedReceiveTlvs, mut val: crate::lightning::blinded_path::payment::PaymentContext) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_context = val.into_native();
}
/// Constructs a new UnauthenticatedReceiveTlvs given each field
#[must_use]
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_new(mut payment_secret_arg: crate::c_types::ThirtyTwoBytes, mut payment_constraints_arg: crate::lightning::blinded_path::payment::PaymentConstraints, mut payment_context_arg: crate::lightning::blinded_path::payment::PaymentContext) -> UnauthenticatedReceiveTlvs {
	UnauthenticatedReceiveTlvs { inner: ObjOps::heap_alloc(nativeUnauthenticatedReceiveTlvs {
		payment_secret: ::lightning::types::payment::PaymentSecret(payment_secret_arg.data),
		payment_constraints: *unsafe { Box::from_raw(payment_constraints_arg.take_inner()) },
		payment_context: payment_context_arg.into_native(),
	}), is_owned: true }
}
impl Clone for UnauthenticatedReceiveTlvs {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUnauthenticatedReceiveTlvs>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnauthenticatedReceiveTlvs_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUnauthenticatedReceiveTlvs)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UnauthenticatedReceiveTlvs
pub extern "C" fn UnauthenticatedReceiveTlvs_clone(orig: &UnauthenticatedReceiveTlvs) -> UnauthenticatedReceiveTlvs {
	orig.clone()
}
/// Get a string which allows debug introspection of a UnauthenticatedReceiveTlvs object
pub extern "C" fn UnauthenticatedReceiveTlvs_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::UnauthenticatedReceiveTlvs }).into()}
/// Creates an authenticated [`ReceiveTlvs`], which includes an HMAC and the provide [`Nonce`]
/// that can be use later to verify it authenticity.
#[must_use]
#[no_mangle]
pub extern "C" fn UnauthenticatedReceiveTlvs_authenticate(mut this_arg: crate::lightning::blinded_path::payment::UnauthenticatedReceiveTlvs, mut nonce: crate::lightning::offers::nonce::Nonce, expanded_key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> crate::lightning::blinded_path::payment::ReceiveTlvs {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).authenticate(*unsafe { Box::from_raw(nonce.take_inner()) }, expanded_key.get_native_ref());
	crate::lightning::blinded_path::payment::ReceiveTlvs { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::blinded_path::payment::PaymentRelay as nativePaymentRelayImport;
pub(crate) type nativePaymentRelay = nativePaymentRelayImport;

/// Parameters for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
#[must_use]
#[repr(C)]
pub struct PaymentRelay {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePaymentRelay,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for PaymentRelay {
	type Target = nativePaymentRelay;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for PaymentRelay { }
unsafe impl core::marker::Sync for PaymentRelay { }
impl Drop for PaymentRelay {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePaymentRelay>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PaymentRelay, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PaymentRelay_free(this_obj: PaymentRelay) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentRelay_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePaymentRelay) };
}
#[allow(unused)]
impl PaymentRelay {
	pub(crate) fn get_native_ref(&self) -> &'static nativePaymentRelay {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePaymentRelay {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePaymentRelay {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_get_cltv_expiry_delta(this_ptr: &PaymentRelay) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_set_cltv_expiry_delta(this_ptr: &mut PaymentRelay, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Liquidity fee charged (in millionths of the amount transferred) for relaying a payment over
/// this [`BlindedHop`], (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn PaymentRelay_get_fee_proportional_millionths(this_ptr: &PaymentRelay) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_proportional_millionths;
	*inner_val
}
/// Liquidity fee charged (in millionths of the amount transferred) for relaying a payment over
/// this [`BlindedHop`], (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn PaymentRelay_set_fee_proportional_millionths(this_ptr: &mut PaymentRelay, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_proportional_millionths = val;
}
/// Base fee charged (in millisatoshi) for relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_get_fee_base_msat(this_ptr: &PaymentRelay) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_base_msat;
	*inner_val
}
/// Base fee charged (in millisatoshi) for relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_set_fee_base_msat(this_ptr: &mut PaymentRelay, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_base_msat = val;
}
/// Constructs a new PaymentRelay given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentRelay_new(mut cltv_expiry_delta_arg: u16, mut fee_proportional_millionths_arg: u32, mut fee_base_msat_arg: u32) -> PaymentRelay {
	PaymentRelay { inner: ObjOps::heap_alloc(nativePaymentRelay {
		cltv_expiry_delta: cltv_expiry_delta_arg,
		fee_proportional_millionths: fee_proportional_millionths_arg,
		fee_base_msat: fee_base_msat_arg,
	}), is_owned: true }
}
impl Clone for PaymentRelay {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePaymentRelay>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentRelay_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePaymentRelay)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PaymentRelay
pub extern "C" fn PaymentRelay_clone(orig: &PaymentRelay) -> PaymentRelay {
	orig.clone()
}
/// Get a string which allows debug introspection of a PaymentRelay object
pub extern "C" fn PaymentRelay_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::PaymentRelay }).into()}

use lightning::blinded_path::payment::PaymentConstraints as nativePaymentConstraintsImport;
pub(crate) type nativePaymentConstraints = nativePaymentConstraintsImport;

/// Constraints for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
#[must_use]
#[repr(C)]
pub struct PaymentConstraints {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePaymentConstraints,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for PaymentConstraints {
	type Target = nativePaymentConstraints;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for PaymentConstraints { }
unsafe impl core::marker::Sync for PaymentConstraints { }
impl Drop for PaymentConstraints {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePaymentConstraints>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PaymentConstraints, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PaymentConstraints_free(this_obj: PaymentConstraints) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentConstraints_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePaymentConstraints) };
}
#[allow(unused)]
impl PaymentConstraints {
	pub(crate) fn get_native_ref(&self) -> &'static nativePaymentConstraints {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePaymentConstraints {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePaymentConstraints {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The maximum total CLTV that is acceptable when relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_get_max_cltv_expiry(this_ptr: &PaymentConstraints) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_cltv_expiry;
	*inner_val
}
/// The maximum total CLTV that is acceptable when relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_set_max_cltv_expiry(this_ptr: &mut PaymentConstraints, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_cltv_expiry = val;
}
/// The minimum value, in msat, that may be accepted by the node corresponding to this
/// [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_get_htlc_minimum_msat(this_ptr: &PaymentConstraints) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	*inner_val
}
/// The minimum value, in msat, that may be accepted by the node corresponding to this
/// [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_set_htlc_minimum_msat(this_ptr: &mut PaymentConstraints, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = val;
}
/// Constructs a new PaymentConstraints given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentConstraints_new(mut max_cltv_expiry_arg: u32, mut htlc_minimum_msat_arg: u64) -> PaymentConstraints {
	PaymentConstraints { inner: ObjOps::heap_alloc(nativePaymentConstraints {
		max_cltv_expiry: max_cltv_expiry_arg,
		htlc_minimum_msat: htlc_minimum_msat_arg,
	}), is_owned: true }
}
impl Clone for PaymentConstraints {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePaymentConstraints>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentConstraints_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePaymentConstraints)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PaymentConstraints
pub extern "C" fn PaymentConstraints_clone(orig: &PaymentConstraints) -> PaymentConstraints {
	orig.clone()
}
/// Get a string which allows debug introspection of a PaymentConstraints object
pub extern "C" fn PaymentConstraints_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::PaymentConstraints }).into()}
/// The context of an inbound payment, which is included in a [`BlindedPaymentPath`] via
/// [`ReceiveTlvs`] and surfaced in [`PaymentPurpose`].
///
/// [`PaymentPurpose`]: crate::events::PaymentPurpose
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PaymentContext {
	/// The payment was made for an invoice requested from a BOLT 12 [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	Bolt12Offer(
		crate::lightning::blinded_path::payment::Bolt12OfferContext),
	/// The payment was made for an invoice sent for a BOLT 12 [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	Bolt12Refund(
		crate::lightning::blinded_path::payment::Bolt12RefundContext),
}
use lightning::blinded_path::payment::PaymentContext as PaymentContextImport;
pub(crate) type nativePaymentContext = PaymentContextImport;

impl PaymentContext {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentContext {
		match self {
			PaymentContext::Bolt12Offer (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentContext::Bolt12Offer (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			PaymentContext::Bolt12Refund (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentContext::Bolt12Refund (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePaymentContext {
		match self {
			PaymentContext::Bolt12Offer (mut a, ) => {
				nativePaymentContext::Bolt12Offer (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			PaymentContext::Bolt12Refund (mut a, ) => {
				nativePaymentContext::Bolt12Refund (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &PaymentContextImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativePaymentContext) };
		match native {
			nativePaymentContext::Bolt12Offer (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentContext::Bolt12Offer (
					crate::lightning::blinded_path::payment::Bolt12OfferContext { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativePaymentContext::Bolt12Refund (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentContext::Bolt12Refund (
					crate::lightning::blinded_path::payment::Bolt12RefundContext { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePaymentContext) -> Self {
		match native {
			nativePaymentContext::Bolt12Offer (mut a, ) => {
				PaymentContext::Bolt12Offer (
					crate::lightning::blinded_path::payment::Bolt12OfferContext { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativePaymentContext::Bolt12Refund (mut a, ) => {
				PaymentContext::Bolt12Refund (
					crate::lightning::blinded_path::payment::Bolt12RefundContext { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the PaymentContext
#[no_mangle]
pub extern "C" fn PaymentContext_free(this_ptr: PaymentContext) { }
/// Creates a copy of the PaymentContext
#[no_mangle]
pub extern "C" fn PaymentContext_clone(orig: &PaymentContext) -> PaymentContext {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const PaymentContext)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut PaymentContext) };
}
#[no_mangle]
/// Utility method to constructs a new Bolt12Offer-variant PaymentContext
pub extern "C" fn PaymentContext_bolt12_offer(a: crate::lightning::blinded_path::payment::Bolt12OfferContext) -> PaymentContext {
	PaymentContext::Bolt12Offer(a, )
}
#[no_mangle]
/// Utility method to constructs a new Bolt12Refund-variant PaymentContext
pub extern "C" fn PaymentContext_bolt12_refund(a: crate::lightning::blinded_path::payment::Bolt12RefundContext) -> PaymentContext {
	PaymentContext::Bolt12Refund(a, )
}
/// Get a string which allows debug introspection of a PaymentContext object
pub extern "C" fn PaymentContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::PaymentContext }).into()}
/// Checks if two PaymentContexts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn PaymentContext_eq(a: &PaymentContext, b: &PaymentContext) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning::blinded_path::payment::Bolt12OfferContext as nativeBolt12OfferContextImport;
pub(crate) type nativeBolt12OfferContext = nativeBolt12OfferContextImport;

/// The context of a payment made for an invoice requested from a BOLT 12 [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[repr(C)]
pub struct Bolt12OfferContext {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt12OfferContext,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Bolt12OfferContext {
	type Target = nativeBolt12OfferContext;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Bolt12OfferContext { }
unsafe impl core::marker::Sync for Bolt12OfferContext { }
impl Drop for Bolt12OfferContext {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt12OfferContext>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt12OfferContext, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt12OfferContext_free(this_obj: Bolt12OfferContext) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12OfferContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt12OfferContext) };
}
#[allow(unused)]
impl Bolt12OfferContext {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt12OfferContext {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt12OfferContext {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt12OfferContext {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The identifier of the [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[no_mangle]
pub extern "C" fn Bolt12OfferContext_get_offer_id(this_ptr: &Bolt12OfferContext) -> crate::lightning::offers::offer::OfferId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().offer_id;
	crate::lightning::offers::offer::OfferId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::offers::offer::OfferId<>) as *mut _) }, is_owned: false }
}
/// The identifier of the [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[no_mangle]
pub extern "C" fn Bolt12OfferContext_set_offer_id(this_ptr: &mut Bolt12OfferContext, mut val: crate::lightning::offers::offer::OfferId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.offer_id = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Fields from an [`InvoiceRequest`] sent for a [`Bolt12Invoice`].
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[no_mangle]
pub extern "C" fn Bolt12OfferContext_get_invoice_request(this_ptr: &Bolt12OfferContext) -> crate::lightning::offers::invoice_request::InvoiceRequestFields {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().invoice_request;
	crate::lightning::offers::invoice_request::InvoiceRequestFields { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::offers::invoice_request::InvoiceRequestFields<>) as *mut _) }, is_owned: false }
}
/// Fields from an [`InvoiceRequest`] sent for a [`Bolt12Invoice`].
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[no_mangle]
pub extern "C" fn Bolt12OfferContext_set_invoice_request(this_ptr: &mut Bolt12OfferContext, mut val: crate::lightning::offers::invoice_request::InvoiceRequestFields) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.invoice_request = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new Bolt12OfferContext given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12OfferContext_new(mut offer_id_arg: crate::lightning::offers::offer::OfferId, mut invoice_request_arg: crate::lightning::offers::invoice_request::InvoiceRequestFields) -> Bolt12OfferContext {
	Bolt12OfferContext { inner: ObjOps::heap_alloc(nativeBolt12OfferContext {
		offer_id: *unsafe { Box::from_raw(offer_id_arg.take_inner()) },
		invoice_request: *unsafe { Box::from_raw(invoice_request_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for Bolt12OfferContext {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt12OfferContext>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12OfferContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBolt12OfferContext)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt12OfferContext
pub extern "C" fn Bolt12OfferContext_clone(orig: &Bolt12OfferContext) -> Bolt12OfferContext {
	orig.clone()
}
/// Get a string which allows debug introspection of a Bolt12OfferContext object
pub extern "C" fn Bolt12OfferContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::Bolt12OfferContext }).into()}
/// Checks if two Bolt12OfferContexts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Bolt12OfferContext_eq(a: &Bolt12OfferContext, b: &Bolt12OfferContext) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::blinded_path::payment::Bolt12RefundContext as nativeBolt12RefundContextImport;
pub(crate) type nativeBolt12RefundContext = nativeBolt12RefundContextImport;

/// The context of a payment made for an invoice sent for a BOLT 12 [`Refund`].
///
/// [`Refund`]: crate::offers::refund::Refund
#[must_use]
#[repr(C)]
pub struct Bolt12RefundContext {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt12RefundContext,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Bolt12RefundContext {
	type Target = nativeBolt12RefundContext;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Bolt12RefundContext { }
unsafe impl core::marker::Sync for Bolt12RefundContext { }
impl Drop for Bolt12RefundContext {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt12RefundContext>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt12RefundContext, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt12RefundContext_free(this_obj: Bolt12RefundContext) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12RefundContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt12RefundContext) };
}
#[allow(unused)]
impl Bolt12RefundContext {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt12RefundContext {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt12RefundContext {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt12RefundContext {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new Bolt12RefundContext given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12RefundContext_new() -> Bolt12RefundContext {
	Bolt12RefundContext { inner: ObjOps::heap_alloc(nativeBolt12RefundContext {
	}), is_owned: true }
}
impl Clone for Bolt12RefundContext {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt12RefundContext>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12RefundContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBolt12RefundContext)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt12RefundContext
pub extern "C" fn Bolt12RefundContext_clone(orig: &Bolt12RefundContext) -> Bolt12RefundContext {
	orig.clone()
}
/// Get a string which allows debug introspection of a Bolt12RefundContext object
pub extern "C" fn Bolt12RefundContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::Bolt12RefundContext }).into()}
/// Checks if two Bolt12RefundContexts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Bolt12RefundContext_eq(a: &Bolt12RefundContext, b: &Bolt12RefundContext) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the ForwardTlvs object into a byte array which can be read by ForwardTlvs_read
pub extern "C" fn ForwardTlvs_write(obj: &crate::lightning::blinded_path::payment::ForwardTlvs) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ForwardTlvs_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativeForwardTlvs) })
}
#[no_mangle]
/// Serialize the ReceiveTlvs object into a byte array which can be read by ReceiveTlvs_read
pub extern "C" fn ReceiveTlvs_write(obj: &crate::lightning::blinded_path::payment::ReceiveTlvs) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ReceiveTlvs_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativeReceiveTlvs) })
}
#[no_mangle]
/// Serialize the UnauthenticatedReceiveTlvs object into a byte array which can be read by UnauthenticatedReceiveTlvs_read
pub extern "C" fn UnauthenticatedReceiveTlvs_write(obj: &crate::lightning::blinded_path::payment::UnauthenticatedReceiveTlvs) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn UnauthenticatedReceiveTlvs_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativeUnauthenticatedReceiveTlvs) })
}
#[no_mangle]
/// Serialize the PaymentRelay object into a byte array which can be read by PaymentRelay_read
pub extern "C" fn PaymentRelay_write(obj: &crate::lightning::blinded_path::payment::PaymentRelay) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentRelay_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativePaymentRelay) })
}
#[no_mangle]
/// Read a PaymentRelay from a byte array, created by PaymentRelay_write
pub extern "C" fn PaymentRelay_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PaymentRelayDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::PaymentRelay, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::PaymentRelay { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the PaymentConstraints object into a byte array which can be read by PaymentConstraints_read
pub extern "C" fn PaymentConstraints_write(obj: &crate::lightning::blinded_path::payment::PaymentConstraints) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentConstraints_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativePaymentConstraints) })
}
#[no_mangle]
/// Read a PaymentConstraints from a byte array, created by PaymentConstraints_write
pub extern "C" fn PaymentConstraints_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PaymentConstraintsDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::PaymentConstraints, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::PaymentConstraints { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the PaymentContext object into a byte array which can be read by PaymentContext_read
pub extern "C" fn PaymentContext_write(obj: &crate::lightning::blinded_path::payment::PaymentContext) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentContext_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	PaymentContext_write(unsafe { &*(obj as *const PaymentContext) })
}
#[no_mangle]
/// Read a PaymentContext from a byte array, created by PaymentContext_write
pub extern "C" fn PaymentContext_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PaymentContextDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::PaymentContext, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::PaymentContext::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the Bolt12OfferContext object into a byte array which can be read by Bolt12OfferContext_read
pub extern "C" fn Bolt12OfferContext_write(obj: &crate::lightning::blinded_path::payment::Bolt12OfferContext) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt12OfferContext_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativeBolt12OfferContext) })
}
#[no_mangle]
/// Read a Bolt12OfferContext from a byte array, created by Bolt12OfferContext_write
pub extern "C" fn Bolt12OfferContext_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_Bolt12OfferContextDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::Bolt12OfferContext, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::Bolt12OfferContext { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the Bolt12RefundContext object into a byte array which can be read by Bolt12RefundContext_read
pub extern "C" fn Bolt12RefundContext_write(obj: &crate::lightning::blinded_path::payment::Bolt12RefundContext) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt12RefundContext_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::payment::nativeBolt12RefundContext) })
}
#[no_mangle]
/// Read a Bolt12RefundContext from a byte array, created by Bolt12RefundContext_write
pub extern "C" fn Bolt12RefundContext_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_Bolt12RefundContextDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::Bolt12RefundContext, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::Bolt12RefundContext { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
