// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and methods for constructing [`BlindedMessagePath`]s to send a message over.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::blinded_path::message::BlindedMessagePath as nativeBlindedMessagePathImport;
pub(crate) type nativeBlindedMessagePath = nativeBlindedMessagePathImport;

/// A blinded path to be used for sending or receiving a message, hiding the identity of the
/// recipient.
#[must_use]
#[repr(C)]
pub struct BlindedMessagePath {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedMessagePath,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for BlindedMessagePath {
	type Target = nativeBlindedMessagePath;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for BlindedMessagePath { }
unsafe impl core::marker::Sync for BlindedMessagePath { }
impl Drop for BlindedMessagePath {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedMessagePath>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedMessagePath, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedMessagePath_free(this_obj: BlindedMessagePath) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedMessagePath_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedMessagePath) };
}
#[allow(unused)]
impl BlindedMessagePath {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedMessagePath {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedMessagePath {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedMessagePath {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for BlindedMessagePath {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedMessagePath>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedMessagePath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeBlindedMessagePath) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedMessagePath
pub extern "C" fn BlindedMessagePath_clone(orig: &BlindedMessagePath) -> BlindedMessagePath {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a BlindedMessagePath object
pub extern "C" fn BlindedMessagePath_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::message::BlindedMessagePath }).into()}
/// Generates a non-cryptographic 64-bit hash of the BlindedMessagePath.
#[no_mangle]
pub extern "C" fn BlindedMessagePath_hash(o: &BlindedMessagePath) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedMessagePaths contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedMessagePath_eq(a: &BlindedMessagePath, b: &BlindedMessagePath) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the BlindedMessagePath object into a byte array which can be read by BlindedMessagePath_read
pub extern "C" fn BlindedMessagePath_write(obj: &crate::lightning::blinded_path::message::BlindedMessagePath) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedMessagePath_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::message::nativeBlindedMessagePath) })
}
#[no_mangle]
/// Read a BlindedMessagePath from a byte array, created by BlindedMessagePath_write
pub extern "C" fn BlindedMessagePath_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedMessagePathDecodeErrorZ {
	let res: Result<lightning::blinded_path::message::BlindedMessagePath, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Create a one-hop blinded path for a message.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_one_hop(mut recipient_node_id: crate::c_types::PublicKey, mut local_node_receive_key: crate::lightning::sign::ReceiveAuthKey, mut context: crate::lightning::blinded_path::message::MessageContext, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::lightning::blinded_path::message::BlindedMessagePath {
	let mut ret = lightning::blinded_path::message::BlindedMessagePath::one_hop(recipient_node_id.into_rust(), *unsafe { Box::from_raw(local_node_receive_key.take_inner()) }, context.into_native(), entropy_source, secp256k1::global::SECP256K1);
	crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Create a path for an onion message, to be forwarded along `node_pks`.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_new(mut intermediate_nodes: crate::c_types::derived::CVec_MessageForwardNodeZ, mut recipient_node_id: crate::c_types::PublicKey, mut local_node_receive_key: crate::lightning::sign::ReceiveAuthKey, mut context: crate::lightning::blinded_path::message::MessageContext, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::lightning::blinded_path::message::BlindedMessagePath {
	let mut local_intermediate_nodes = Vec::new(); for mut item in intermediate_nodes.into_rust().drain(..) { local_intermediate_nodes.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::blinded_path::message::BlindedMessagePath::new(&local_intermediate_nodes[..], recipient_node_id.into_rust(), *unsafe { Box::from_raw(local_node_receive_key.take_inner()) }, context.into_native(), entropy_source, secp256k1::global::SECP256K1);
	crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Same as [`BlindedMessagePath::new`], but allows specifying a number of dummy hops.
///
/// Note:
/// At most [`MAX_DUMMY_HOPS_COUNT`] dummy hops can be added to the blinded path.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_new_with_dummy_hops(mut intermediate_nodes: crate::c_types::derived::CVec_MessageForwardNodeZ, mut recipient_node_id: crate::c_types::PublicKey, mut dummy_hop_count: usize, mut local_node_receive_key: crate::lightning::sign::ReceiveAuthKey, mut context: crate::lightning::blinded_path::message::MessageContext, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::lightning::blinded_path::message::BlindedMessagePath {
	let mut local_intermediate_nodes = Vec::new(); for mut item in intermediate_nodes.into_rust().drain(..) { local_intermediate_nodes.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::blinded_path::message::BlindedMessagePath::new_with_dummy_hops(&local_intermediate_nodes[..], recipient_node_id.into_rust(), dummy_hop_count, *unsafe { Box::from_raw(local_node_receive_key.take_inner()) }, context.into_native(), entropy_source, secp256k1::global::SECP256K1);
	crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Attempts to a use a compact representation for the [`IntroductionNode`] by using a directed
/// short channel id from a channel in `network_graph` leading to the introduction node.
///
/// While this may result in a smaller encoding, there is a trade off in that the path may
/// become invalid if the channel is closed or hasn't been propagated via gossip. Therefore,
/// calling this may not be suitable for long-lived blinded paths.
#[no_mangle]
pub extern "C" fn BlindedMessagePath_use_compact_introduction_node(this_arg: &mut crate::lightning::blinded_path::message::BlindedMessagePath, network_graph: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::blinded_path::message::nativeBlindedMessagePath)) }.use_compact_introduction_node(network_graph.get_native_ref())
}

/// Returns the introduction [`NodeId`] of the blinded path, if it is publicly reachable (i.e.,
/// it is found in the network graph).
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_public_introduction_node_id(this_arg: &crate::lightning::blinded_path::message::BlindedMessagePath, network_graph: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph) -> crate::lightning::routing::gossip::NodeId {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.public_introduction_node_id(network_graph.get_native_ref());
	let mut local_ret = crate::lightning::routing::gossip::NodeId { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::routing::gossip::NodeId<>) as *mut _ }, is_owned: false };
	local_ret
}

/// The [`IntroductionNode`] of the blinded path.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_introduction_node(this_arg: &crate::lightning::blinded_path::message::BlindedMessagePath) -> crate::lightning::blinded_path::IntroductionNode {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.introduction_node();
	crate::lightning::blinded_path::IntroductionNode::from_native(ret)
}

/// Used by the [`IntroductionNode`] to decrypt its [`encrypted_payload`] to forward the message.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_blinding_point(this_arg: &crate::lightning::blinded_path::message::BlindedMessagePath) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.blinding_point();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// The [`BlindedHop`]s within the blinded path.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_blinded_hops(this_arg: &crate::lightning::blinded_path::message::BlindedMessagePath) -> crate::c_types::derived::CVec_BlindedHopZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.blinded_hops();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::BlindedHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Advance the blinded onion message path by one hop, making the second hop into the new
/// introduction node.
///
/// Will only modify `self` when returning `Ok`.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_advance_path_by_one(this_arg: &mut crate::lightning::blinded_path::message::BlindedMessagePath, node_signer: &crate::lightning::sign::NodeSigner, node_id_lookup: &crate::lightning::blinded_path::NodeIdLookUp) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::blinded_path::message::nativeBlindedMessagePath)) }.advance_path_by_one(node_signer, node_id_lookup, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Creates a new [`BlindedMessagePath`] from its constituent parts.
///
/// Useful when you need to reconstruct a blinded path from previously serialized components.
///
/// Parameters:
/// * `introduction_node_id`: The public key of the introduction node in the path
/// * `blinding_point`: The public key used for blinding the path
/// * `blinded_hops`: The encrypted routing information for each hop in the path
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_from_blinded_path(mut introduction_node_id: crate::c_types::PublicKey, mut blinding_point: crate::c_types::PublicKey, mut blinded_hops: crate::c_types::derived::CVec_BlindedHopZ) -> crate::lightning::blinded_path::message::BlindedMessagePath {
	let mut local_blinded_hops = Vec::new(); for mut item in blinded_hops.into_rust().drain(..) { local_blinded_hops.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::blinded_path::message::BlindedMessagePath::from_blinded_path(introduction_node_id.into_rust(), blinding_point.into_rust(), local_blinded_hops);
	crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// The next hop to forward an onion message along its path.
///
/// Note that payment blinded paths always specify their next hop using an explicit node id.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum NextMessageHop {
	/// The node id of the next hop.
	NodeId(
		crate::c_types::PublicKey),
	/// The short channel id leading to the next hop.
	ShortChannelId(
		u64),
}
use lightning::blinded_path::message::NextMessageHop as NextMessageHopImport;
pub(crate) type nativeNextMessageHop = NextMessageHopImport;

impl NextMessageHop {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeNextMessageHop {
		match self {
			NextMessageHop::NodeId (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeNextMessageHop::NodeId (
					a_nonref.into_rust(),
				)
			},
			NextMessageHop::ShortChannelId (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeNextMessageHop::ShortChannelId (
					a_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeNextMessageHop {
		match self {
			NextMessageHop::NodeId (mut a, ) => {
				nativeNextMessageHop::NodeId (
					a.into_rust(),
				)
			},
			NextMessageHop::ShortChannelId (mut a, ) => {
				nativeNextMessageHop::ShortChannelId (
					a,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &NextMessageHopImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeNextMessageHop) };
		match native {
			nativeNextMessageHop::NodeId (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				NextMessageHop::NodeId (
					crate::c_types::PublicKey::from_rust(&a_nonref),
				)
			},
			nativeNextMessageHop::ShortChannelId (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				NextMessageHop::ShortChannelId (
					a_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeNextMessageHop) -> Self {
		match native {
			nativeNextMessageHop::NodeId (mut a, ) => {
				NextMessageHop::NodeId (
					crate::c_types::PublicKey::from_rust(&a),
				)
			},
			nativeNextMessageHop::ShortChannelId (mut a, ) => {
				NextMessageHop::ShortChannelId (
					a,
				)
			},
		}
	}
}
/// Frees any resources used by the NextMessageHop
#[no_mangle]
pub extern "C" fn NextMessageHop_free(this_ptr: NextMessageHop) { }
/// Creates a copy of the NextMessageHop
#[no_mangle]
pub extern "C" fn NextMessageHop_clone(orig: &NextMessageHop) -> NextMessageHop {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NextMessageHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const NextMessageHop)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NextMessageHop_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut NextMessageHop) };
}
#[no_mangle]
/// Utility method to constructs a new NodeId-variant NextMessageHop
pub extern "C" fn NextMessageHop_node_id(a: crate::c_types::PublicKey) -> NextMessageHop {
	NextMessageHop::NodeId(a, )
}
#[no_mangle]
/// Utility method to constructs a new ShortChannelId-variant NextMessageHop
pub extern "C" fn NextMessageHop_short_channel_id(a: u64) -> NextMessageHop {
	NextMessageHop::ShortChannelId(a, )
}
/// Get a string which allows debug introspection of a NextMessageHop object
pub extern "C" fn NextMessageHop_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::message::NextMessageHop }).into()}
/// Generates a non-cryptographic 64-bit hash of the NextMessageHop.
#[no_mangle]
pub extern "C" fn NextMessageHop_hash(o: &NextMessageHop) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two NextMessageHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn NextMessageHop_eq(a: &NextMessageHop, b: &NextMessageHop) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning::blinded_path::message::MessageForwardNode as nativeMessageForwardNodeImport;
pub(crate) type nativeMessageForwardNode = nativeMessageForwardNodeImport;

/// An intermediate node, and possibly a short channel id leading to the next node.
///
/// Note:
/// [`MessageForwardNode`] must represent a node that supports [`supports_onion_messages`]
/// in order to be included in valid blinded paths for onion messaging.
///
/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
#[must_use]
#[repr(C)]
pub struct MessageForwardNode {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMessageForwardNode,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for MessageForwardNode {
	type Target = nativeMessageForwardNode;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for MessageForwardNode { }
unsafe impl core::marker::Sync for MessageForwardNode { }
impl Drop for MessageForwardNode {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMessageForwardNode>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MessageForwardNode, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MessageForwardNode_free(this_obj: MessageForwardNode) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageForwardNode_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMessageForwardNode) };
}
#[allow(unused)]
impl MessageForwardNode {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMessageForwardNode {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMessageForwardNode {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMessageForwardNode {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// This node's pubkey.
#[no_mangle]
pub extern "C" fn MessageForwardNode_get_node_id(this_ptr: &MessageForwardNode) -> crate::c_types::PublicKey {
	let mut inner_val = &mut MessageForwardNode::get_native_mut_ref(this_ptr).node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// This node's pubkey.
#[no_mangle]
pub extern "C" fn MessageForwardNode_set_node_id(this_ptr: &mut MessageForwardNode, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_id = val.into_rust();
}
/// The channel between `node_id` and the next hop. If set, the constructed [`BlindedHop`]'s
/// `encrypted_payload` will use this instead of the next [`MessageForwardNode::node_id`] for a
/// more compact representation.
#[no_mangle]
pub extern "C" fn MessageForwardNode_get_short_channel_id(this_ptr: &MessageForwardNode) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut MessageForwardNode::get_native_mut_ref(this_ptr).short_channel_id;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The channel between `node_id` and the next hop. If set, the constructed [`BlindedHop`]'s
/// `encrypted_payload` will use this instead of the next [`MessageForwardNode::node_id`] for a
/// more compact representation.
#[no_mangle]
pub extern "C" fn MessageForwardNode_set_short_channel_id(this_ptr: &mut MessageForwardNode, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = local_val;
}
/// Constructs a new MessageForwardNode given each field
#[must_use]
#[no_mangle]
pub extern "C" fn MessageForwardNode_new(mut node_id_arg: crate::c_types::PublicKey, mut short_channel_id_arg: crate::c_types::derived::COption_u64Z) -> MessageForwardNode {
	let mut local_short_channel_id_arg = if short_channel_id_arg.is_some() { Some( { short_channel_id_arg.take() }) } else { None };
	MessageForwardNode { inner: ObjOps::heap_alloc(nativeMessageForwardNode {
		node_id: node_id_arg.into_rust(),
		short_channel_id: local_short_channel_id_arg,
	}), is_owned: true }
}
impl Clone for MessageForwardNode {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeMessageForwardNode>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageForwardNode_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeMessageForwardNode) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the MessageForwardNode
pub extern "C" fn MessageForwardNode_clone(orig: &MessageForwardNode) -> MessageForwardNode {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a MessageForwardNode object
pub extern "C" fn MessageForwardNode_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::message::MessageForwardNode }).into()}
/// Generates a non-cryptographic 64-bit hash of the MessageForwardNode.
#[no_mangle]
pub extern "C" fn MessageForwardNode_hash(o: &MessageForwardNode) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two MessageForwardNodes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn MessageForwardNode_eq(a: &MessageForwardNode, b: &MessageForwardNode) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Additional data included by the recipient in a [`BlindedMessagePath`].
///
/// This data is encrypted by the recipient and will be given to the corresponding message handler
/// when handling a message sent over the [`BlindedMessagePath`]. The recipient can use this data to
/// authenticate the message or for further processing if needed.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum MessageContext {
	/// Context specific to an [`OffersMessage`].
	///
	/// [`OffersMessage`]: crate::onion_message::offers::OffersMessage
	Offers(
		crate::lightning::blinded_path::message::OffersContext),
	/// Context specific to an [`AsyncPaymentsMessage`].
	///
	/// [`AsyncPaymentsMessage`]: crate::onion_message::async_payments::AsyncPaymentsMessage
	AsyncPayments(
		crate::lightning::blinded_path::message::AsyncPaymentsContext),
	/// Represents a context for a blinded path used in a reply path when requesting a DNSSEC proof
	/// in a [`DNSResolverMessage`].
	///
	/// [`DNSResolverMessage`]: crate::onion_message::dns_resolution::DNSResolverMessage
	DNSResolver(
		crate::lightning::blinded_path::message::DNSResolverContext),
	/// Context specific to a [`CustomOnionMessageHandler::CustomMessage`].
	///
	/// [`CustomOnionMessageHandler::CustomMessage`]: crate::onion_message::messenger::CustomOnionMessageHandler::CustomMessage
	Custom(
		crate::c_types::derived::CVec_u8Z),
}
use lightning::blinded_path::message::MessageContext as MessageContextImport;
pub(crate) type nativeMessageContext = MessageContextImport;

impl MessageContext {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMessageContext {
		match self {
			MessageContext::Offers (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeMessageContext::Offers (
					a_nonref.into_native(),
				)
			},
			MessageContext::AsyncPayments (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeMessageContext::AsyncPayments (
					a_nonref.into_native(),
				)
			},
			MessageContext::DNSResolver (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeMessageContext::DNSResolver (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			MessageContext::Custom (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.into_rust().drain(..) { local_a_nonref.push( { item }); };
				nativeMessageContext::Custom (
					local_a_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeMessageContext {
		match self {
			MessageContext::Offers (mut a, ) => {
				nativeMessageContext::Offers (
					a.into_native(),
				)
			},
			MessageContext::AsyncPayments (mut a, ) => {
				nativeMessageContext::AsyncPayments (
					a.into_native(),
				)
			},
			MessageContext::DNSResolver (mut a, ) => {
				nativeMessageContext::DNSResolver (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			MessageContext::Custom (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.into_rust().drain(..) { local_a.push( { item }); };
				nativeMessageContext::Custom (
					local_a,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &MessageContextImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeMessageContext) };
		match native {
			nativeMessageContext::Offers (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				MessageContext::Offers (
					crate::lightning::blinded_path::message::OffersContext::native_into(a_nonref),
				)
			},
			nativeMessageContext::AsyncPayments (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				MessageContext::AsyncPayments (
					crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(a_nonref),
				)
			},
			nativeMessageContext::DNSResolver (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				MessageContext::DNSResolver (
					crate::lightning::blinded_path::message::DNSResolverContext { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeMessageContext::Custom (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.drain(..) { local_a_nonref.push( { item }); };
				MessageContext::Custom (
					local_a_nonref.into(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeMessageContext) -> Self {
		match native {
			nativeMessageContext::Offers (mut a, ) => {
				MessageContext::Offers (
					crate::lightning::blinded_path::message::OffersContext::native_into(a),
				)
			},
			nativeMessageContext::AsyncPayments (mut a, ) => {
				MessageContext::AsyncPayments (
					crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(a),
				)
			},
			nativeMessageContext::DNSResolver (mut a, ) => {
				MessageContext::DNSResolver (
					crate::lightning::blinded_path::message::DNSResolverContext { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeMessageContext::Custom (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.drain(..) { local_a.push( { item }); };
				MessageContext::Custom (
					local_a.into(),
				)
			},
		}
	}
}
/// Frees any resources used by the MessageContext
#[no_mangle]
pub extern "C" fn MessageContext_free(this_ptr: MessageContext) { }
/// Creates a copy of the MessageContext
#[no_mangle]
pub extern "C" fn MessageContext_clone(orig: &MessageContext) -> MessageContext {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const MessageContext)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut MessageContext) };
}
#[no_mangle]
/// Utility method to constructs a new Offers-variant MessageContext
pub extern "C" fn MessageContext_offers(a: crate::lightning::blinded_path::message::OffersContext) -> MessageContext {
	MessageContext::Offers(a, )
}
#[no_mangle]
/// Utility method to constructs a new AsyncPayments-variant MessageContext
pub extern "C" fn MessageContext_async_payments(a: crate::lightning::blinded_path::message::AsyncPaymentsContext) -> MessageContext {
	MessageContext::AsyncPayments(a, )
}
#[no_mangle]
/// Utility method to constructs a new DNSResolver-variant MessageContext
pub extern "C" fn MessageContext_dnsresolver(a: crate::lightning::blinded_path::message::DNSResolverContext) -> MessageContext {
	MessageContext::DNSResolver(a, )
}
#[no_mangle]
/// Utility method to constructs a new Custom-variant MessageContext
pub extern "C" fn MessageContext_custom(a: crate::c_types::derived::CVec_u8Z) -> MessageContext {
	MessageContext::Custom(a, )
}
/// Get a string which allows debug introspection of a MessageContext object
pub extern "C" fn MessageContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::message::MessageContext }).into()}
/// Contains data specific to an [`OffersMessage`].
///
/// [`OffersMessage`]: crate::onion_message::offers::OffersMessage
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum OffersContext {
	/// Context used by a [`BlindedMessagePath`] within an [`Offer`].
	///
	/// This variant is intended to be received when handling an [`InvoiceRequest`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	InvoiceRequest {
		/// A nonce used for authenticating that an [`InvoiceRequest`] is for a valid [`Offer`] and
		/// for deriving the offer's signing keys.
		///
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		/// [`Offer`]: crate::offers::offer::Offer
		nonce: crate::lightning::offers::nonce::Nonce,
	},
	/// Context used by a [`BlindedMessagePath`] within the [`Offer`] of an async recipient.
	///
	/// This variant is received by the static invoice server when handling an [`InvoiceRequest`] on
	/// behalf of said async recipient.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	StaticInvoiceRequested {
		/// An identifier for the async recipient for whom we as a static invoice server are serving
		/// [`StaticInvoice`]s. Used paired with the
		/// [`OffersContext::StaticInvoiceRequested::invoice_slot`] when looking up a corresponding
		/// [`StaticInvoice`] to return to the payer if the recipient is offline. This id was previously
		/// provided via [`AsyncPaymentsContext::ServeStaticInvoice::recipient_id`].
		///
		/// Also useful for rate limiting the number of [`InvoiceRequest`]s we will respond to on
		/// recipient's behalf.
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		recipient_id: crate::c_types::derived::CVec_u8Z,
		/// The slot number for a specific [`StaticInvoice`] that the recipient previously
		/// requested be served on their behalf. Useful when paired with the
		/// [`OffersContext::StaticInvoiceRequested::recipient_id`] to pull that specific invoice from
		/// the database when payers send an [`InvoiceRequest`]. This id was previously
		/// provided via [`AsyncPaymentsContext::ServeStaticInvoice::invoice_slot`].
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		invoice_slot: u16,
		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored.
		///
		/// Useful to timeout async recipients that are no longer supported as clients.
		path_absolute_expiry: u64,
	},
	/// Context used by a [`BlindedMessagePath`] within a [`Refund`] or as a reply path for an
	/// [`InvoiceRequest`].
	///
	/// This variant is intended to be received when handling a [`Bolt12Invoice`] or an
	/// [`InvoiceError`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`InvoiceError`]: crate::offers::invoice_error::InvoiceError
	OutboundPayment {
		/// Payment ID used when creating a [`Refund`] or [`InvoiceRequest`].
		///
		/// [`Refund`]: crate::offers::refund::Refund
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// A nonce used for authenticating that a [`Bolt12Invoice`] is for a valid [`Refund`] or
		/// [`InvoiceRequest`] and for deriving their signing keys.
		///
		/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
		/// [`Refund`]: crate::offers::refund::Refund
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		nonce: crate::lightning::offers::nonce::Nonce,
	},
	/// Context used by a [`BlindedMessagePath`] as a reply path for a [`Bolt12Invoice`].
	///
	/// This variant is intended to be received when handling an [`InvoiceError`].
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`InvoiceError`]: crate::offers::invoice_error::InvoiceError
	InboundPayment {
		/// The same payment hash as [`Bolt12Invoice::payment_hash`].
		///
		/// [`Bolt12Invoice::payment_hash`]: crate::offers::invoice::Bolt12Invoice::payment_hash
		payment_hash: crate::c_types::ThirtyTwoBytes,
	},
}
use lightning::blinded_path::message::OffersContext as OffersContextImport;
pub(crate) type nativeOffersContext = OffersContextImport;

impl OffersContext {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeOffersContext {
		match self {
			OffersContext::InvoiceRequest {ref nonce, } => {
				let mut nonce_nonref = Clone::clone(nonce);
				nativeOffersContext::InvoiceRequest {
					nonce: *unsafe { Box::from_raw(nonce_nonref.take_inner()) },
				}
			},
			OffersContext::StaticInvoiceRequested {ref recipient_id, ref invoice_slot, ref path_absolute_expiry, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.into_rust().drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				nativeOffersContext::StaticInvoiceRequested {
					recipient_id: local_recipient_id_nonref,
					invoice_slot: invoice_slot_nonref,
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry_nonref),
				}
			},
			OffersContext::OutboundPayment {ref payment_id, ref nonce, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut nonce_nonref = Clone::clone(nonce);
				nativeOffersContext::OutboundPayment {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					nonce: *unsafe { Box::from_raw(nonce_nonref.take_inner()) },
				}
			},
			OffersContext::InboundPayment {ref payment_hash, } => {
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				nativeOffersContext::InboundPayment {
					payment_hash: ::lightning::types::payment::PaymentHash(payment_hash_nonref.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeOffersContext {
		match self {
			OffersContext::InvoiceRequest {mut nonce, } => {
				nativeOffersContext::InvoiceRequest {
					nonce: *unsafe { Box::from_raw(nonce.take_inner()) },
				}
			},
			OffersContext::StaticInvoiceRequested {mut recipient_id, mut invoice_slot, mut path_absolute_expiry, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.into_rust().drain(..) { local_recipient_id.push( { item }); };
				nativeOffersContext::StaticInvoiceRequested {
					recipient_id: local_recipient_id,
					invoice_slot: invoice_slot,
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry),
				}
			},
			OffersContext::OutboundPayment {mut payment_id, mut nonce, } => {
				nativeOffersContext::OutboundPayment {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					nonce: *unsafe { Box::from_raw(nonce.take_inner()) },
				}
			},
			OffersContext::InboundPayment {mut payment_hash, } => {
				nativeOffersContext::InboundPayment {
					payment_hash: ::lightning::types::payment::PaymentHash(payment_hash.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &OffersContextImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeOffersContext) };
		match native {
			nativeOffersContext::InvoiceRequest {ref nonce, } => {
				let mut nonce_nonref = Clone::clone(nonce);
				OffersContext::InvoiceRequest {
					nonce: crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(nonce_nonref), is_owned: true },
				}
			},
			nativeOffersContext::StaticInvoiceRequested {ref recipient_id, ref invoice_slot, ref path_absolute_expiry, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				OffersContext::StaticInvoiceRequested {
					recipient_id: local_recipient_id_nonref.into(),
					invoice_slot: invoice_slot_nonref,
					path_absolute_expiry: path_absolute_expiry_nonref.as_secs(),
				}
			},
			nativeOffersContext::OutboundPayment {ref payment_id, ref nonce, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut nonce_nonref = Clone::clone(nonce);
				OffersContext::OutboundPayment {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					nonce: crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(nonce_nonref), is_owned: true },
				}
			},
			nativeOffersContext::InboundPayment {ref payment_hash, } => {
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				OffersContext::InboundPayment {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeOffersContext) -> Self {
		match native {
			nativeOffersContext::InvoiceRequest {mut nonce, } => {
				OffersContext::InvoiceRequest {
					nonce: crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(nonce), is_owned: true },
				}
			},
			nativeOffersContext::StaticInvoiceRequested {mut recipient_id, mut invoice_slot, mut path_absolute_expiry, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.drain(..) { local_recipient_id.push( { item }); };
				OffersContext::StaticInvoiceRequested {
					recipient_id: local_recipient_id.into(),
					invoice_slot: invoice_slot,
					path_absolute_expiry: path_absolute_expiry.as_secs(),
				}
			},
			nativeOffersContext::OutboundPayment {mut payment_id, mut nonce, } => {
				OffersContext::OutboundPayment {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					nonce: crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(nonce), is_owned: true },
				}
			},
			nativeOffersContext::InboundPayment {mut payment_hash, } => {
				OffersContext::InboundPayment {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
				}
			},
		}
	}
}
/// Frees any resources used by the OffersContext
#[no_mangle]
pub extern "C" fn OffersContext_free(this_ptr: OffersContext) { }
/// Creates a copy of the OffersContext
#[no_mangle]
pub extern "C" fn OffersContext_clone(orig: &OffersContext) -> OffersContext {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OffersContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const OffersContext)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OffersContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut OffersContext) };
}
#[no_mangle]
/// Utility method to constructs a new InvoiceRequest-variant OffersContext
pub extern "C" fn OffersContext_invoice_request(nonce: crate::lightning::offers::nonce::Nonce) -> OffersContext {
	OffersContext::InvoiceRequest {
		nonce,
	}
}
#[no_mangle]
/// Utility method to constructs a new StaticInvoiceRequested-variant OffersContext
pub extern "C" fn OffersContext_static_invoice_requested(recipient_id: crate::c_types::derived::CVec_u8Z, invoice_slot: u16, path_absolute_expiry: u64) -> OffersContext {
	OffersContext::StaticInvoiceRequested {
		recipient_id,
		invoice_slot,
		path_absolute_expiry,
	}
}
#[no_mangle]
/// Utility method to constructs a new OutboundPayment-variant OffersContext
pub extern "C" fn OffersContext_outbound_payment(payment_id: crate::c_types::ThirtyTwoBytes, nonce: crate::lightning::offers::nonce::Nonce) -> OffersContext {
	OffersContext::OutboundPayment {
		payment_id,
		nonce,
	}
}
#[no_mangle]
/// Utility method to constructs a new InboundPayment-variant OffersContext
pub extern "C" fn OffersContext_inbound_payment(payment_hash: crate::c_types::ThirtyTwoBytes) -> OffersContext {
	OffersContext::InboundPayment {
		payment_hash,
	}
}
/// Get a string which allows debug introspection of a OffersContext object
pub extern "C" fn OffersContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::message::OffersContext }).into()}
/// Checks if two OffersContexts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn OffersContext_eq(a: &OffersContext, b: &OffersContext) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Contains data specific to an [`AsyncPaymentsMessage`].
///
/// [`AsyncPaymentsMessage`]: crate::onion_message::async_payments::AsyncPaymentsMessage
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum AsyncPaymentsContext {
	/// Context used by a [`BlindedMessagePath`] provided out-of-band to an async recipient, where the
	/// context is provided back to the static invoice server in corresponding [`OfferPathsRequest`]s.
	///
	/// [`OfferPathsRequest`]: crate::onion_message::async_payments::OfferPathsRequest
	OfferPathsRequest {
		/// An identifier for the async recipient that is requesting blinded paths to include in their
		/// [`Offer::paths`]. This ID will be surfaced when the async recipient eventually sends a
		/// corresponding [`ServeStaticInvoice`] message, and can be used to rate limit the recipient.
		///
		/// [`Offer::paths`]: crate::offers::offer::Offer::paths
		/// [`ServeStaticInvoice`]: crate::onion_message::async_payments::ServeStaticInvoice
		recipient_id: crate::c_types::derived::CVec_u8Z,
		/// An optional field indicating the time as duration since the Unix epoch at which this path
		/// expires and messages sent over it should be ignored.
		///
		/// Useful to timeout async recipients that are no longer supported as clients.
		path_absolute_expiry: crate::c_types::derived::COption_u64Z,
	},
	/// Context used by a reply path to an [`OfferPathsRequest`], provided back to us as an async
	/// recipient in corresponding [`OfferPaths`] messages from the static invoice server.
	///
	/// [`OfferPathsRequest`]: crate::onion_message::async_payments::OfferPathsRequest
	/// [`OfferPaths`]: crate::onion_message::async_payments::OfferPaths
	OfferPaths {
		/// The \"slot\" in the static invoice server's database that the invoice corresponding to these
		/// offer paths should go into, originally set by us in [`OfferPathsRequest::invoice_slot`]. This
		/// value allows us as the recipient to replace a specific invoice that is stored by the server,
		/// which is useful for limiting the number of invoices stored by the server while also keeping
		/// all the invoices persisted with the server fresh.
		///
		/// [`OfferPathsRequest::invoice_slot`]: crate::onion_message::async_payments::OfferPathsRequest::invoice_slot
		invoice_slot: u16,
		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored.
		///
		/// This avoids the situation where the [`OfferPaths`] message is very delayed and thus
		/// outdated.
		///
		/// [`OfferPaths`]: crate::onion_message::async_payments::OfferPaths
		path_absolute_expiry: u64,
	},
	/// Context used by a reply path to an [`OfferPaths`] message, provided back to us as the static
	/// invoice server in corresponding [`ServeStaticInvoice`] messages.
	///
	/// [`OfferPaths`]: crate::onion_message::async_payments::OfferPaths
	/// [`ServeStaticInvoice`]: crate::onion_message::async_payments::ServeStaticInvoice
	ServeStaticInvoice {
		/// An identifier for the async recipient that is requesting that a [`StaticInvoice`] be served
		/// on their behalf.
		///
		/// Useful when surfaced alongside the below `invoice_slot` when payers send an
		/// [`InvoiceRequest`], to pull the specific static invoice from the database.
		///
		/// Also useful to rate limit the invoices being persisted on behalf of a particular recipient.
		///
		/// This id will be provided back to us as the static invoice server via
		/// [`OffersContext::StaticInvoiceRequested::recipient_id`].
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		recipient_id: crate::c_types::derived::CVec_u8Z,
		/// The slot number for the specific [`StaticInvoice`] that the recipient is requesting be
		/// served on their behalf. Useful when surfaced alongside the above `recipient_id` when payers
		/// send an [`InvoiceRequest`], to pull the specific static invoice from the database. This id
		/// will be provided back to us as the static invoice server via
		/// [`OffersContext::StaticInvoiceRequested::invoice_slot`].
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		invoice_slot: u16,
		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored.
		///
		/// Useful to timeout async recipients that are no longer supported as clients.
		path_absolute_expiry: u64,
	},
	/// Context used by a reply path to a [`ServeStaticInvoice`] message, provided back to us in
	/// corresponding [`StaticInvoicePersisted`] messages.
	///
	/// [`ServeStaticInvoice`]: crate::onion_message::async_payments::ServeStaticInvoice
	/// [`StaticInvoicePersisted`]: crate::onion_message::async_payments::StaticInvoicePersisted
	StaticInvoicePersisted {
		/// The id of the offer in the cache corresponding to the [`StaticInvoice`] that has been
		/// persisted. This invoice is now ready to be provided by the static invoice server in response
		/// to [`InvoiceRequest`]s, so the corresponding offer can be marked as ready to receive
		/// payments.
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		offer_id: crate::lightning::offers::offer::OfferId,
		/// The time as duration since the Unix epoch at which the invoice corresponding to this path
		/// was created. Useful to know when an invoice needs replacement.
		invoice_created_at: u64,
	},
	/// Context contained within the reply [`BlindedMessagePath`] we put in outbound
	/// [`HeldHtlcAvailable`] messages, provided back to us in corresponding [`ReleaseHeldHtlc`]
	/// messages if we are an always-online sender paying an async recipient.
	///
	/// [`HeldHtlcAvailable`]: crate::onion_message::async_payments::HeldHtlcAvailable
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	OutboundPayment {
		/// ID used when payment to the originating [`Offer`] was initiated. Useful for us to identify
		/// which of our pending outbound payments should be released to its often-offline payee.
		///
		/// [`Offer`]: crate::offers::offer::Offer
		payment_id: crate::c_types::ThirtyTwoBytes,
	},
	/// Context contained within the [`BlindedMessagePath`]s we put in static invoices, provided back
	/// to us in corresponding [`HeldHtlcAvailable`] messages.
	///
	/// [`HeldHtlcAvailable`]: crate::onion_message::async_payments::HeldHtlcAvailable
	InboundPayment {
		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored. Without this, anyone with the path corresponding to this context is
		/// able to trivially ask if we're online forever.
		path_absolute_expiry: u64,
	},
	/// Context contained within the reply [`BlindedMessagePath`] put in outbound
	/// [`HeldHtlcAvailable`] messages, provided back to the async sender's always-online counterparty
	/// in corresponding [`ReleaseHeldHtlc`] messages.
	///
	/// [`HeldHtlcAvailable`]: crate::onion_message::async_payments::HeldHtlcAvailable
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	ReleaseHeldHtlc {
		/// An identifier for the HTLC that should be released by us as the sender's always-online
		/// channel counterparty to the often-offline recipient.
		intercept_id: crate::c_types::ThirtyTwoBytes,
		/// The short channel id alias corresponding to the to-be-released inbound HTLC, to help locate
		/// the HTLC internally if the [`ReleaseHeldHtlc`] races our node decoding the held HTLC's
		/// onion.
		///
		/// We use the outbound scid alias because it is stable even if the channel splices, unlike
		/// regular short channel ids.
		///
		/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
		prev_outbound_scid_alias: u64,
		/// The id of the to-be-released HTLC, to help locate the HTLC internally if the
		/// [`ReleaseHeldHtlc`] races our node decoding the held HTLC's onion.
		///
		/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
		htlc_id: u64,
	},
}
use lightning::blinded_path::message::AsyncPaymentsContext as AsyncPaymentsContextImport;
pub(crate) type nativeAsyncPaymentsContext = AsyncPaymentsContextImport;

impl AsyncPaymentsContext {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeAsyncPaymentsContext {
		match self {
			AsyncPaymentsContext::OfferPathsRequest {ref recipient_id, ref path_absolute_expiry, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.into_rust().drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				let mut local_path_absolute_expiry_nonref = { /*path_absolute_expiry_nonref*/ let path_absolute_expiry_nonref_opt = path_absolute_expiry_nonref; if path_absolute_expiry_nonref_opt.is_none() { None } else { Some({ { core::time::Duration::from_secs({ path_absolute_expiry_nonref_opt.take() }) }})} };
				nativeAsyncPaymentsContext::OfferPathsRequest {
					recipient_id: local_recipient_id_nonref,
					path_absolute_expiry: local_path_absolute_expiry_nonref,
				}
			},
			AsyncPaymentsContext::OfferPaths {ref invoice_slot, ref path_absolute_expiry, } => {
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				nativeAsyncPaymentsContext::OfferPaths {
					invoice_slot: invoice_slot_nonref,
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry_nonref),
				}
			},
			AsyncPaymentsContext::ServeStaticInvoice {ref recipient_id, ref invoice_slot, ref path_absolute_expiry, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.into_rust().drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				nativeAsyncPaymentsContext::ServeStaticInvoice {
					recipient_id: local_recipient_id_nonref,
					invoice_slot: invoice_slot_nonref,
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry_nonref),
				}
			},
			AsyncPaymentsContext::StaticInvoicePersisted {ref offer_id, ref invoice_created_at, } => {
				let mut offer_id_nonref = Clone::clone(offer_id);
				let mut invoice_created_at_nonref = Clone::clone(invoice_created_at);
				nativeAsyncPaymentsContext::StaticInvoicePersisted {
					offer_id: *unsafe { Box::from_raw(offer_id_nonref.take_inner()) },
					invoice_created_at: core::time::Duration::from_secs(invoice_created_at_nonref),
				}
			},
			AsyncPaymentsContext::OutboundPayment {ref payment_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				nativeAsyncPaymentsContext::OutboundPayment {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
				}
			},
			AsyncPaymentsContext::InboundPayment {ref path_absolute_expiry, } => {
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				nativeAsyncPaymentsContext::InboundPayment {
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry_nonref),
				}
			},
			AsyncPaymentsContext::ReleaseHeldHtlc {ref intercept_id, ref prev_outbound_scid_alias, ref htlc_id, } => {
				let mut intercept_id_nonref = Clone::clone(intercept_id);
				let mut prev_outbound_scid_alias_nonref = Clone::clone(prev_outbound_scid_alias);
				let mut htlc_id_nonref = Clone::clone(htlc_id);
				nativeAsyncPaymentsContext::ReleaseHeldHtlc {
					intercept_id: ::lightning::ln::channelmanager::InterceptId(intercept_id_nonref.data),
					prev_outbound_scid_alias: prev_outbound_scid_alias_nonref,
					htlc_id: htlc_id_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeAsyncPaymentsContext {
		match self {
			AsyncPaymentsContext::OfferPathsRequest {mut recipient_id, mut path_absolute_expiry, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.into_rust().drain(..) { local_recipient_id.push( { item }); };
				let mut local_path_absolute_expiry = { /*path_absolute_expiry*/ let path_absolute_expiry_opt = path_absolute_expiry; if path_absolute_expiry_opt.is_none() { None } else { Some({ { core::time::Duration::from_secs({ path_absolute_expiry_opt.take() }) }})} };
				nativeAsyncPaymentsContext::OfferPathsRequest {
					recipient_id: local_recipient_id,
					path_absolute_expiry: local_path_absolute_expiry,
				}
			},
			AsyncPaymentsContext::OfferPaths {mut invoice_slot, mut path_absolute_expiry, } => {
				nativeAsyncPaymentsContext::OfferPaths {
					invoice_slot: invoice_slot,
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry),
				}
			},
			AsyncPaymentsContext::ServeStaticInvoice {mut recipient_id, mut invoice_slot, mut path_absolute_expiry, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.into_rust().drain(..) { local_recipient_id.push( { item }); };
				nativeAsyncPaymentsContext::ServeStaticInvoice {
					recipient_id: local_recipient_id,
					invoice_slot: invoice_slot,
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry),
				}
			},
			AsyncPaymentsContext::StaticInvoicePersisted {mut offer_id, mut invoice_created_at, } => {
				nativeAsyncPaymentsContext::StaticInvoicePersisted {
					offer_id: *unsafe { Box::from_raw(offer_id.take_inner()) },
					invoice_created_at: core::time::Duration::from_secs(invoice_created_at),
				}
			},
			AsyncPaymentsContext::OutboundPayment {mut payment_id, } => {
				nativeAsyncPaymentsContext::OutboundPayment {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
				}
			},
			AsyncPaymentsContext::InboundPayment {mut path_absolute_expiry, } => {
				nativeAsyncPaymentsContext::InboundPayment {
					path_absolute_expiry: core::time::Duration::from_secs(path_absolute_expiry),
				}
			},
			AsyncPaymentsContext::ReleaseHeldHtlc {mut intercept_id, mut prev_outbound_scid_alias, mut htlc_id, } => {
				nativeAsyncPaymentsContext::ReleaseHeldHtlc {
					intercept_id: ::lightning::ln::channelmanager::InterceptId(intercept_id.data),
					prev_outbound_scid_alias: prev_outbound_scid_alias,
					htlc_id: htlc_id,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &AsyncPaymentsContextImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeAsyncPaymentsContext) };
		match native {
			nativeAsyncPaymentsContext::OfferPathsRequest {ref recipient_id, ref path_absolute_expiry, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				let mut local_path_absolute_expiry_nonref = if path_absolute_expiry_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { path_absolute_expiry_nonref.unwrap().as_secs() }) };
				AsyncPaymentsContext::OfferPathsRequest {
					recipient_id: local_recipient_id_nonref.into(),
					path_absolute_expiry: local_path_absolute_expiry_nonref,
				}
			},
			nativeAsyncPaymentsContext::OfferPaths {ref invoice_slot, ref path_absolute_expiry, } => {
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				AsyncPaymentsContext::OfferPaths {
					invoice_slot: invoice_slot_nonref,
					path_absolute_expiry: path_absolute_expiry_nonref.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::ServeStaticInvoice {ref recipient_id, ref invoice_slot, ref path_absolute_expiry, } => {
				let mut recipient_id_nonref = Clone::clone(recipient_id);
				let mut local_recipient_id_nonref = Vec::new(); for mut item in recipient_id_nonref.drain(..) { local_recipient_id_nonref.push( { item }); };
				let mut invoice_slot_nonref = Clone::clone(invoice_slot);
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				AsyncPaymentsContext::ServeStaticInvoice {
					recipient_id: local_recipient_id_nonref.into(),
					invoice_slot: invoice_slot_nonref,
					path_absolute_expiry: path_absolute_expiry_nonref.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::StaticInvoicePersisted {ref offer_id, ref invoice_created_at, } => {
				let mut offer_id_nonref = Clone::clone(offer_id);
				let mut invoice_created_at_nonref = Clone::clone(invoice_created_at);
				AsyncPaymentsContext::StaticInvoicePersisted {
					offer_id: crate::lightning::offers::offer::OfferId { inner: ObjOps::heap_alloc(offer_id_nonref), is_owned: true },
					invoice_created_at: invoice_created_at_nonref.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::OutboundPayment {ref payment_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				AsyncPaymentsContext::OutboundPayment {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
				}
			},
			nativeAsyncPaymentsContext::InboundPayment {ref path_absolute_expiry, } => {
				let mut path_absolute_expiry_nonref = Clone::clone(path_absolute_expiry);
				AsyncPaymentsContext::InboundPayment {
					path_absolute_expiry: path_absolute_expiry_nonref.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::ReleaseHeldHtlc {ref intercept_id, ref prev_outbound_scid_alias, ref htlc_id, } => {
				let mut intercept_id_nonref = Clone::clone(intercept_id);
				let mut prev_outbound_scid_alias_nonref = Clone::clone(prev_outbound_scid_alias);
				let mut htlc_id_nonref = Clone::clone(htlc_id);
				AsyncPaymentsContext::ReleaseHeldHtlc {
					intercept_id: crate::c_types::ThirtyTwoBytes { data: intercept_id_nonref.0 },
					prev_outbound_scid_alias: prev_outbound_scid_alias_nonref,
					htlc_id: htlc_id_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeAsyncPaymentsContext) -> Self {
		match native {
			nativeAsyncPaymentsContext::OfferPathsRequest {mut recipient_id, mut path_absolute_expiry, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.drain(..) { local_recipient_id.push( { item }); };
				let mut local_path_absolute_expiry = if path_absolute_expiry.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { path_absolute_expiry.unwrap().as_secs() }) };
				AsyncPaymentsContext::OfferPathsRequest {
					recipient_id: local_recipient_id.into(),
					path_absolute_expiry: local_path_absolute_expiry,
				}
			},
			nativeAsyncPaymentsContext::OfferPaths {mut invoice_slot, mut path_absolute_expiry, } => {
				AsyncPaymentsContext::OfferPaths {
					invoice_slot: invoice_slot,
					path_absolute_expiry: path_absolute_expiry.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::ServeStaticInvoice {mut recipient_id, mut invoice_slot, mut path_absolute_expiry, } => {
				let mut local_recipient_id = Vec::new(); for mut item in recipient_id.drain(..) { local_recipient_id.push( { item }); };
				AsyncPaymentsContext::ServeStaticInvoice {
					recipient_id: local_recipient_id.into(),
					invoice_slot: invoice_slot,
					path_absolute_expiry: path_absolute_expiry.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::StaticInvoicePersisted {mut offer_id, mut invoice_created_at, } => {
				AsyncPaymentsContext::StaticInvoicePersisted {
					offer_id: crate::lightning::offers::offer::OfferId { inner: ObjOps::heap_alloc(offer_id), is_owned: true },
					invoice_created_at: invoice_created_at.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::OutboundPayment {mut payment_id, } => {
				AsyncPaymentsContext::OutboundPayment {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
				}
			},
			nativeAsyncPaymentsContext::InboundPayment {mut path_absolute_expiry, } => {
				AsyncPaymentsContext::InboundPayment {
					path_absolute_expiry: path_absolute_expiry.as_secs(),
				}
			},
			nativeAsyncPaymentsContext::ReleaseHeldHtlc {mut intercept_id, mut prev_outbound_scid_alias, mut htlc_id, } => {
				AsyncPaymentsContext::ReleaseHeldHtlc {
					intercept_id: crate::c_types::ThirtyTwoBytes { data: intercept_id.0 },
					prev_outbound_scid_alias: prev_outbound_scid_alias,
					htlc_id: htlc_id,
				}
			},
		}
	}
}
/// Frees any resources used by the AsyncPaymentsContext
#[no_mangle]
pub extern "C" fn AsyncPaymentsContext_free(this_ptr: AsyncPaymentsContext) { }
/// Creates a copy of the AsyncPaymentsContext
#[no_mangle]
pub extern "C" fn AsyncPaymentsContext_clone(orig: &AsyncPaymentsContext) -> AsyncPaymentsContext {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AsyncPaymentsContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const AsyncPaymentsContext)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AsyncPaymentsContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut AsyncPaymentsContext) };
}
#[no_mangle]
/// Utility method to constructs a new OfferPathsRequest-variant AsyncPaymentsContext
pub extern "C" fn AsyncPaymentsContext_offer_paths_request(recipient_id: crate::c_types::derived::CVec_u8Z, path_absolute_expiry: crate::c_types::derived::COption_u64Z) -> AsyncPaymentsContext {
	AsyncPaymentsContext::OfferPathsRequest {
		recipient_id,
		path_absolute_expiry,
	}
}
#[no_mangle]
/// Utility method to constructs a new OfferPaths-variant AsyncPaymentsContext
pub extern "C" fn AsyncPaymentsContext_offer_paths(invoice_slot: u16, path_absolute_expiry: u64) -> AsyncPaymentsContext {
	AsyncPaymentsContext::OfferPaths {
		invoice_slot,
		path_absolute_expiry,
	}
}
#[no_mangle]
/// Utility method to constructs a new ServeStaticInvoice-variant AsyncPaymentsContext
pub extern "C" fn AsyncPaymentsContext_serve_static_invoice(recipient_id: crate::c_types::derived::CVec_u8Z, invoice_slot: u16, path_absolute_expiry: u64) -> AsyncPaymentsContext {
	AsyncPaymentsContext::ServeStaticInvoice {
		recipient_id,
		invoice_slot,
		path_absolute_expiry,
	}
}
#[no_mangle]
/// Utility method to constructs a new StaticInvoicePersisted-variant AsyncPaymentsContext
pub extern "C" fn AsyncPaymentsContext_static_invoice_persisted(offer_id: crate::lightning::offers::offer::OfferId, invoice_created_at: u64) -> AsyncPaymentsContext {
	AsyncPaymentsContext::StaticInvoicePersisted {
		offer_id,
		invoice_created_at,
	}
}
#[no_mangle]
/// Utility method to constructs a new OutboundPayment-variant AsyncPaymentsContext
pub extern "C" fn AsyncPaymentsContext_outbound_payment(payment_id: crate::c_types::ThirtyTwoBytes) -> AsyncPaymentsContext {
	AsyncPaymentsContext::OutboundPayment {
		payment_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new InboundPayment-variant AsyncPaymentsContext
pub extern "C" fn AsyncPaymentsContext_inbound_payment(path_absolute_expiry: u64) -> AsyncPaymentsContext {
	AsyncPaymentsContext::InboundPayment {
		path_absolute_expiry,
	}
}
#[no_mangle]
/// Utility method to constructs a new ReleaseHeldHtlc-variant AsyncPaymentsContext
pub extern "C" fn AsyncPaymentsContext_release_held_htlc(intercept_id: crate::c_types::ThirtyTwoBytes, prev_outbound_scid_alias: u64, htlc_id: u64) -> AsyncPaymentsContext {
	AsyncPaymentsContext::ReleaseHeldHtlc {
		intercept_id,
		prev_outbound_scid_alias,
		htlc_id,
	}
}
/// Get a string which allows debug introspection of a AsyncPaymentsContext object
pub extern "C" fn AsyncPaymentsContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::message::AsyncPaymentsContext }).into()}
#[no_mangle]
/// Serialize the MessageContext object into a byte array which can be read by MessageContext_read
pub extern "C" fn MessageContext_write(obj: &crate::lightning::blinded_path::message::MessageContext) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn MessageContext_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	MessageContext_write(unsafe { &*(obj as *const MessageContext) })
}
#[no_mangle]
/// Read a MessageContext from a byte array, created by MessageContext_write
pub extern "C" fn MessageContext_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_MessageContextDecodeErrorZ {
	let res: Result<lightning::blinded_path::message::MessageContext, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::message::MessageContext::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the OffersContext object into a byte array which can be read by OffersContext_read
pub extern "C" fn OffersContext_write(obj: &crate::lightning::blinded_path::message::OffersContext) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn OffersContext_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	OffersContext_write(unsafe { &*(obj as *const OffersContext) })
}
#[no_mangle]
/// Read a OffersContext from a byte array, created by OffersContext_write
pub extern "C" fn OffersContext_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OffersContextDecodeErrorZ {
	let res: Result<lightning::blinded_path::message::OffersContext, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::message::OffersContext::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the AsyncPaymentsContext object into a byte array which can be read by AsyncPaymentsContext_read
pub extern "C" fn AsyncPaymentsContext_write(obj: &crate::lightning::blinded_path::message::AsyncPaymentsContext) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn AsyncPaymentsContext_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	AsyncPaymentsContext_write(unsafe { &*(obj as *const AsyncPaymentsContext) })
}
#[no_mangle]
/// Read a AsyncPaymentsContext from a byte array, created by AsyncPaymentsContext_write
pub extern "C" fn AsyncPaymentsContext_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_AsyncPaymentsContextDecodeErrorZ {
	let res: Result<lightning::blinded_path::message::AsyncPaymentsContext, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::message::AsyncPaymentsContext::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::blinded_path::message::DNSResolverContext as nativeDNSResolverContextImport;
pub(crate) type nativeDNSResolverContext = nativeDNSResolverContextImport;

/// Contains a simple nonce for use in a blinded path's context.
///
/// Such a context is required when receiving a [`DNSSECProof`] message.
///
/// [`DNSSECProof`]: crate::onion_message::dns_resolution::DNSSECProof
#[must_use]
#[repr(C)]
pub struct DNSResolverContext {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDNSResolverContext,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for DNSResolverContext {
	type Target = nativeDNSResolverContext;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for DNSResolverContext { }
unsafe impl core::marker::Sync for DNSResolverContext { }
impl Drop for DNSResolverContext {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDNSResolverContext>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DNSResolverContext, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DNSResolverContext_free(this_obj: DNSResolverContext) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSResolverContext_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDNSResolverContext) };
}
#[allow(unused)]
impl DNSResolverContext {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDNSResolverContext {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDNSResolverContext {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDNSResolverContext {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// A nonce which uniquely describes a DNS resolution, useful for looking up metadata about the
/// request.
#[no_mangle]
pub extern "C" fn DNSResolverContext_get_nonce(this_ptr: &DNSResolverContext) -> *const [u8; 16] {
	let mut inner_val = &mut DNSResolverContext::get_native_mut_ref(this_ptr).nonce;
	inner_val
}
/// A nonce which uniquely describes a DNS resolution, useful for looking up metadata about the
/// request.
#[no_mangle]
pub extern "C" fn DNSResolverContext_set_nonce(this_ptr: &mut DNSResolverContext, mut val: crate::c_types::SixteenBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.nonce = val.data;
}
/// Constructs a new DNSResolverContext given each field
#[must_use]
#[no_mangle]
pub extern "C" fn DNSResolverContext_new(mut nonce_arg: crate::c_types::SixteenBytes) -> DNSResolverContext {
	DNSResolverContext { inner: ObjOps::heap_alloc(nativeDNSResolverContext {
		nonce: nonce_arg.data,
	}), is_owned: true }
}
impl Clone for DNSResolverContext {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDNSResolverContext>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSResolverContext_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeDNSResolverContext) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DNSResolverContext
pub extern "C" fn DNSResolverContext_clone(orig: &DNSResolverContext) -> DNSResolverContext {
	Clone::clone(orig)
}
/// Get a string which allows debug introspection of a DNSResolverContext object
pub extern "C" fn DNSResolverContext_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::message::DNSResolverContext }).into()}
/// Generates a non-cryptographic 64-bit hash of the DNSResolverContext.
#[no_mangle]
pub extern "C" fn DNSResolverContext_hash(o: &DNSResolverContext) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two DNSResolverContexts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn DNSResolverContext_eq(a: &DNSResolverContext, b: &DNSResolverContext) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the DNSResolverContext object into a byte array which can be read by DNSResolverContext_read
pub extern "C" fn DNSResolverContext_write(obj: &crate::lightning::blinded_path::message::DNSResolverContext) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn DNSResolverContext_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::blinded_path::message::nativeDNSResolverContext) })
}
#[no_mangle]
/// Read a DNSResolverContext from a byte array, created by DNSResolverContext_write
pub extern "C" fn DNSResolverContext_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_DNSResolverContextDecodeErrorZ {
	let res: Result<lightning::blinded_path::message::DNSResolverContext, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::message::DNSResolverContext { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// The maximum number of dummy hops that can be added to a blinded path.
/// This is to prevent paths from becoming too long and potentially causing
/// issues with message processing or routing.

#[no_mangle]
pub static MAX_DUMMY_HOPS_COUNT: usize = lightning::blinded_path::message::MAX_DUMMY_HOPS_COUNT;
