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
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedMessagePath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedMessagePath)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedMessagePath
pub extern "C" fn BlindedMessagePath_clone(orig: &BlindedMessagePath) -> BlindedMessagePath {
	orig.clone()
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
pub extern "C" fn BlindedMessagePath_one_hop(mut recipient_node_id: crate::c_types::PublicKey, mut context: crate::lightning::blinded_path::message::MessageContext, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_BlindedMessagePathNoneZ {
	let mut ret = lightning::blinded_path::message::BlindedMessagePath::one_hop(recipient_node_id.into_rust(), context.into_native(), entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a path for an onion message, to be forwarded along `node_pks`. The last node
/// pubkey in `node_pks` will be the destination node.
///
/// Errors if no hops are provided or if `node_pk`(s) are invalid.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedMessagePath_new(mut intermediate_nodes: crate::c_types::derived::CVec_MessageForwardNodeZ, mut recipient_node_id: crate::c_types::PublicKey, mut context: crate::lightning::blinded_path::message::MessageContext, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_BlindedMessagePathNoneZ {
	let mut local_intermediate_nodes = Vec::new(); for mut item in intermediate_nodes.into_rust().drain(..) { local_intermediate_nodes.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::blinded_path::message::BlindedMessagePath::new(&local_intermediate_nodes[..], recipient_node_id.into_rust(), context.into_native(), entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
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
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_id;
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
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
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
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageForwardNode_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeMessageForwardNode)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the MessageForwardNode
pub extern "C" fn MessageForwardNode_clone(orig: &MessageForwardNode) -> MessageForwardNode {
	orig.clone()
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
		/// Authentication code for the [`PaymentId`], which should be checked when the context is
		/// used with an [`InvoiceError`].
		///
		/// [`InvoiceError`]: crate::offers::invoice_error::InvoiceError
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		hmac: crate::c_types::ThirtyTwoBytes,
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
			OffersContext::OutboundPayment {ref payment_id, ref nonce, ref hmac, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut nonce_nonref = Clone::clone(nonce);
				let mut hmac_nonref = Clone::clone(hmac);
				let mut local_hmac_nonref = if hmac_nonref.data == [0; 32] { None } else { Some( { hmac_nonref.data }) };
				nativeOffersContext::OutboundPayment {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					nonce: *unsafe { Box::from_raw(nonce_nonref.take_inner()) },
					hmac: local_hmac_nonref,
				}
			},
			OffersContext::InboundPayment {ref payment_hash, } => {
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				nativeOffersContext::InboundPayment {
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
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
			OffersContext::OutboundPayment {mut payment_id, mut nonce, mut hmac, } => {
				let mut local_hmac = if hmac.data == [0; 32] { None } else { Some( { hmac.data }) };
				nativeOffersContext::OutboundPayment {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					nonce: *unsafe { Box::from_raw(nonce.take_inner()) },
					hmac: local_hmac,
				}
			},
			OffersContext::InboundPayment {mut payment_hash, } => {
				nativeOffersContext::InboundPayment {
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
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
			nativeOffersContext::OutboundPayment {ref payment_id, ref nonce, ref hmac, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut nonce_nonref = Clone::clone(nonce);
				let mut hmac_nonref = Clone::clone(hmac);
				let mut local_hmac_nonref = if hmac_nonref.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (hmac_nonref.unwrap()) } } };
				OffersContext::OutboundPayment {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					nonce: crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(nonce_nonref), is_owned: true },
					hmac: local_hmac_nonref,
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
			nativeOffersContext::OutboundPayment {mut payment_id, mut nonce, mut hmac, } => {
				let mut local_hmac = if hmac.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (hmac.unwrap()) } } };
				OffersContext::OutboundPayment {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					nonce: crate::lightning::offers::nonce::Nonce { inner: ObjOps::heap_alloc(nonce), is_owned: true },
					hmac: local_hmac,
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
/// Utility method to constructs a new OutboundPayment-variant OffersContext
pub extern "C" fn OffersContext_outbound_payment(payment_id: crate::c_types::ThirtyTwoBytes, nonce: crate::lightning::offers::nonce::Nonce, hmac: crate::c_types::ThirtyTwoBytes) -> OffersContext {
	OffersContext::OutboundPayment {
		payment_id,
		nonce,
		hmac,
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
