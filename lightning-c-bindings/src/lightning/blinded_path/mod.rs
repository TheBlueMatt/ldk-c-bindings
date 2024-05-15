// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Creating blinded paths and related utilities live here.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod payment;
mod message {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod utils {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

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
use lightning::blinded_path::NextMessageHop as NextMessageHopImport;
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
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::NextMessageHop }).into()}
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

use lightning::blinded_path::BlindedPath as nativeBlindedPathImport;
pub(crate) type nativeBlindedPath = nativeBlindedPathImport;

/// Onion messages and payments can be sent and received to blinded paths, which serve to hide the
/// identity of the recipient.
#[must_use]
#[repr(C)]
pub struct BlindedPath {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedPath,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedPath {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedPath>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedPath, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedPath_free(this_obj: BlindedPath) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPath_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedPath) };
}
#[allow(unused)]
impl BlindedPath {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedPath {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedPath {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedPath {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// To send to a blinded path, the sender first finds a route to the unblinded
/// `introduction_node`, which can unblind its [`encrypted_payload`] to find out the onion
/// message or payment's next hop and forward it along.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_get_introduction_node(this_ptr: &BlindedPath) -> crate::lightning::blinded_path::IntroductionNode {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().introduction_node;
	crate::lightning::blinded_path::IntroductionNode::from_native(inner_val)
}
/// To send to a blinded path, the sender first finds a route to the unblinded
/// `introduction_node`, which can unblind its [`encrypted_payload`] to find out the onion
/// message or payment's next hop and forward it along.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_set_introduction_node(this_ptr: &mut BlindedPath, mut val: crate::lightning::blinded_path::IntroductionNode) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.introduction_node = val.into_native();
}
/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
/// message or payment.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_get_blinding_point(this_ptr: &BlindedPath) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinding_point;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
/// message or payment.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_set_blinding_point(this_ptr: &mut BlindedPath, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinding_point = val.into_rust();
}
/// The hops composing the blinded path.
#[no_mangle]
pub extern "C" fn BlindedPath_get_blinded_hops(this_ptr: &BlindedPath) -> crate::c_types::derived::CVec_BlindedHopZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinded_hops;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::blinded_path::BlindedHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::blinded_path::BlindedHop<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The hops composing the blinded path.
#[no_mangle]
pub extern "C" fn BlindedPath_set_blinded_hops(this_ptr: &mut BlindedPath, mut val: crate::c_types::derived::CVec_BlindedHopZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinded_hops = local_val;
}
/// Constructs a new BlindedPath given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_new(mut introduction_node_arg: crate::lightning::blinded_path::IntroductionNode, mut blinding_point_arg: crate::c_types::PublicKey, mut blinded_hops_arg: crate::c_types::derived::CVec_BlindedHopZ) -> BlindedPath {
	let mut local_blinded_hops_arg = Vec::new(); for mut item in blinded_hops_arg.into_rust().drain(..) { local_blinded_hops_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	BlindedPath { inner: ObjOps::heap_alloc(nativeBlindedPath {
		introduction_node: introduction_node_arg.into_native(),
		blinding_point: blinding_point_arg.into_rust(),
		blinded_hops: local_blinded_hops_arg,
	}), is_owned: true }
}
impl Clone for BlindedPath {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedPath>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedPath)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedPath
pub extern "C" fn BlindedPath_clone(orig: &BlindedPath) -> BlindedPath {
	orig.clone()
}
/// Get a string which allows debug introspection of a BlindedPath object
pub extern "C" fn BlindedPath_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::BlindedPath }).into()}
/// Generates a non-cryptographic 64-bit hash of the BlindedPath.
#[no_mangle]
pub extern "C" fn BlindedPath_hash(o: &BlindedPath) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedPaths contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedPath_eq(a: &BlindedPath, b: &BlindedPath) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// The unblinded node in a [`BlindedPath`].
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum IntroductionNode {
	/// The node id of the introduction node.
	NodeId(
		crate::c_types::PublicKey),
	/// The short channel id of the channel leading to the introduction node. The [`Direction`]
	/// identifies which side of the channel is the introduction node.
	DirectedShortChannelId(
		crate::lightning::blinded_path::Direction,
		u64),
}
use lightning::blinded_path::IntroductionNode as IntroductionNodeImport;
pub(crate) type nativeIntroductionNode = IntroductionNodeImport;

impl IntroductionNode {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeIntroductionNode {
		match self {
			IntroductionNode::NodeId (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeIntroductionNode::NodeId (
					a_nonref.into_rust(),
				)
			},
			IntroductionNode::DirectedShortChannelId (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativeIntroductionNode::DirectedShortChannelId (
					a_nonref.into_native(),
					b_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeIntroductionNode {
		match self {
			IntroductionNode::NodeId (mut a, ) => {
				nativeIntroductionNode::NodeId (
					a.into_rust(),
				)
			},
			IntroductionNode::DirectedShortChannelId (mut a, mut b, ) => {
				nativeIntroductionNode::DirectedShortChannelId (
					a.into_native(),
					b,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &IntroductionNodeImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeIntroductionNode) };
		match native {
			nativeIntroductionNode::NodeId (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				IntroductionNode::NodeId (
					crate::c_types::PublicKey::from_rust(&a_nonref),
				)
			},
			nativeIntroductionNode::DirectedShortChannelId (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				IntroductionNode::DirectedShortChannelId (
					crate::lightning::blinded_path::Direction::native_into(a_nonref),
					b_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeIntroductionNode) -> Self {
		match native {
			nativeIntroductionNode::NodeId (mut a, ) => {
				IntroductionNode::NodeId (
					crate::c_types::PublicKey::from_rust(&a),
				)
			},
			nativeIntroductionNode::DirectedShortChannelId (mut a, mut b, ) => {
				IntroductionNode::DirectedShortChannelId (
					crate::lightning::blinded_path::Direction::native_into(a),
					b,
				)
			},
		}
	}
}
/// Frees any resources used by the IntroductionNode
#[no_mangle]
pub extern "C" fn IntroductionNode_free(this_ptr: IntroductionNode) { }
/// Creates a copy of the IntroductionNode
#[no_mangle]
pub extern "C" fn IntroductionNode_clone(orig: &IntroductionNode) -> IntroductionNode {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn IntroductionNode_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const IntroductionNode)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn IntroductionNode_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut IntroductionNode) };
}
#[no_mangle]
/// Utility method to constructs a new NodeId-variant IntroductionNode
pub extern "C" fn IntroductionNode_node_id(a: crate::c_types::PublicKey) -> IntroductionNode {
	IntroductionNode::NodeId(a, )
}
#[no_mangle]
/// Utility method to constructs a new DirectedShortChannelId-variant IntroductionNode
pub extern "C" fn IntroductionNode_directed_short_channel_id(a: crate::lightning::blinded_path::Direction,b: u64) -> IntroductionNode {
	IntroductionNode::DirectedShortChannelId(a, b, )
}
/// Get a string which allows debug introspection of a IntroductionNode object
pub extern "C" fn IntroductionNode_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::IntroductionNode }).into()}
/// Generates a non-cryptographic 64-bit hash of the IntroductionNode.
#[no_mangle]
pub extern "C" fn IntroductionNode_hash(o: &IntroductionNode) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two IntroductionNodes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn IntroductionNode_eq(a: &IntroductionNode, b: &IntroductionNode) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// The side of a channel that is the [`IntroductionNode`] in a [`BlindedPath`]. [BOLT 7] defines
/// which nodes is which in the [`ChannelAnnouncement`] message.
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_announcement-message
/// [`ChannelAnnouncement`]: crate::ln::msgs::ChannelAnnouncement
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Direction {
	/// The lesser node id when compared lexicographically in ascending order.
	NodeOne,
	/// The greater node id when compared lexicographically in ascending order.
	NodeTwo,
}
use lightning::blinded_path::Direction as DirectionImport;
pub(crate) type nativeDirection = DirectionImport;

impl Direction {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeDirection {
		match self {
			Direction::NodeOne => nativeDirection::NodeOne,
			Direction::NodeTwo => nativeDirection::NodeTwo,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeDirection {
		match self {
			Direction::NodeOne => nativeDirection::NodeOne,
			Direction::NodeTwo => nativeDirection::NodeTwo,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &DirectionImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeDirection) };
		match native {
			nativeDirection::NodeOne => Direction::NodeOne,
			nativeDirection::NodeTwo => Direction::NodeTwo,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeDirection) -> Self {
		match native {
			nativeDirection::NodeOne => Direction::NodeOne,
			nativeDirection::NodeTwo => Direction::NodeTwo,
		}
	}
}
/// Creates a copy of the Direction
#[no_mangle]
pub extern "C" fn Direction_clone(orig: &Direction) -> Direction {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Direction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Direction)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Direction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Direction) };
}
#[no_mangle]
/// Utility method to constructs a new NodeOne-variant Direction
pub extern "C" fn Direction_node_one() -> Direction {
	Direction::NodeOne}
#[no_mangle]
/// Utility method to constructs a new NodeTwo-variant Direction
pub extern "C" fn Direction_node_two() -> Direction {
	Direction::NodeTwo}
/// Get a string which allows debug introspection of a Direction object
pub extern "C" fn Direction_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::Direction }).into()}
/// Generates a non-cryptographic 64-bit hash of the Direction.
#[no_mangle]
pub extern "C" fn Direction_hash(o: &Direction) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Directions contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Direction_eq(a: &Direction, b: &Direction) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An interface for looking up the node id of a channel counterparty for the purpose of forwarding
/// an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[repr(C)]
pub struct NodeIdLookUp {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the node id of the forwarding node's channel counterparty with `short_channel_id`.
	///
	/// Here, the forwarding node is referring to the node of the [`OnionMessenger`] parameterized
	/// by the [`NodeIdLookUp`] and the counterparty to one of that node's peers.
	///
	/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
	///
	/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub next_node_id: extern "C" fn (this_arg: *const c_void, short_channel_id: u64) -> crate::c_types::PublicKey,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for NodeIdLookUp {}
unsafe impl Sync for NodeIdLookUp {}
#[allow(unused)]
pub(crate) fn NodeIdLookUp_clone_fields(orig: &NodeIdLookUp) -> NodeIdLookUp {
	NodeIdLookUp {
		this_arg: orig.this_arg,
		next_node_id: Clone::clone(&orig.next_node_id),
		free: Clone::clone(&orig.free),
	}
}

use lightning::blinded_path::NodeIdLookUp as rustNodeIdLookUp;
impl rustNodeIdLookUp for NodeIdLookUp {
	fn next_node_id(&self, mut short_channel_id: u64) -> Option<bitcoin::secp256k1::PublicKey> {
		let mut ret = (self.next_node_id)(self.this_arg, short_channel_id);
		let mut local_ret = if ret.is_null() { None } else { Some( { ret.into_rust() }) };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for NodeIdLookUp {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for NodeIdLookUp {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn NodeIdLookUp_free(this_ptr: NodeIdLookUp) { }
impl Drop for NodeIdLookUp {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::blinded_path::EmptyNodeIdLookUp as nativeEmptyNodeIdLookUpImport;
pub(crate) type nativeEmptyNodeIdLookUp = nativeEmptyNodeIdLookUpImport;

/// A [`NodeIdLookUp`] that always returns `None`.
#[must_use]
#[repr(C)]
pub struct EmptyNodeIdLookUp {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeEmptyNodeIdLookUp,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for EmptyNodeIdLookUp {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeEmptyNodeIdLookUp>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the EmptyNodeIdLookUp, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn EmptyNodeIdLookUp_free(this_obj: EmptyNodeIdLookUp) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn EmptyNodeIdLookUp_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeEmptyNodeIdLookUp) };
}
#[allow(unused)]
impl EmptyNodeIdLookUp {
	pub(crate) fn get_native_ref(&self) -> &'static nativeEmptyNodeIdLookUp {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeEmptyNodeIdLookUp {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeEmptyNodeIdLookUp {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Constructs a new EmptyNodeIdLookUp given each field
#[must_use]
#[no_mangle]
pub extern "C" fn EmptyNodeIdLookUp_new() -> EmptyNodeIdLookUp {
	EmptyNodeIdLookUp { inner: ObjOps::heap_alloc(nativeEmptyNodeIdLookUp {
	}), is_owned: true }
}
impl From<nativeEmptyNodeIdLookUp> for crate::lightning::blinded_path::NodeIdLookUp {
	fn from(obj: nativeEmptyNodeIdLookUp) -> Self {
		let rust_obj = crate::lightning::blinded_path::EmptyNodeIdLookUp { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = EmptyNodeIdLookUp_as_NodeIdLookUp(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(EmptyNodeIdLookUp_free_void);
		ret
	}
}
/// Constructs a new NodeIdLookUp which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned NodeIdLookUp must be freed before this_arg is
#[no_mangle]
pub extern "C" fn EmptyNodeIdLookUp_as_NodeIdLookUp(this_arg: &EmptyNodeIdLookUp) -> crate::lightning::blinded_path::NodeIdLookUp {
	crate::lightning::blinded_path::NodeIdLookUp {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		next_node_id: EmptyNodeIdLookUp_NodeIdLookUp_next_node_id,
	}
}

#[must_use]
extern "C" fn EmptyNodeIdLookUp_NodeIdLookUp_next_node_id(this_arg: *const c_void, mut short_channel_id: u64) -> crate::c_types::PublicKey {
	let mut ret = <nativeEmptyNodeIdLookUp as lightning::blinded_path::NodeIdLookUp>::next_node_id(unsafe { &mut *(this_arg as *mut nativeEmptyNodeIdLookUp) }, short_channel_id);
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}


use lightning::blinded_path::BlindedHop as nativeBlindedHopImport;
pub(crate) type nativeBlindedHop = nativeBlindedHopImport;

/// An encrypted payload and node id corresponding to a hop in a payment or onion message path, to
/// be encoded in the sender's onion packet. These hops cannot be identified by outside observers
/// and thus can be used to hide the identity of the recipient.
#[must_use]
#[repr(C)]
pub struct BlindedHop {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedHop,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedHop {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedHop>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedHop, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedHop_free(this_obj: BlindedHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedHop_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedHop) };
}
#[allow(unused)]
impl BlindedHop {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedHop {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedHop {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedHop {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The blinded node id of this hop in a [`BlindedPath`].
#[no_mangle]
pub extern "C" fn BlindedHop_get_blinded_node_id(this_ptr: &BlindedHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinded_node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The blinded node id of this hop in a [`BlindedPath`].
#[no_mangle]
pub extern "C" fn BlindedHop_set_blinded_node_id(this_ptr: &mut BlindedHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinded_node_id = val.into_rust();
}
/// The encrypted payload intended for this hop in a [`BlindedPath`].
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn BlindedHop_get_encrypted_payload(this_ptr: &BlindedHop) -> crate::c_types::derived::CVec_u8Z {
	let mut inner_val = this_ptr.get_native_mut_ref().encrypted_payload.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// The encrypted payload intended for this hop in a [`BlindedPath`].
#[no_mangle]
pub extern "C" fn BlindedHop_set_encrypted_payload(this_ptr: &mut BlindedHop, mut val: crate::c_types::derived::CVec_u8Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.encrypted_payload = local_val;
}
/// Constructs a new BlindedHop given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHop_new(mut blinded_node_id_arg: crate::c_types::PublicKey, mut encrypted_payload_arg: crate::c_types::derived::CVec_u8Z) -> BlindedHop {
	let mut local_encrypted_payload_arg = Vec::new(); for mut item in encrypted_payload_arg.into_rust().drain(..) { local_encrypted_payload_arg.push( { item }); };
	BlindedHop { inner: ObjOps::heap_alloc(nativeBlindedHop {
		blinded_node_id: blinded_node_id_arg.into_rust(),
		encrypted_payload: local_encrypted_payload_arg,
	}), is_owned: true }
}
impl Clone for BlindedHop {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedHop>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedHop)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedHop
pub extern "C" fn BlindedHop_clone(orig: &BlindedHop) -> BlindedHop {
	orig.clone()
}
/// Get a string which allows debug introspection of a BlindedHop object
pub extern "C" fn BlindedHop_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::BlindedHop }).into()}
/// Generates a non-cryptographic 64-bit hash of the BlindedHop.
#[no_mangle]
pub extern "C" fn BlindedHop_hash(o: &BlindedHop) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedHop_eq(a: &BlindedHop, b: &BlindedHop) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Create a one-hop blinded path for a message.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_one_hop_for_message(mut recipient_node_id: crate::c_types::PublicKey, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_BlindedPathNoneZ {
	let mut ret = lightning::blinded_path::BlindedPath::one_hop_for_message(recipient_node_id.into_rust(), entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blinded path for an onion message, to be forwarded along `node_pks`. The last node
/// pubkey in `node_pks` will be the destination node.
///
/// Errors if no hops are provided or if `node_pk`(s) are invalid.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_new_for_message(mut node_pks: crate::c_types::derived::CVec_PublicKeyZ, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_BlindedPathNoneZ {
	let mut local_node_pks = Vec::new(); for mut item in node_pks.into_rust().drain(..) { local_node_pks.push( { item.into_rust() }); };
	let mut ret = lightning::blinded_path::BlindedPath::new_for_message(&local_node_pks[..], entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a one-hop blinded path for a payment.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_one_hop_for_payment(mut payee_node_id: crate::c_types::PublicKey, mut payee_tlvs: crate::lightning::blinded_path::payment::ReceiveTlvs, mut min_final_cltv_expiry_delta: u16, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_C2Tuple_BlindedPayInfoBlindedPathZNoneZ {
	let mut ret = lightning::blinded_path::BlindedPath::one_hop_for_payment(payee_node_id.into_rust(), *unsafe { Box::from_raw(payee_tlvs.take_inner()) }, min_final_cltv_expiry_delta, entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::lightning::offers::invoice::BlindedPayInfo { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blinded path for a payment, to be forwarded along `intermediate_nodes`.
///
/// Errors if:
/// * a provided node id is invalid
/// * [`BlindedPayInfo`] calculation results in an integer overflow
/// * any unknown features are required in the provided [`ForwardTlvs`]
///
/// [`ForwardTlvs`]: crate::blinded_path::payment::ForwardTlvs
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_new_for_payment(mut intermediate_nodes: crate::c_types::derived::CVec_ForwardNodeZ, mut payee_node_id: crate::c_types::PublicKey, mut payee_tlvs: crate::lightning::blinded_path::payment::ReceiveTlvs, mut htlc_maximum_msat: u64, mut min_final_cltv_expiry_delta: u16, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_C2Tuple_BlindedPayInfoBlindedPathZNoneZ {
	let mut local_intermediate_nodes = Vec::new(); for mut item in intermediate_nodes.into_rust().drain(..) { local_intermediate_nodes.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::blinded_path::BlindedPath::new_for_payment(local_intermediate_nodes, payee_node_id.into_rust(), *unsafe { Box::from_raw(payee_tlvs.take_inner()) }, htlc_maximum_msat, min_final_cltv_expiry_delta, entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::lightning::offers::invoice::BlindedPayInfo { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Returns the introduction [`NodeId`] of the blinded path, if it is publicly reachable (i.e.,
/// it is found in the network graph).
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_public_introduction_node_id(this_arg: &crate::lightning::blinded_path::BlindedPath, network_graph: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph) -> crate::lightning::routing::gossip::NodeId {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.public_introduction_node_id(network_graph.get_native_ref());
	let mut local_ret = crate::lightning::routing::gossip::NodeId { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::routing::gossip::NodeId<>) as *mut _ }, is_owned: false };
	local_ret
}

#[no_mangle]
/// Serialize the BlindedPath object into a byte array which can be read by BlindedPath_read
pub extern "C" fn BlindedPath_write(obj: &crate::lightning::blinded_path::BlindedPath) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedPath_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBlindedPath) })
}
#[no_mangle]
/// Read a BlindedPath from a byte array, created by BlindedPath_write
pub extern "C" fn BlindedPath_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedPathDecodeErrorZ {
	let res: Result<lightning::blinded_path::BlindedPath, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the BlindedHop object into a byte array which can be read by BlindedHop_read
pub extern "C" fn BlindedHop_write(obj: &crate::lightning::blinded_path::BlindedHop) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedHop_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBlindedHop) })
}
#[no_mangle]
/// Read a BlindedHop from a byte array, created by BlindedHop_write
pub extern "C" fn BlindedHop_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedHopDecodeErrorZ {
	let res: Result<lightning::blinded_path::BlindedHop, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::BlindedHop { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
