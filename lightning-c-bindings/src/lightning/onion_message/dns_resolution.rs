// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This module defines message handling for DNSSEC proof fetching using [bLIP 32].
//!
//! It contains [`DNSResolverMessage`]s as well as a [`DNSResolverMessageHandler`] trait to handle
//! such messages using an [`OnionMessenger`].
//!
//! With the `dnssec` feature enabled, it also contains `OMNameResolver`, which does all the work
//! required to resolve BIP 353 [`HumanReadableName`]s using [bLIP 32] - sending onion messages to
//! a DNS resolver, validating the proofs, and ultimately surfacing validated data back to the
//! caller.
//!
//! [bLIP 32]: https://github.com/lightning/blips/blob/master/blip-0032.md
//! [`OnionMessenger`]: super::messenger::OnionMessenger

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// A handler for an [`OnionMessage`] containing a DNS(SEC) query or a DNSSEC proof
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[repr(C)]
pub struct DNSResolverMessageHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Handle a [`DNSSECQuery`] message.
	///
	/// If we provide DNS resolution services to third parties, we should respond with a
	/// [`DNSSECProof`] message.
	///
	/// Note that responder (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub handle_dnssec_query: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::dns_resolution::DNSSECQuery, responder: crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::COption_C2Tuple_DNSResolverMessageResponseInstructionZZ,
	/// Handle a [`DNSSECProof`] message (in response to a [`DNSSECQuery`] we presumably sent).
	///
	/// With this, we should be able to validate the DNS record we requested.
	pub handle_dnssec_proof: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::dns_resolution::DNSSECProof, context: crate::lightning::blinded_path::message::DNSResolverContext),
	/// Gets the node feature flags which this handler itself supports. Useful for setting the
	/// `dns_resolver` flag if this handler supports returning [`DNSSECProof`] messages in response
	/// to [`DNSSECQuery`] messages.
	pub provided_node_features: extern "C" fn (this_arg: *const c_void) -> crate::lightning_types::features::NodeFeatures,
	/// Release any [`DNSResolverMessage`]s that need to be sent.
	pub release_pending_messages: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C2Tuple_DNSResolverMessageMessageSendInstructionsZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for DNSResolverMessageHandler {}
unsafe impl Sync for DNSResolverMessageHandler {}
#[allow(unused)]
pub(crate) fn DNSResolverMessageHandler_clone_fields(orig: &DNSResolverMessageHandler) -> DNSResolverMessageHandler {
	DNSResolverMessageHandler {
		this_arg: orig.this_arg,
		handle_dnssec_query: Clone::clone(&orig.handle_dnssec_query),
		handle_dnssec_proof: Clone::clone(&orig.handle_dnssec_proof),
		provided_node_features: Clone::clone(&orig.provided_node_features),
		release_pending_messages: Clone::clone(&orig.release_pending_messages),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::dns_resolution::DNSResolverMessageHandler as rustDNSResolverMessageHandler;
impl rustDNSResolverMessageHandler for DNSResolverMessageHandler {
	fn handle_dnssec_query(&self, mut message: lightning::onion_message::dns_resolution::DNSSECQuery, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::dns_resolution::DNSResolverMessage, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.handle_dnssec_query)(self.this_arg, crate::lightning::onion_message::dns_resolution::DNSSECQuery { inner: ObjOps::heap_alloc(message), is_owned: true }, local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (orig_ret_0_0.into_native(), *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_dnssec_proof(&self, mut message: lightning::onion_message::dns_resolution::DNSSECProof, mut context: lightning::blinded_path::message::DNSResolverContext) {
		(self.handle_dnssec_proof)(self.this_arg, crate::lightning::onion_message::dns_resolution::DNSSECProof { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::DNSResolverContext { inner: ObjOps::heap_alloc(context), is_owned: true })
	}
	fn provided_node_features(&self) -> lightning_types::features::NodeFeatures {
		let mut ret = (self.provided_node_features)(self.this_arg);
		*unsafe { Box::from_raw(ret.take_inner()) }
	}
	fn release_pending_messages(&self) -> Vec<(lightning::onion_message::dns_resolution::DNSResolverMessage, lightning::onion_message::messenger::MessageSendInstructions)> {
		let mut ret = (self.release_pending_messages)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_ret_0 = (orig_ret_0_0.into_native(), orig_ret_0_1.into_native()); local_ret_0 }); };
		local_ret
	}
}

pub struct DNSResolverMessageHandlerRef(DNSResolverMessageHandler);
impl rustDNSResolverMessageHandler for DNSResolverMessageHandlerRef {
	fn handle_dnssec_query(&self, mut message: lightning::onion_message::dns_resolution::DNSSECQuery, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(lightning::onion_message::dns_resolution::DNSResolverMessage, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.0.handle_dnssec_query)(self.0.this_arg, crate::lightning::onion_message::dns_resolution::DNSSECQuery { inner: ObjOps::heap_alloc(message), is_owned: true }, local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (orig_ret_0_0.into_native(), *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn handle_dnssec_proof(&self, mut message: lightning::onion_message::dns_resolution::DNSSECProof, mut context: lightning::blinded_path::message::DNSResolverContext) {
		(self.0.handle_dnssec_proof)(self.0.this_arg, crate::lightning::onion_message::dns_resolution::DNSSECProof { inner: ObjOps::heap_alloc(message), is_owned: true }, crate::lightning::blinded_path::message::DNSResolverContext { inner: ObjOps::heap_alloc(context), is_owned: true })
	}
	fn provided_node_features(&self) -> lightning_types::features::NodeFeatures {
		let mut ret = (self.0.provided_node_features)(self.0.this_arg);
		*unsafe { Box::from_raw(ret.take_inner()) }
	}
	fn release_pending_messages(&self) -> Vec<(lightning::onion_message::dns_resolution::DNSResolverMessage, lightning::onion_message::messenger::MessageSendInstructions)> {
		let mut ret = (self.0.release_pending_messages)(self.0.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_ret_0 = (orig_ret_0_0.into_native(), orig_ret_0_1.into_native()); local_ret_0 }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for DNSResolverMessageHandler {
	type Target = DNSResolverMessageHandlerRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const DNSResolverMessageHandlerRef) }
	}
}
impl core::ops::DerefMut for DNSResolverMessageHandler {
	fn deref_mut(&mut self) -> &mut DNSResolverMessageHandlerRef {
		unsafe { &mut *(self as *mut _ as *mut DNSResolverMessageHandlerRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn DNSResolverMessageHandler_free(this_ptr: DNSResolverMessageHandler) { }
impl Drop for DNSResolverMessageHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// An enum containing the possible onion messages which are used uses to request and receive
/// DNSSEC proofs.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum DNSResolverMessage {
	/// A query requesting a DNSSEC proof
	DNSSECQuery(
		crate::lightning::onion_message::dns_resolution::DNSSECQuery),
	/// A response containing a DNSSEC proof
	DNSSECProof(
		crate::lightning::onion_message::dns_resolution::DNSSECProof),
}
use lightning::onion_message::dns_resolution::DNSResolverMessage as DNSResolverMessageImport;
pub(crate) type nativeDNSResolverMessage = DNSResolverMessageImport;

impl DNSResolverMessage {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeDNSResolverMessage {
		match self {
			DNSResolverMessage::DNSSECQuery (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeDNSResolverMessage::DNSSECQuery (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			DNSResolverMessage::DNSSECProof (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeDNSResolverMessage::DNSSECProof (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeDNSResolverMessage {
		match self {
			DNSResolverMessage::DNSSECQuery (mut a, ) => {
				nativeDNSResolverMessage::DNSSECQuery (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			DNSResolverMessage::DNSSECProof (mut a, ) => {
				nativeDNSResolverMessage::DNSSECProof (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &DNSResolverMessageImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeDNSResolverMessage) };
		match native {
			nativeDNSResolverMessage::DNSSECQuery (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				DNSResolverMessage::DNSSECQuery (
					crate::lightning::onion_message::dns_resolution::DNSSECQuery { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeDNSResolverMessage::DNSSECProof (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				DNSResolverMessage::DNSSECProof (
					crate::lightning::onion_message::dns_resolution::DNSSECProof { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeDNSResolverMessage) -> Self {
		match native {
			nativeDNSResolverMessage::DNSSECQuery (mut a, ) => {
				DNSResolverMessage::DNSSECQuery (
					crate::lightning::onion_message::dns_resolution::DNSSECQuery { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeDNSResolverMessage::DNSSECProof (mut a, ) => {
				DNSResolverMessage::DNSSECProof (
					crate::lightning::onion_message::dns_resolution::DNSSECProof { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the DNSResolverMessage
#[no_mangle]
pub extern "C" fn DNSResolverMessage_free(this_ptr: DNSResolverMessage) { }
/// Creates a copy of the DNSResolverMessage
#[no_mangle]
pub extern "C" fn DNSResolverMessage_clone(orig: &DNSResolverMessage) -> DNSResolverMessage {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSResolverMessage_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const DNSResolverMessage)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSResolverMessage_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut DNSResolverMessage) };
}
#[no_mangle]
/// Utility method to constructs a new DNSSECQuery-variant DNSResolverMessage
pub extern "C" fn DNSResolverMessage_dnssecquery(a: crate::lightning::onion_message::dns_resolution::DNSSECQuery) -> DNSResolverMessage {
	DNSResolverMessage::DNSSECQuery(a, )
}
#[no_mangle]
/// Utility method to constructs a new DNSSECProof-variant DNSResolverMessage
pub extern "C" fn DNSResolverMessage_dnssecproof(a: crate::lightning::onion_message::dns_resolution::DNSSECProof) -> DNSResolverMessage {
	DNSResolverMessage::DNSSECProof(a, )
}
/// Get a string which allows debug introspection of a DNSResolverMessage object
pub extern "C" fn DNSResolverMessage_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::dns_resolution::DNSResolverMessage }).into()}
/// Generates a non-cryptographic 64-bit hash of the DNSResolverMessage.
#[no_mangle]
pub extern "C" fn DNSResolverMessage_hash(o: &DNSResolverMessage) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two DNSResolverMessages contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn DNSResolverMessage_eq(a: &DNSResolverMessage, b: &DNSResolverMessage) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning::onion_message::dns_resolution::DNSSECQuery as nativeDNSSECQueryImport;
pub(crate) type nativeDNSSECQuery = nativeDNSSECQueryImport;

/// A message which is sent to a DNSSEC prover requesting a DNSSEC proof for the given name.
#[must_use]
#[repr(C)]
pub struct DNSSECQuery {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDNSSECQuery,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for DNSSECQuery {
	type Target = nativeDNSSECQuery;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for DNSSECQuery { }
unsafe impl core::marker::Sync for DNSSECQuery { }
impl Drop for DNSSECQuery {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDNSSECQuery>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DNSSECQuery, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DNSSECQuery_free(this_obj: DNSSECQuery) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSSECQuery_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDNSSECQuery) };
}
#[allow(unused)]
impl DNSSECQuery {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDNSSECQuery {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDNSSECQuery {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDNSSECQuery {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for DNSSECQuery {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDNSSECQuery>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSSECQuery_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeDNSSECQuery)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DNSSECQuery
pub extern "C" fn DNSSECQuery_clone(orig: &DNSSECQuery) -> DNSSECQuery {
	orig.clone()
}
/// Get a string which allows debug introspection of a DNSSECQuery object
pub extern "C" fn DNSSECQuery_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::dns_resolution::DNSSECQuery }).into()}
/// Generates a non-cryptographic 64-bit hash of the DNSSECQuery.
#[no_mangle]
pub extern "C" fn DNSSECQuery_hash(o: &DNSSECQuery) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two DNSSECQuerys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn DNSSECQuery_eq(a: &DNSSECQuery, b: &DNSSECQuery) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::onion_message::dns_resolution::DNSSECProof as nativeDNSSECProofImport;
pub(crate) type nativeDNSSECProof = nativeDNSSECProofImport;

/// A message which is sent in response to [`DNSSECQuery`] containing a DNSSEC proof.
#[must_use]
#[repr(C)]
pub struct DNSSECProof {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDNSSECProof,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for DNSSECProof {
	type Target = nativeDNSSECProof;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for DNSSECProof { }
unsafe impl core::marker::Sync for DNSSECProof { }
impl Drop for DNSSECProof {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDNSSECProof>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DNSSECProof, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DNSSECProof_free(this_obj: DNSSECProof) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSSECProof_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDNSSECProof) };
}
#[allow(unused)]
impl DNSSECProof {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDNSSECProof {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDNSSECProof {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDNSSECProof {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// An [RFC 9102 DNSSEC AuthenticationChain] providing a DNSSEC proof.
///
/// [RFC 9102 DNSSEC AuthenticationChain]: https://www.rfc-editor.org/rfc/rfc9102.html#name-dnssec-authentication-chain
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn DNSSECProof_get_proof(this_ptr: &DNSSECProof) -> crate::c_types::derived::CVec_u8Z {
	let mut inner_val = this_ptr.get_native_mut_ref().proof.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// An [RFC 9102 DNSSEC AuthenticationChain] providing a DNSSEC proof.
///
/// [RFC 9102 DNSSEC AuthenticationChain]: https://www.rfc-editor.org/rfc/rfc9102.html#name-dnssec-authentication-chain
#[no_mangle]
pub extern "C" fn DNSSECProof_set_proof(this_ptr: &mut DNSSECProof, mut val: crate::c_types::derived::CVec_u8Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.proof = local_val;
}
impl Clone for DNSSECProof {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDNSSECProof>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DNSSECProof_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeDNSSECProof)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DNSSECProof
pub extern "C" fn DNSSECProof_clone(orig: &DNSSECProof) -> DNSSECProof {
	orig.clone()
}
/// Get a string which allows debug introspection of a DNSSECProof object
pub extern "C" fn DNSSECProof_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::dns_resolution::DNSSECProof }).into()}
/// Generates a non-cryptographic 64-bit hash of the DNSSECProof.
#[no_mangle]
pub extern "C" fn DNSSECProof_hash(o: &DNSSECProof) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two DNSSECProofs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn DNSSECProof_eq(a: &DNSSECProof, b: &DNSSECProof) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns whether `tlv_type` corresponds to a TLV record for DNS Resolvers.
#[must_use]
#[no_mangle]
pub extern "C" fn DNSResolverMessage_is_known_type(mut tlv_type: u64) -> bool {
	let mut ret = lightning::onion_message::dns_resolution::DNSResolverMessage::is_known_type(tlv_type);
	ret
}

#[no_mangle]
/// Serialize the DNSResolverMessage object into a byte array which can be read by DNSResolverMessage_read
pub extern "C" fn DNSResolverMessage_write(obj: &crate::lightning::onion_message::dns_resolution::DNSResolverMessage) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn DNSResolverMessage_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	DNSResolverMessage_write(unsafe { &*(obj as *const DNSResolverMessage) })
}
#[no_mangle]
/// Read a DNSResolverMessage from a byte array, created by DNSResolverMessage_write
pub extern "C" fn DNSResolverMessage_read(ser: crate::c_types::u8slice, arg: u64) -> crate::c_types::derived::CResult_DNSResolverMessageDecodeErrorZ {
	let arg_conv = arg;
	let res: Result<lightning::onion_message::dns_resolution::DNSResolverMessage, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::dns_resolution::DNSResolverMessage::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
impl From<nativeDNSResolverMessage> for crate::lightning::onion_message::packet::OnionMessageContents {
	fn from(obj: nativeDNSResolverMessage) -> Self {
		let rust_obj = crate::lightning::onion_message::dns_resolution::DNSResolverMessage::native_into(obj);
		let mut ret = DNSResolverMessage_as_OnionMessageContents(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(DNSResolverMessage_free_void);
		ret
	}
}
/// Constructs a new OnionMessageContents which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageContents must be freed before this_arg is
#[no_mangle]
pub extern "C" fn DNSResolverMessage_as_OnionMessageContents(this_arg: &DNSResolverMessage) -> crate::lightning::onion_message::packet::OnionMessageContents {
	crate::lightning::onion_message::packet::OnionMessageContents {
		this_arg: unsafe { ObjOps::untweak_ptr(this_arg as *const DNSResolverMessage as *mut DNSResolverMessage) as *mut c_void },
		free: None,
		tlv_type: DNSResolverMessage_OnionMessageContents_tlv_type,
		msg_type: DNSResolverMessage_OnionMessageContents_msg_type,
		write: DNSResolverMessage_write_void,
		debug_str: DNSResolverMessage_debug_str_void,
		cloned: Some(OnionMessageContents_DNSResolverMessage_cloned),
	}
}

#[must_use]
extern "C" fn DNSResolverMessage_OnionMessageContents_tlv_type(this_arg: *const c_void) -> u64 {
	let mut ret = <nativeDNSResolverMessage as lightning::onion_message::packet::OnionMessageContents>::tlv_type(unsafe { &mut *(this_arg as *mut nativeDNSResolverMessage) }, );
	ret
}
#[must_use]
extern "C" fn DNSResolverMessage_OnionMessageContents_msg_type(this_arg: *const c_void) -> crate::c_types::Str {
	let mut ret = <nativeDNSResolverMessage as lightning::onion_message::packet::OnionMessageContents>::msg_type(unsafe { &mut *(this_arg as *mut nativeDNSResolverMessage) }, );
	ret.into()
}
extern "C" fn OnionMessageContents_DNSResolverMessage_cloned(new_obj: &mut crate::lightning::onion_message::packet::OnionMessageContents) {
	new_obj.this_arg = DNSResolverMessage_clone_void(new_obj.this_arg);
	new_obj.free = Some(DNSResolverMessage_free_void);
}


use lightning::onion_message::dns_resolution::HumanReadableName as nativeHumanReadableNameImport;
pub(crate) type nativeHumanReadableName = nativeHumanReadableNameImport;

/// A struct containing the two parts of a BIP 353 Human Readable Name - the user and domain parts.
///
/// The `user` and `domain` parts, together, cannot exceed 232 bytes in length, and both must be
/// non-empty.
///
/// To protect against [Homograph Attacks], both parts of a Human Readable Name must be plain
/// ASCII.
///
/// [Homograph Attacks]: https://en.wikipedia.org/wiki/IDN_homograph_attack
#[must_use]
#[repr(C)]
pub struct HumanReadableName {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHumanReadableName,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for HumanReadableName {
	type Target = nativeHumanReadableName;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for HumanReadableName { }
unsafe impl core::marker::Sync for HumanReadableName { }
impl Drop for HumanReadableName {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHumanReadableName>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the HumanReadableName, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn HumanReadableName_free(this_obj: HumanReadableName) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HumanReadableName_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHumanReadableName) };
}
#[allow(unused)]
impl HumanReadableName {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHumanReadableName {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHumanReadableName {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHumanReadableName {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for HumanReadableName {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHumanReadableName>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HumanReadableName_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeHumanReadableName)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the HumanReadableName
pub extern "C" fn HumanReadableName_clone(orig: &HumanReadableName) -> HumanReadableName {
	orig.clone()
}
/// Get a string which allows debug introspection of a HumanReadableName object
pub extern "C" fn HumanReadableName_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::dns_resolution::HumanReadableName }).into()}
/// Generates a non-cryptographic 64-bit hash of the HumanReadableName.
#[no_mangle]
pub extern "C" fn HumanReadableName_hash(o: &HumanReadableName) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two HumanReadableNames contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn HumanReadableName_eq(a: &HumanReadableName, b: &HumanReadableName) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Constructs a new [`HumanReadableName`] from the `user` and `domain` parts. See the
/// struct-level documentation for more on the requirements on each.
#[must_use]
#[no_mangle]
pub extern "C" fn HumanReadableName_new(mut user: crate::c_types::Str, mut domain: crate::c_types::Str) -> crate::c_types::derived::CResult_HumanReadableNameNoneZ {
	let mut ret = lightning::onion_message::dns_resolution::HumanReadableName::new(user.into_string(), domain.into_string());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::dns_resolution::HumanReadableName { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Constructs a new [`HumanReadableName`] from the standard encoding - `user`@`domain`.
///
/// If `user` includes the standard BIP 353 ₿ prefix it is automatically removed as required by
/// BIP 353.
#[must_use]
#[no_mangle]
pub extern "C" fn HumanReadableName_from_encoded(mut encoded: crate::c_types::Str) -> crate::c_types::derived::CResult_HumanReadableNameNoneZ {
	let mut ret = lightning::onion_message::dns_resolution::HumanReadableName::from_encoded(encoded.into_str());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::dns_resolution::HumanReadableName { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Gets the `user` part of this Human Readable Name
#[must_use]
#[no_mangle]
pub extern "C" fn HumanReadableName_user(this_arg: &crate::lightning::onion_message::dns_resolution::HumanReadableName) -> crate::c_types::Str {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.user();
	ret.into()
}

/// Gets the `domain` part of this Human Readable Name
#[must_use]
#[no_mangle]
pub extern "C" fn HumanReadableName_domain(this_arg: &crate::lightning::onion_message::dns_resolution::HumanReadableName) -> crate::c_types::Str {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.domain();
	ret.into()
}

#[no_mangle]
/// Serialize the HumanReadableName object into a byte array which can be read by HumanReadableName_read
pub extern "C" fn HumanReadableName_write(obj: &crate::lightning::onion_message::dns_resolution::HumanReadableName) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn HumanReadableName_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::dns_resolution::nativeHumanReadableName) })
}
#[no_mangle]
/// Read a HumanReadableName from a byte array, created by HumanReadableName_write
pub extern "C" fn HumanReadableName_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HumanReadableNameDecodeErrorZ {
	let res: Result<lightning::onion_message::dns_resolution::HumanReadableName, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::dns_resolution::HumanReadableName { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::onion_message::dns_resolution::OMNameResolver as nativeOMNameResolverImport;
pub(crate) type nativeOMNameResolver = nativeOMNameResolverImport;

/// A stateful resolver which maps BIP 353 Human Readable Names to URIs and BOLT12 [`Offer`]s.
///
/// It does not directly implement [`DNSResolverMessageHandler`] but implements all the core logic
/// which is required in a client which intends to.
///
/// It relies on being made aware of the passage of time with regular calls to
/// [`Self::new_best_block`] in order to time out existing queries. Queries time out after two
/// blocks.
#[must_use]
#[repr(C)]
pub struct OMNameResolver {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOMNameResolver,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OMNameResolver {
	type Target = nativeOMNameResolver;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OMNameResolver { }
unsafe impl core::marker::Sync for OMNameResolver { }
impl Drop for OMNameResolver {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOMNameResolver>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OMNameResolver, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OMNameResolver_free(this_obj: OMNameResolver) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OMNameResolver_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOMNameResolver) };
}
#[allow(unused)]
impl OMNameResolver {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOMNameResolver {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOMNameResolver {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOMNameResolver {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Builds a new [`OMNameResolver`].
#[must_use]
#[no_mangle]
pub extern "C" fn OMNameResolver_new(mut latest_block_time: u32, mut latest_block_height: u32) -> crate::lightning::onion_message::dns_resolution::OMNameResolver {
	let mut ret = lightning::onion_message::dns_resolution::OMNameResolver::new(latest_block_time, latest_block_height);
	crate::lightning::onion_message::dns_resolution::OMNameResolver { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Informs the [`OMNameResolver`] of the passage of time in the form of a new best Bitcoin
/// block.
///
/// This will call back to resolve some pending queries which have timed out.
#[no_mangle]
pub extern "C" fn OMNameResolver_new_best_block(this_arg: &crate::lightning::onion_message::dns_resolution::OMNameResolver, mut height: u32, mut time: u32) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.new_best_block(height, time)
}

/// Begins the process of resolving a BIP 353 Human Readable Name.
///
/// Returns a [`DNSSECQuery`] onion message and a [`DNSResolverContext`] which should be sent
/// to a resolver (with the context used to generate the blinded response path) on success.
#[must_use]
#[no_mangle]
pub extern "C" fn OMNameResolver_resolve_name(this_arg: &crate::lightning::onion_message::dns_resolution::OMNameResolver, mut payment_id: crate::c_types::ThirtyTwoBytes, mut name: crate::lightning::onion_message::dns_resolution::HumanReadableName, entropy_source: &crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_C2Tuple_DNSSECQueryDNSResolverContextZNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.resolve_name(::lightning::ln::channelmanager::PaymentId(payment_id.data), *unsafe { Box::from_raw(name.take_inner()) }, entropy_source);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::lightning::onion_message::dns_resolution::DNSSECQuery { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, crate::lightning::blinded_path::message::DNSResolverContext { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Handles a [`DNSSECProof`] message, attempting to verify it and match it against a pending
/// query.
///
/// If verification succeeds, the resulting bitcoin: URI is parsed to find a contained
/// [`Offer`].
///
/// Note that a single proof for a wildcard DNS entry may complete several requests for
/// different [`HumanReadableName`]s.
///
/// If an [`Offer`] is found, it, as well as the [`PaymentId`] and original `name` passed to
/// [`Self::resolve_name`] are returned.
#[must_use]
#[no_mangle]
pub extern "C" fn OMNameResolver_handle_dnssec_proof_for_offer(this_arg: &crate::lightning::onion_message::dns_resolution::OMNameResolver, mut msg: crate::lightning::onion_message::dns_resolution::DNSSECProof, mut context: crate::lightning::blinded_path::message::DNSResolverContext) -> crate::c_types::derived::COption_C2Tuple_CVec_C2Tuple_HumanReadableNameThirtyTwoBytesZZOfferZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_dnssec_proof_for_offer(*unsafe { Box::from_raw(msg.take_inner()) }, *unsafe { Box::from_raw(context.take_inner()) });
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_C2Tuple_CVec_C2Tuple_HumanReadableNameThirtyTwoBytesZZOfferZZ::None } else { crate::c_types::derived::COption_C2Tuple_CVec_C2Tuple_HumanReadableNameThirtyTwoBytesZZOfferZZ::Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (ret.unwrap()); let mut local_orig_ret_0_0 = Vec::new(); for mut item in orig_ret_0_0.drain(..) { local_orig_ret_0_0.push( { let (mut orig_orig_ret_0_0_0_0, mut orig_orig_ret_0_0_0_1) = item; let mut local_orig_ret_0_0_0 = (crate::lightning::onion_message::dns_resolution::HumanReadableName { inner: ObjOps::heap_alloc(orig_orig_ret_0_0_0_0), is_owned: true }, crate::c_types::ThirtyTwoBytes { data: orig_orig_ret_0_0_0_1.0 }).into(); local_orig_ret_0_0_0 }); }; let mut local_ret_0 = (local_orig_ret_0_0.into(), crate::lightning::offers::offer::Offer { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }) };
	local_ret
}

/// Handles a [`DNSSECProof`] message, attempting to verify it and match it against any pending
/// queries.
///
/// If verification succeeds, all matching [`PaymentId`] and [`HumanReadableName`]s passed to
/// [`Self::resolve_name`], as well as the resolved bitcoin: URI are returned.
///
/// Note that a single proof for a wildcard DNS entry may complete several requests for
/// different [`HumanReadableName`]s.
///
/// This method is useful for those who handle bitcoin: URIs already, handling more than just
/// BOLT12 [`Offer`]s.
#[must_use]
#[no_mangle]
pub extern "C" fn OMNameResolver_handle_dnssec_proof_for_uri(this_arg: &crate::lightning::onion_message::dns_resolution::OMNameResolver, mut msg: crate::lightning::onion_message::dns_resolution::DNSSECProof, mut context: crate::lightning::blinded_path::message::DNSResolverContext) -> crate::c_types::derived::COption_C2Tuple_CVec_C2Tuple_HumanReadableNameThirtyTwoBytesZZStrZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_dnssec_proof_for_uri(*unsafe { Box::from_raw(msg.take_inner()) }, *unsafe { Box::from_raw(context.take_inner()) });
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_C2Tuple_CVec_C2Tuple_HumanReadableNameThirtyTwoBytesZZStrZZ::None } else { crate::c_types::derived::COption_C2Tuple_CVec_C2Tuple_HumanReadableNameThirtyTwoBytesZZStrZZ::Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (ret.unwrap()); let mut local_orig_ret_0_0 = Vec::new(); for mut item in orig_ret_0_0.drain(..) { local_orig_ret_0_0.push( { let (mut orig_orig_ret_0_0_0_0, mut orig_orig_ret_0_0_0_1) = item; let mut local_orig_ret_0_0_0 = (crate::lightning::onion_message::dns_resolution::HumanReadableName { inner: ObjOps::heap_alloc(orig_orig_ret_0_0_0_0), is_owned: true }, crate::c_types::ThirtyTwoBytes { data: orig_orig_ret_0_0_0_1.0 }).into(); local_orig_ret_0_0_0 }); }; let mut local_ret_0 = (local_orig_ret_0_0.into(), orig_ret_0_1.into()).into(); local_ret_0 }) };
	local_ret
}

