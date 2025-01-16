// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! LDK sends, receives, and forwards onion messages via this [`OnionMessenger`], which lives here,
//! as well as various types, traits, and utilities that it uses.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::onion_message::messenger::OnionMessenger as nativeOnionMessengerImport;
pub(crate) type nativeOnionMessenger = nativeOnionMessengerImport<crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::util::logger::Logger, crate::lightning::blinded_path::NodeIdLookUp, crate::lightning::onion_message::messenger::MessageRouter, crate::lightning::onion_message::offers::OffersMessageHandler, crate::lightning::onion_message::async_payments::AsyncPaymentsMessageHandler, crate::lightning::onion_message::dns_resolution::DNSResolverMessageHandler, crate::lightning::onion_message::messenger::CustomOnionMessageHandler, >;

/// A sender, receiver and forwarder of [`OnionMessage`]s.
///
/// # Handling Messages
///
/// `OnionMessenger` implements [`OnionMessageHandler`], making it responsible for either forwarding
/// messages to peers or delegating to the appropriate handler for the message type. Currently, the
/// available handlers are:
/// * [`OffersMessageHandler`], for responding to [`InvoiceRequest`]s and paying [`Bolt12Invoice`]s
/// * [`CustomOnionMessageHandler`], for handling user-defined message types
///
/// # Sending Messages
///
/// [`OnionMessage`]s are sent initially using [`OnionMessenger::send_onion_message`]. When handling
/// a message, the matched handler may return a response message which `OnionMessenger` will send
/// on its behalf.
///
/// # Example
///
/// ```
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::hex::FromHex;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, self};
/// # use lightning::blinded_path::EmptyNodeIdLookUp;
/// # use lightning::blinded_path::message::{BlindedMessagePath, MessageForwardNode, MessageContext};
/// # use lightning::sign::{EntropySource, KeysManager};
/// # use lightning::ln::peer_handler::IgnoringMessageHandler;
/// # use lightning::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions, OnionMessagePath, OnionMessenger};
/// # use lightning::onion_message::packet::OnionMessageContents;
/// # use lightning::util::logger::{Logger, Record};
/// # use lightning::util::ser::{Writeable, Writer};
/// # use lightning::io;
/// # use std::sync::Arc;
/// # struct FakeLogger;
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: Record) { println!(\"{:?}\" , record); }
/// # }
/// # struct FakeMessageRouter {}
/// # impl MessageRouter for FakeMessageRouter {
/// #     fn find_path(&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination) -> Result<OnionMessagePath, ()> {
/// #         let secp_ctx = Secp256k1::new();
/// #         let node_secret = SecretKey::from_slice(&<Vec<u8>>::from_hex(\"0101010101010101010101010101010101010101010101010101010101010101\").unwrap()[..]).unwrap();
/// #         let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// #         let hop_node_id2 = hop_node_id1;
/// #         Ok(OnionMessagePath {
/// #             intermediate_nodes: vec![hop_node_id1, hop_node_id2],
/// #             destination,
/// #             first_node_addresses: None,
/// #         })
/// #     }
/// #     fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
/// #         &self, _recipient: PublicKey, _context: MessageContext, _peers: Vec<PublicKey>, _secp_ctx: &Secp256k1<T>
/// #     ) -> Result<Vec<BlindedMessagePath>, ()> {
/// #         unreachable!()
/// #     }
/// # }
/// # let seed = [42u8; 32];
/// # let time = Duration::from_secs(123456);
/// # let keys_manager = KeysManager::new(&seed, time.as_secs(), time.subsec_nanos());
/// # let logger = Arc::new(FakeLogger {});
/// # let node_secret = SecretKey::from_slice(&<Vec<u8>>::from_hex(\"0101010101010101010101010101010101010101010101010101010101010101\").unwrap()[..]).unwrap();
/// # let secp_ctx = Secp256k1::new();
/// # let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// # let (hop_node_id3, hop_node_id4) = (hop_node_id1, hop_node_id1);
/// # let destination_node_id = hop_node_id1;
/// # let node_id_lookup = EmptyNodeIdLookUp {};
/// # let message_router = Arc::new(FakeMessageRouter {});
/// # let custom_message_handler = IgnoringMessageHandler {};
/// # let offers_message_handler = IgnoringMessageHandler {};
/// # let async_payments_message_handler = IgnoringMessageHandler {};
/// # let dns_resolution_message_handler = IgnoringMessageHandler {};
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(
///     &keys_manager, &keys_manager, logger, &node_id_lookup, message_router,
///     &offers_message_handler, &async_payments_message_handler, &dns_resolution_message_handler,
///     &custom_message_handler,
/// );
///
/// # #[derive(Clone, Debug)]
/// # struct YourCustomMessage {}
/// impl Writeable for YourCustomMessage {
/// \tfn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
/// \t\t# Ok(())
/// \t\t// Write your custom onion message to `w`
/// \t}
/// }
/// impl OnionMessageContents for YourCustomMessage {
/// \tfn tlv_type(&self) -> u64 {
/// \t\t# let your_custom_message_type = 42;
/// \t\tyour_custom_message_type
/// \t}
/// \tfn msg_type(&self) -> &'static str { \"YourCustomMessageType\" }
/// }
/// // Send a custom onion message to a node id.
/// let destination = Destination::Node(destination_node_id);
/// let instructions = MessageSendInstructions::WithoutReplyPath { destination };
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(message, instructions);
///
/// // Create a blinded path to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [
/// \tMessageForwardNode { node_id: hop_node_id3, short_channel_id: None },
/// \tMessageForwardNode { node_id: hop_node_id4, short_channel_id: None },
/// ];
/// let context = MessageContext::Custom(Vec::new());
/// let blinded_path = BlindedMessagePath::new(&hops, your_node_id, context, &keys_manager, &secp_ctx).unwrap();
///
/// // Send a custom onion message to a blinded path.
/// let destination = Destination::BlindedPath(blinded_path);
/// let instructions = MessageSendInstructions::WithoutReplyPath { destination };
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(message, instructions);
/// ```
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[repr(C)]
pub struct OnionMessenger {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOnionMessenger,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OnionMessenger {
	type Target = nativeOnionMessenger;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OnionMessenger { }
unsafe impl core::marker::Sync for OnionMessenger { }
impl Drop for OnionMessenger {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOnionMessenger>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OnionMessenger, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OnionMessenger_free(this_obj: OnionMessenger) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OnionMessenger_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOnionMessenger) };
}
#[allow(unused)]
impl OnionMessenger {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOnionMessenger {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOnionMessenger {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOnionMessenger {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}

use lightning::onion_message::messenger::Responder as nativeResponderImport;
pub(crate) type nativeResponder = nativeResponderImport;

/// The `Responder` struct creates an appropriate [`ResponseInstruction`] for responding to a
/// message.
#[must_use]
#[repr(C)]
pub struct Responder {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeResponder,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Responder {
	type Target = nativeResponder;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Responder { }
unsafe impl core::marker::Sync for Responder { }
impl Drop for Responder {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeResponder>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Responder, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Responder_free(this_obj: Responder) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Responder_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeResponder) };
}
#[allow(unused)]
impl Responder {
	pub(crate) fn get_native_ref(&self) -> &'static nativeResponder {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeResponder {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeResponder {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for Responder {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeResponder>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Responder_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeResponder)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Responder
pub extern "C" fn Responder_clone(orig: &Responder) -> Responder {
	orig.clone()
}
/// Get a string which allows debug introspection of a Responder object
pub extern "C" fn Responder_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::messenger::Responder }).into()}
/// Checks if two Responders contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Responder_eq(a: &Responder, b: &Responder) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the Responder object into a byte array which can be read by Responder_read
pub extern "C" fn Responder_write(obj: &crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Responder_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::onion_message::messenger::nativeResponder) })
}
#[no_mangle]
/// Read a Responder from a byte array, created by Responder_write
pub extern "C" fn Responder_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ResponderDecodeErrorZ {
	let res: Result<lightning::onion_message::messenger::Responder, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::Responder { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Creates a [`ResponseInstruction`] for responding without including a reply path.
///
/// Use when the recipient doesn't need to send back a reply to us.
#[must_use]
#[no_mangle]
pub extern "C" fn Responder_respond(mut this_arg: crate::lightning::onion_message::messenger::Responder) -> crate::lightning::onion_message::messenger::ResponseInstruction {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).respond();
	crate::lightning::onion_message::messenger::ResponseInstruction { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a [`ResponseInstruction`] for responding including a reply path.
///
/// Use when the recipient needs to send back a reply to us.
#[must_use]
#[no_mangle]
pub extern "C" fn Responder_respond_with_reply_path(mut this_arg: crate::lightning::onion_message::messenger::Responder, mut context: crate::lightning::blinded_path::message::MessageContext) -> crate::lightning::onion_message::messenger::ResponseInstruction {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).respond_with_reply_path(context.into_native());
	crate::lightning::onion_message::messenger::ResponseInstruction { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::onion_message::messenger::ResponseInstruction as nativeResponseInstructionImport;
pub(crate) type nativeResponseInstruction = nativeResponseInstructionImport;

/// Instructions for how and where to send the response to an onion message.
#[must_use]
#[repr(C)]
pub struct ResponseInstruction {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeResponseInstruction,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ResponseInstruction {
	type Target = nativeResponseInstruction;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ResponseInstruction { }
unsafe impl core::marker::Sync for ResponseInstruction { }
impl Drop for ResponseInstruction {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeResponseInstruction>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ResponseInstruction, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ResponseInstruction_free(this_obj: ResponseInstruction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ResponseInstruction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeResponseInstruction) };
}
#[allow(unused)]
impl ResponseInstruction {
	pub(crate) fn get_native_ref(&self) -> &'static nativeResponseInstruction {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeResponseInstruction {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeResponseInstruction {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
impl Clone for ResponseInstruction {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeResponseInstruction>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ResponseInstruction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeResponseInstruction)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ResponseInstruction
pub extern "C" fn ResponseInstruction_clone(orig: &ResponseInstruction) -> ResponseInstruction {
	orig.clone()
}
/// Converts this [`ResponseInstruction`] into a [`MessageSendInstructions`] so that it can be
/// used to send the response via a normal message sending method.
#[must_use]
#[no_mangle]
pub extern "C" fn ResponseInstruction_into_instructions(mut this_arg: crate::lightning::onion_message::messenger::ResponseInstruction) -> crate::lightning::onion_message::messenger::MessageSendInstructions {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_instructions();
	crate::lightning::onion_message::messenger::MessageSendInstructions::native_into(ret)
}

/// Instructions for how and where to send a message.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum MessageSendInstructions {
	/// Indicates that a message should be sent including the provided reply path for the recipient
	/// to respond.
	WithSpecifiedReplyPath {
		/// The destination where we need to send our message.
		destination: crate::lightning::onion_message::messenger::Destination,
		/// The reply path which should be included in the message.
		reply_path: crate::lightning::blinded_path::message::BlindedMessagePath,
	},
	/// Indicates that a message should be sent including a reply path for the recipient to
	/// respond.
	WithReplyPath {
		/// The destination where we need to send our message.
		destination: crate::lightning::onion_message::messenger::Destination,
		/// The context to include in the reply path we'll give the recipient so they can respond
		/// to us.
		context: crate::lightning::blinded_path::message::MessageContext,
	},
	/// Indicates that a message should be sent without including a reply path, preventing the
	/// recipient from responding.
	WithoutReplyPath {
		/// The destination where we need to send our message.
		destination: crate::lightning::onion_message::messenger::Destination,
	},
	/// Indicates that a message is being sent as a reply to a received message.
	ForReply {
		/// The instructions provided by the [`Responder`].
		instructions: crate::lightning::onion_message::messenger::ResponseInstruction,
	},
}
use lightning::onion_message::messenger::MessageSendInstructions as MessageSendInstructionsImport;
pub(crate) type nativeMessageSendInstructions = MessageSendInstructionsImport;

impl MessageSendInstructions {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMessageSendInstructions {
		match self {
			MessageSendInstructions::WithSpecifiedReplyPath {ref destination, ref reply_path, } => {
				let mut destination_nonref = Clone::clone(destination);
				let mut reply_path_nonref = Clone::clone(reply_path);
				nativeMessageSendInstructions::WithSpecifiedReplyPath {
					destination: destination_nonref.into_native(),
					reply_path: *unsafe { Box::from_raw(reply_path_nonref.take_inner()) },
				}
			},
			MessageSendInstructions::WithReplyPath {ref destination, ref context, } => {
				let mut destination_nonref = Clone::clone(destination);
				let mut context_nonref = Clone::clone(context);
				nativeMessageSendInstructions::WithReplyPath {
					destination: destination_nonref.into_native(),
					context: context_nonref.into_native(),
				}
			},
			MessageSendInstructions::WithoutReplyPath {ref destination, } => {
				let mut destination_nonref = Clone::clone(destination);
				nativeMessageSendInstructions::WithoutReplyPath {
					destination: destination_nonref.into_native(),
				}
			},
			MessageSendInstructions::ForReply {ref instructions, } => {
				let mut instructions_nonref = Clone::clone(instructions);
				nativeMessageSendInstructions::ForReply {
					instructions: *unsafe { Box::from_raw(instructions_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeMessageSendInstructions {
		match self {
			MessageSendInstructions::WithSpecifiedReplyPath {mut destination, mut reply_path, } => {
				nativeMessageSendInstructions::WithSpecifiedReplyPath {
					destination: destination.into_native(),
					reply_path: *unsafe { Box::from_raw(reply_path.take_inner()) },
				}
			},
			MessageSendInstructions::WithReplyPath {mut destination, mut context, } => {
				nativeMessageSendInstructions::WithReplyPath {
					destination: destination.into_native(),
					context: context.into_native(),
				}
			},
			MessageSendInstructions::WithoutReplyPath {mut destination, } => {
				nativeMessageSendInstructions::WithoutReplyPath {
					destination: destination.into_native(),
				}
			},
			MessageSendInstructions::ForReply {mut instructions, } => {
				nativeMessageSendInstructions::ForReply {
					instructions: *unsafe { Box::from_raw(instructions.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &MessageSendInstructionsImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeMessageSendInstructions) };
		match native {
			nativeMessageSendInstructions::WithSpecifiedReplyPath {ref destination, ref reply_path, } => {
				let mut destination_nonref = Clone::clone(destination);
				let mut reply_path_nonref = Clone::clone(reply_path);
				MessageSendInstructions::WithSpecifiedReplyPath {
					destination: crate::lightning::onion_message::messenger::Destination::native_into(destination_nonref),
					reply_path: crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(reply_path_nonref), is_owned: true },
				}
			},
			nativeMessageSendInstructions::WithReplyPath {ref destination, ref context, } => {
				let mut destination_nonref = Clone::clone(destination);
				let mut context_nonref = Clone::clone(context);
				MessageSendInstructions::WithReplyPath {
					destination: crate::lightning::onion_message::messenger::Destination::native_into(destination_nonref),
					context: crate::lightning::blinded_path::message::MessageContext::native_into(context_nonref),
				}
			},
			nativeMessageSendInstructions::WithoutReplyPath {ref destination, } => {
				let mut destination_nonref = Clone::clone(destination);
				MessageSendInstructions::WithoutReplyPath {
					destination: crate::lightning::onion_message::messenger::Destination::native_into(destination_nonref),
				}
			},
			nativeMessageSendInstructions::ForReply {ref instructions, } => {
				let mut instructions_nonref = Clone::clone(instructions);
				MessageSendInstructions::ForReply {
					instructions: crate::lightning::onion_message::messenger::ResponseInstruction { inner: ObjOps::heap_alloc(instructions_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeMessageSendInstructions) -> Self {
		match native {
			nativeMessageSendInstructions::WithSpecifiedReplyPath {mut destination, mut reply_path, } => {
				MessageSendInstructions::WithSpecifiedReplyPath {
					destination: crate::lightning::onion_message::messenger::Destination::native_into(destination),
					reply_path: crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(reply_path), is_owned: true },
				}
			},
			nativeMessageSendInstructions::WithReplyPath {mut destination, mut context, } => {
				MessageSendInstructions::WithReplyPath {
					destination: crate::lightning::onion_message::messenger::Destination::native_into(destination),
					context: crate::lightning::blinded_path::message::MessageContext::native_into(context),
				}
			},
			nativeMessageSendInstructions::WithoutReplyPath {mut destination, } => {
				MessageSendInstructions::WithoutReplyPath {
					destination: crate::lightning::onion_message::messenger::Destination::native_into(destination),
				}
			},
			nativeMessageSendInstructions::ForReply {mut instructions, } => {
				MessageSendInstructions::ForReply {
					instructions: crate::lightning::onion_message::messenger::ResponseInstruction { inner: ObjOps::heap_alloc(instructions), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the MessageSendInstructions
#[no_mangle]
pub extern "C" fn MessageSendInstructions_free(this_ptr: MessageSendInstructions) { }
/// Creates a copy of the MessageSendInstructions
#[no_mangle]
pub extern "C" fn MessageSendInstructions_clone(orig: &MessageSendInstructions) -> MessageSendInstructions {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageSendInstructions_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const MessageSendInstructions)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageSendInstructions_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut MessageSendInstructions) };
}
#[no_mangle]
/// Utility method to constructs a new WithSpecifiedReplyPath-variant MessageSendInstructions
pub extern "C" fn MessageSendInstructions_with_specified_reply_path(destination: crate::lightning::onion_message::messenger::Destination, reply_path: crate::lightning::blinded_path::message::BlindedMessagePath) -> MessageSendInstructions {
	MessageSendInstructions::WithSpecifiedReplyPath {
		destination,
		reply_path,
	}
}
#[no_mangle]
/// Utility method to constructs a new WithReplyPath-variant MessageSendInstructions
pub extern "C" fn MessageSendInstructions_with_reply_path(destination: crate::lightning::onion_message::messenger::Destination, context: crate::lightning::blinded_path::message::MessageContext) -> MessageSendInstructions {
	MessageSendInstructions::WithReplyPath {
		destination,
		context,
	}
}
#[no_mangle]
/// Utility method to constructs a new WithoutReplyPath-variant MessageSendInstructions
pub extern "C" fn MessageSendInstructions_without_reply_path(destination: crate::lightning::onion_message::messenger::Destination) -> MessageSendInstructions {
	MessageSendInstructions::WithoutReplyPath {
		destination,
	}
}
#[no_mangle]
/// Utility method to constructs a new ForReply-variant MessageSendInstructions
pub extern "C" fn MessageSendInstructions_for_reply(instructions: crate::lightning::onion_message::messenger::ResponseInstruction) -> MessageSendInstructions {
	MessageSendInstructions::ForReply {
		instructions,
	}
}
/// A trait defining behavior for routing an [`OnionMessage`].
#[repr(C)]
pub struct MessageRouter {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns a route for sending an [`OnionMessage`] to the given [`Destination`].
	pub find_path: extern "C" fn (this_arg: *const c_void, sender: crate::c_types::PublicKey, peers: crate::c_types::derived::CVec_PublicKeyZ, destination: crate::lightning::onion_message::messenger::Destination) -> crate::c_types::derived::CResult_OnionMessagePathNoneZ,
	/// Creates [`BlindedMessagePath`]s to the `recipient` node. The nodes in `peers` are assumed to
	/// be direct peers with the `recipient`.
	pub create_blinded_paths: extern "C" fn (this_arg: *const c_void, recipient: crate::c_types::PublicKey, context: crate::lightning::blinded_path::message::MessageContext, peers: crate::c_types::derived::CVec_PublicKeyZ) -> crate::c_types::derived::CResult_CVec_BlindedMessagePathZNoneZ,
	/// Creates compact [`BlindedMessagePath`]s to the `recipient` node. The nodes in `peers` are
	/// assumed to be direct peers with the `recipient`.
	///
	/// Compact blinded paths use short channel ids instead of pubkeys for a smaller serialization,
	/// which is beneficial when a QR code is used to transport the data. The SCID is passed using
	/// a [`MessageForwardNode`] but may be `None` for graceful degradation.
	///
	/// Implementations using additional intermediate nodes are responsible for using a
	/// [`MessageForwardNode`] with `Some` short channel id, if possible. Similarly, implementations
	/// should call [`BlindedMessagePath::use_compact_introduction_node`].
	///
	/// The provided implementation simply delegates to [`MessageRouter::create_blinded_paths`],
	/// ignoring the short channel ids.
	pub create_compact_blinded_paths: extern "C" fn (this_arg: *const c_void, recipient: crate::c_types::PublicKey, context: crate::lightning::blinded_path::message::MessageContext, peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::CResult_CVec_BlindedMessagePathZNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for MessageRouter {}
unsafe impl Sync for MessageRouter {}
#[allow(unused)]
pub(crate) fn MessageRouter_clone_fields(orig: &MessageRouter) -> MessageRouter {
	MessageRouter {
		this_arg: orig.this_arg,
		find_path: Clone::clone(&orig.find_path),
		create_blinded_paths: Clone::clone(&orig.create_blinded_paths),
		create_compact_blinded_paths: Clone::clone(&orig.create_compact_blinded_paths),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::messenger::MessageRouter as rustMessageRouter;
impl rustMessageRouter for MessageRouter {
	fn find_path(&self, mut sender: bitcoin::secp256k1::PublicKey, mut peers: Vec<bitcoin::secp256k1::PublicKey>, mut destination: lightning::onion_message::messenger::Destination) -> Result<lightning::onion_message::messenger::OnionMessagePath, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::c_types::PublicKey::from_rust(&item) }); };
		let mut ret = (self.find_path)(self.this_arg, crate::c_types::PublicKey::from_rust(&sender), local_peers.into(), crate::lightning::onion_message::messenger::Destination::native_into(destination));
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn create_blinded_paths<T:bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(&self, mut recipient: bitcoin::secp256k1::PublicKey, mut context: lightning::blinded_path::message::MessageContext, mut peers: Vec<bitcoin::secp256k1::PublicKey>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<T>) -> Result<Vec<lightning::blinded_path::message::BlindedMessagePath>, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::c_types::PublicKey::from_rust(&item) }); };
		let mut ret = (self.create_blinded_paths)(self.this_arg, crate::c_types::PublicKey::from_rust(&recipient), crate::lightning::blinded_path::message::MessageContext::native_into(context), local_peers.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn create_compact_blinded_paths<T:bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(&self, mut recipient: bitcoin::secp256k1::PublicKey, mut context: lightning::blinded_path::message::MessageContext, mut peers: Vec<lightning::blinded_path::message::MessageForwardNode>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<T>) -> Result<Vec<lightning::blinded_path::message::BlindedMessagePath>, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::lightning::blinded_path::message::MessageForwardNode { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
		let mut ret = (self.create_compact_blinded_paths)(self.this_arg, crate::c_types::PublicKey::from_rust(&recipient), crate::lightning::blinded_path::message::MessageContext::native_into(context), local_peers.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

pub struct MessageRouterRef(MessageRouter);
impl rustMessageRouter for MessageRouterRef {
	fn find_path(&self, mut sender: bitcoin::secp256k1::PublicKey, mut peers: Vec<bitcoin::secp256k1::PublicKey>, mut destination: lightning::onion_message::messenger::Destination) -> Result<lightning::onion_message::messenger::OnionMessagePath, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::c_types::PublicKey::from_rust(&item) }); };
		let mut ret = (self.0.find_path)(self.0.this_arg, crate::c_types::PublicKey::from_rust(&sender), local_peers.into(), crate::lightning::onion_message::messenger::Destination::native_into(destination));
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn create_blinded_paths<T:bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(&self, mut recipient: bitcoin::secp256k1::PublicKey, mut context: lightning::blinded_path::message::MessageContext, mut peers: Vec<bitcoin::secp256k1::PublicKey>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<T>) -> Result<Vec<lightning::blinded_path::message::BlindedMessagePath>, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::c_types::PublicKey::from_rust(&item) }); };
		let mut ret = (self.0.create_blinded_paths)(self.0.this_arg, crate::c_types::PublicKey::from_rust(&recipient), crate::lightning::blinded_path::message::MessageContext::native_into(context), local_peers.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn create_compact_blinded_paths<T:bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(&self, mut recipient: bitcoin::secp256k1::PublicKey, mut context: lightning::blinded_path::message::MessageContext, mut peers: Vec<lightning::blinded_path::message::MessageForwardNode>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<T>) -> Result<Vec<lightning::blinded_path::message::BlindedMessagePath>, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::lightning::blinded_path::message::MessageForwardNode { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
		let mut ret = (self.0.create_compact_blinded_paths)(self.0.this_arg, crate::c_types::PublicKey::from_rust(&recipient), crate::lightning::blinded_path::message::MessageContext::native_into(context), local_peers.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for MessageRouter {
	type Target = MessageRouterRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const MessageRouterRef) }
	}
}
impl core::ops::DerefMut for MessageRouter {
	fn deref_mut(&mut self) -> &mut MessageRouterRef {
		unsafe { &mut *(self as *mut _ as *mut MessageRouterRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn MessageRouter_free(this_ptr: MessageRouter) { }
impl Drop for MessageRouter {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::onion_message::messenger::DefaultMessageRouter as nativeDefaultMessageRouterImport;
pub(crate) type nativeDefaultMessageRouter = nativeDefaultMessageRouterImport<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger, crate::lightning::sign::EntropySource, >;

/// A [`MessageRouter`] that can only route to a directly connected [`Destination`].
///
/// # Privacy
///
/// Creating [`BlindedMessagePath`]s may affect privacy since, if a suitable path cannot be found,
/// it will create a one-hop path using the recipient as the introduction node if it is a announced
/// node. Otherwise, there is no way to find a path to the introduction node in order to send a
/// message, and thus an `Err` is returned.
#[must_use]
#[repr(C)]
pub struct DefaultMessageRouter {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDefaultMessageRouter,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for DefaultMessageRouter {
	type Target = nativeDefaultMessageRouter;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for DefaultMessageRouter { }
unsafe impl core::marker::Sync for DefaultMessageRouter { }
impl Drop for DefaultMessageRouter {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDefaultMessageRouter>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DefaultMessageRouter, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DefaultMessageRouter_free(this_obj: DefaultMessageRouter) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DefaultMessageRouter_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDefaultMessageRouter) };
}
#[allow(unused)]
impl DefaultMessageRouter {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDefaultMessageRouter {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDefaultMessageRouter {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDefaultMessageRouter {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Creates a [`DefaultMessageRouter`] using the given [`NetworkGraph`].
#[must_use]
#[no_mangle]
pub extern "C" fn DefaultMessageRouter_new(network_graph: &crate::lightning::routing::gossip::NetworkGraph, mut entropy_source: crate::lightning::sign::EntropySource) -> crate::lightning::onion_message::messenger::DefaultMessageRouter {
	let mut ret = lightning::onion_message::messenger::DefaultMessageRouter::new(network_graph.get_native_ref(), entropy_source);
	crate::lightning::onion_message::messenger::DefaultMessageRouter { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeDefaultMessageRouter> for crate::lightning::onion_message::messenger::MessageRouter {
	fn from(obj: nativeDefaultMessageRouter) -> Self {
		let rust_obj = crate::lightning::onion_message::messenger::DefaultMessageRouter { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = DefaultMessageRouter_as_MessageRouter(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(DefaultMessageRouter_free_void);
		ret
	}
}
/// Constructs a new MessageRouter which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageRouter must be freed before this_arg is
#[no_mangle]
pub extern "C" fn DefaultMessageRouter_as_MessageRouter(this_arg: &DefaultMessageRouter) -> crate::lightning::onion_message::messenger::MessageRouter {
	crate::lightning::onion_message::messenger::MessageRouter {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		find_path: DefaultMessageRouter_MessageRouter_find_path,
		create_blinded_paths: DefaultMessageRouter_MessageRouter_create_blinded_paths,
		create_compact_blinded_paths: DefaultMessageRouter_MessageRouter_create_compact_blinded_paths,
	}
}

#[must_use]
extern "C" fn DefaultMessageRouter_MessageRouter_find_path(this_arg: *const c_void, mut sender: crate::c_types::PublicKey, mut peers: crate::c_types::derived::CVec_PublicKeyZ, mut destination: crate::lightning::onion_message::messenger::Destination) -> crate::c_types::derived::CResult_OnionMessagePathNoneZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { item.into_rust() }); };
	let mut ret = <nativeDefaultMessageRouter as lightning::onion_message::messenger::MessageRouter>::find_path(unsafe { &mut *(this_arg as *mut nativeDefaultMessageRouter) }, sender.into_rust(), local_peers, destination.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::OnionMessagePath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn DefaultMessageRouter_MessageRouter_create_blinded_paths(this_arg: *const c_void, mut recipient: crate::c_types::PublicKey, mut context: crate::lightning::blinded_path::message::MessageContext, mut peers: crate::c_types::derived::CVec_PublicKeyZ) -> crate::c_types::derived::CResult_CVec_BlindedMessagePathZNoneZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { item.into_rust() }); };
	let mut ret = <nativeDefaultMessageRouter as lightning::onion_message::messenger::MessageRouter>::create_blinded_paths(unsafe { &mut *(this_arg as *mut nativeDefaultMessageRouter) }, recipient.into_rust(), context.into_native(), local_peers, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn DefaultMessageRouter_MessageRouter_create_compact_blinded_paths(this_arg: *const c_void, mut recipient: crate::c_types::PublicKey, mut context: crate::lightning::blinded_path::message::MessageContext, mut peers: crate::c_types::derived::CVec_MessageForwardNodeZ) -> crate::c_types::derived::CResult_CVec_BlindedMessagePathZNoneZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = <nativeDefaultMessageRouter as lightning::onion_message::messenger::MessageRouter>::create_compact_blinded_paths(unsafe { &mut *(this_arg as *mut nativeDefaultMessageRouter) }, recipient.into_rust(), context.into_native(), local_peers, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(item), is_owned: true } }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}


use lightning::onion_message::messenger::OnionMessagePath as nativeOnionMessagePathImport;
pub(crate) type nativeOnionMessagePath = nativeOnionMessagePathImport;

/// A path for sending an [`OnionMessage`].
#[must_use]
#[repr(C)]
pub struct OnionMessagePath {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOnionMessagePath,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for OnionMessagePath {
	type Target = nativeOnionMessagePath;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for OnionMessagePath { }
unsafe impl core::marker::Sync for OnionMessagePath { }
impl Drop for OnionMessagePath {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOnionMessagePath>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OnionMessagePath, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OnionMessagePath_free(this_obj: OnionMessagePath) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OnionMessagePath_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOnionMessagePath) };
}
#[allow(unused)]
impl OnionMessagePath {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOnionMessagePath {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOnionMessagePath {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOnionMessagePath {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Nodes on the path between the sender and the destination.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn OnionMessagePath_get_intermediate_nodes(this_ptr: &OnionMessagePath) -> crate::c_types::derived::CVec_PublicKeyZ {
	let mut inner_val = this_ptr.get_native_mut_ref().intermediate_nodes.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { crate::c_types::PublicKey::from_rust(&item) }); };
	local_inner_val.into()
}
/// Nodes on the path between the sender and the destination.
#[no_mangle]
pub extern "C" fn OnionMessagePath_set_intermediate_nodes(this_ptr: &mut OnionMessagePath, mut val: crate::c_types::derived::CVec_PublicKeyZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_rust() }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.intermediate_nodes = local_val;
}
/// The recipient of the message.
#[no_mangle]
pub extern "C" fn OnionMessagePath_get_destination(this_ptr: &OnionMessagePath) -> crate::lightning::onion_message::messenger::Destination {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().destination;
	crate::lightning::onion_message::messenger::Destination::from_native(inner_val)
}
/// The recipient of the message.
#[no_mangle]
pub extern "C" fn OnionMessagePath_set_destination(this_ptr: &mut OnionMessagePath, mut val: crate::lightning::onion_message::messenger::Destination) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.destination = val.into_native();
}
/// Addresses that may be used to connect to [`OnionMessagePath::first_node`].
///
/// Only needs to be set if a connection to the node is required. [`OnionMessenger`] may use
/// this to initiate such a connection.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn OnionMessagePath_get_first_node_addresses(this_ptr: &OnionMessagePath) -> crate::c_types::derived::COption_CVec_SocketAddressZZ {
	let mut inner_val = this_ptr.get_native_mut_ref().first_node_addresses.clone();
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_CVec_SocketAddressZZ::None } else { crate::c_types::derived::COption_CVec_SocketAddressZZ::Some( { let mut local_inner_val_0 = Vec::new(); for mut item in inner_val.unwrap().drain(..) { local_inner_val_0.push( { crate::lightning::ln::msgs::SocketAddress::native_into(item) }); }; local_inner_val_0.into() }) };
	local_inner_val
}
/// Addresses that may be used to connect to [`OnionMessagePath::first_node`].
///
/// Only needs to be set if a connection to the node is required. [`OnionMessenger`] may use
/// this to initiate such a connection.
#[no_mangle]
pub extern "C" fn OnionMessagePath_set_first_node_addresses(this_ptr: &mut OnionMessagePath, mut val: crate::c_types::derived::COption_CVec_SocketAddressZZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { let mut local_val_0 = Vec::new(); for mut item in { val_opt.take() }.into_rust().drain(..) { local_val_0.push( { item.into_native() }); }; local_val_0 }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.first_node_addresses = local_val;
}
/// Constructs a new OnionMessagePath given each field
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessagePath_new(mut intermediate_nodes_arg: crate::c_types::derived::CVec_PublicKeyZ, mut destination_arg: crate::lightning::onion_message::messenger::Destination, mut first_node_addresses_arg: crate::c_types::derived::COption_CVec_SocketAddressZZ) -> OnionMessagePath {
	let mut local_intermediate_nodes_arg = Vec::new(); for mut item in intermediate_nodes_arg.into_rust().drain(..) { local_intermediate_nodes_arg.push( { item.into_rust() }); };
	let mut local_first_node_addresses_arg = { /*first_node_addresses_arg*/ let first_node_addresses_arg_opt = first_node_addresses_arg; if first_node_addresses_arg_opt.is_none() { None } else { Some({ { let mut local_first_node_addresses_arg_0 = Vec::new(); for mut item in { first_node_addresses_arg_opt.take() }.into_rust().drain(..) { local_first_node_addresses_arg_0.push( { item.into_native() }); }; local_first_node_addresses_arg_0 }})} };
	OnionMessagePath { inner: ObjOps::heap_alloc(nativeOnionMessagePath {
		intermediate_nodes: local_intermediate_nodes_arg,
		destination: destination_arg.into_native(),
		first_node_addresses: local_first_node_addresses_arg,
	}), is_owned: true }
}
impl Clone for OnionMessagePath {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOnionMessagePath>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OnionMessagePath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOnionMessagePath)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OnionMessagePath
pub extern "C" fn OnionMessagePath_clone(orig: &OnionMessagePath) -> OnionMessagePath {
	orig.clone()
}
/// Returns the first node in the path.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessagePath_first_node(this_arg: &crate::lightning::onion_message::messenger::OnionMessagePath) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.first_node();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// The destination of an onion message.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(
		crate::c_types::PublicKey),
	/// We're sending this onion message to a blinded path.
	BlindedPath(
		crate::lightning::blinded_path::message::BlindedMessagePath),
}
use lightning::onion_message::messenger::Destination as DestinationImport;
pub(crate) type nativeDestination = DestinationImport;

impl Destination {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeDestination {
		match self {
			Destination::Node (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeDestination::Node (
					a_nonref.into_rust(),
				)
			},
			Destination::BlindedPath (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeDestination::BlindedPath (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeDestination {
		match self {
			Destination::Node (mut a, ) => {
				nativeDestination::Node (
					a.into_rust(),
				)
			},
			Destination::BlindedPath (mut a, ) => {
				nativeDestination::BlindedPath (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &DestinationImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeDestination) };
		match native {
			nativeDestination::Node (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Destination::Node (
					crate::c_types::PublicKey::from_rust(&a_nonref),
				)
			},
			nativeDestination::BlindedPath (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Destination::BlindedPath (
					crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeDestination) -> Self {
		match native {
			nativeDestination::Node (mut a, ) => {
				Destination::Node (
					crate::c_types::PublicKey::from_rust(&a),
				)
			},
			nativeDestination::BlindedPath (mut a, ) => {
				Destination::BlindedPath (
					crate::lightning::blinded_path::message::BlindedMessagePath { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the Destination
#[no_mangle]
pub extern "C" fn Destination_free(this_ptr: Destination) { }
/// Creates a copy of the Destination
#[no_mangle]
pub extern "C" fn Destination_clone(orig: &Destination) -> Destination {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Destination_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Destination)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Destination_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Destination) };
}
#[no_mangle]
/// Utility method to constructs a new Node-variant Destination
pub extern "C" fn Destination_node(a: crate::c_types::PublicKey) -> Destination {
	Destination::Node(a, )
}
#[no_mangle]
/// Utility method to constructs a new BlindedPath-variant Destination
pub extern "C" fn Destination_blinded_path(a: crate::lightning::blinded_path::message::BlindedMessagePath) -> Destination {
	Destination::BlindedPath(a, )
}
/// Generates a non-cryptographic 64-bit hash of the Destination.
#[no_mangle]
pub extern "C" fn Destination_hash(o: &Destination) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Get a string which allows debug introspection of a Destination object
pub extern "C" fn Destination_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::messenger::Destination }).into()}
/// Checks if two Destinations contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Destination_eq(a: &Destination, b: &Destination) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Attempts to resolve the [`IntroductionNode::DirectedShortChannelId`] of a
/// [`Destination::BlindedPath`] to a [`IntroductionNode::NodeId`], if applicable, using the
/// provided [`ReadOnlyNetworkGraph`].
#[no_mangle]
pub extern "C" fn Destination_resolve(this_arg: &mut crate::lightning::onion_message::messenger::Destination, network_graph: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph) {
	this_arg.to_native().resolve(network_graph.get_native_ref())
}

/// Result of successfully [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SendSuccess {
	/// The message was buffered and will be sent once it is processed by
	/// [`OnionMessageHandler::next_onion_message_for_peer`].
	Buffered,
	/// The message was buffered and will be sent once the node is connected as a peer and it is
	/// processed by [`OnionMessageHandler::next_onion_message_for_peer`].
	BufferedAwaitingConnection(
		crate::c_types::PublicKey),
}
use lightning::onion_message::messenger::SendSuccess as SendSuccessImport;
pub(crate) type nativeSendSuccess = SendSuccessImport;

impl SendSuccess {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSendSuccess {
		match self {
			SendSuccess::Buffered => nativeSendSuccess::Buffered,
			SendSuccess::BufferedAwaitingConnection (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeSendSuccess::BufferedAwaitingConnection (
					a_nonref.into_rust(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSendSuccess {
		match self {
			SendSuccess::Buffered => nativeSendSuccess::Buffered,
			SendSuccess::BufferedAwaitingConnection (mut a, ) => {
				nativeSendSuccess::BufferedAwaitingConnection (
					a.into_rust(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &SendSuccessImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeSendSuccess) };
		match native {
			nativeSendSuccess::Buffered => SendSuccess::Buffered,
			nativeSendSuccess::BufferedAwaitingConnection (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				SendSuccess::BufferedAwaitingConnection (
					crate::c_types::PublicKey::from_rust(&a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSendSuccess) -> Self {
		match native {
			nativeSendSuccess::Buffered => SendSuccess::Buffered,
			nativeSendSuccess::BufferedAwaitingConnection (mut a, ) => {
				SendSuccess::BufferedAwaitingConnection (
					crate::c_types::PublicKey::from_rust(&a),
				)
			},
		}
	}
}
/// Frees any resources used by the SendSuccess
#[no_mangle]
pub extern "C" fn SendSuccess_free(this_ptr: SendSuccess) { }
/// Creates a copy of the SendSuccess
#[no_mangle]
pub extern "C" fn SendSuccess_clone(orig: &SendSuccess) -> SendSuccess {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SendSuccess_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const SendSuccess)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SendSuccess_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut SendSuccess) };
}
#[no_mangle]
/// Utility method to constructs a new Buffered-variant SendSuccess
pub extern "C" fn SendSuccess_buffered() -> SendSuccess {
	SendSuccess::Buffered}
#[no_mangle]
/// Utility method to constructs a new BufferedAwaitingConnection-variant SendSuccess
pub extern "C" fn SendSuccess_buffered_awaiting_connection(a: crate::c_types::PublicKey) -> SendSuccess {
	SendSuccess::BufferedAwaitingConnection(a, )
}
/// Generates a non-cryptographic 64-bit hash of the SendSuccess.
#[no_mangle]
pub extern "C" fn SendSuccess_hash(o: &SendSuccess) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Get a string which allows debug introspection of a SendSuccess object
pub extern "C" fn SendSuccess_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::messenger::SendSuccess }).into()}
/// Checks if two SendSuccesss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SendSuccess_eq(a: &SendSuccess, b: &SendSuccess) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(
		crate::c_types::Secp256k1Error),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
	/// The provided [`Destination`] was an invalid [`BlindedMessagePath`] due to not having any
	/// blinded hops.
	TooFewBlindedHops,
	/// The first hop is not a peer and doesn't have a known [`SocketAddress`].
	InvalidFirstHop(
		crate::c_types::PublicKey),
	/// Indicates that a path could not be found by the [`MessageRouter`].
	///
	/// This occurs when either:
	/// - No path from the sender to the destination was found to send the onion message
	/// - No reply path to the sender could be created when responding to an onion message
	PathNotFound,
	/// Onion message contents must have a TLV type >= 64.
	InvalidMessage,
	/// Our next-hop peer's buffer was full or our total outbound buffer was full.
	BufferFull,
	/// Failed to retrieve our node id from the provided [`NodeSigner`].
	///
	/// [`NodeSigner`]: crate::sign::NodeSigner
	GetNodeIdFailed,
	/// The provided [`Destination`] has a blinded path with an unresolved introduction node. An
	/// attempt to resolve it in the [`MessageRouter`] when finding an [`OnionMessagePath`] likely
	/// failed.
	UnresolvedIntroductionNode,
	/// We attempted to send to a blinded path where we are the introduction node, and failed to
	/// advance the blinded path to make the second hop the new introduction node. Either
	/// [`NodeSigner::ecdh`] failed, we failed to tweak the current blinding point to get the
	/// new blinding point, or we were attempting to send to ourselves.
	BlindedPathAdvanceFailed,
}
use lightning::onion_message::messenger::SendError as SendErrorImport;
pub(crate) type nativeSendError = SendErrorImport;

impl SendError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSendError {
		match self {
			SendError::Secp256k1 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeSendError::Secp256k1 (
					a_nonref.into_rust(),
				)
			},
			SendError::TooBigPacket => nativeSendError::TooBigPacket,
			SendError::TooFewBlindedHops => nativeSendError::TooFewBlindedHops,
			SendError::InvalidFirstHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeSendError::InvalidFirstHop (
					a_nonref.into_rust(),
				)
			},
			SendError::PathNotFound => nativeSendError::PathNotFound,
			SendError::InvalidMessage => nativeSendError::InvalidMessage,
			SendError::BufferFull => nativeSendError::BufferFull,
			SendError::GetNodeIdFailed => nativeSendError::GetNodeIdFailed,
			SendError::UnresolvedIntroductionNode => nativeSendError::UnresolvedIntroductionNode,
			SendError::BlindedPathAdvanceFailed => nativeSendError::BlindedPathAdvanceFailed,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSendError {
		match self {
			SendError::Secp256k1 (mut a, ) => {
				nativeSendError::Secp256k1 (
					a.into_rust(),
				)
			},
			SendError::TooBigPacket => nativeSendError::TooBigPacket,
			SendError::TooFewBlindedHops => nativeSendError::TooFewBlindedHops,
			SendError::InvalidFirstHop (mut a, ) => {
				nativeSendError::InvalidFirstHop (
					a.into_rust(),
				)
			},
			SendError::PathNotFound => nativeSendError::PathNotFound,
			SendError::InvalidMessage => nativeSendError::InvalidMessage,
			SendError::BufferFull => nativeSendError::BufferFull,
			SendError::GetNodeIdFailed => nativeSendError::GetNodeIdFailed,
			SendError::UnresolvedIntroductionNode => nativeSendError::UnresolvedIntroductionNode,
			SendError::BlindedPathAdvanceFailed => nativeSendError::BlindedPathAdvanceFailed,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &SendErrorImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeSendError) };
		match native {
			nativeSendError::Secp256k1 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				SendError::Secp256k1 (
					crate::c_types::Secp256k1Error::from_rust(a_nonref),
				)
			},
			nativeSendError::TooBigPacket => SendError::TooBigPacket,
			nativeSendError::TooFewBlindedHops => SendError::TooFewBlindedHops,
			nativeSendError::InvalidFirstHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				SendError::InvalidFirstHop (
					crate::c_types::PublicKey::from_rust(&a_nonref),
				)
			},
			nativeSendError::PathNotFound => SendError::PathNotFound,
			nativeSendError::InvalidMessage => SendError::InvalidMessage,
			nativeSendError::BufferFull => SendError::BufferFull,
			nativeSendError::GetNodeIdFailed => SendError::GetNodeIdFailed,
			nativeSendError::UnresolvedIntroductionNode => SendError::UnresolvedIntroductionNode,
			nativeSendError::BlindedPathAdvanceFailed => SendError::BlindedPathAdvanceFailed,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSendError) -> Self {
		match native {
			nativeSendError::Secp256k1 (mut a, ) => {
				SendError::Secp256k1 (
					crate::c_types::Secp256k1Error::from_rust(a),
				)
			},
			nativeSendError::TooBigPacket => SendError::TooBigPacket,
			nativeSendError::TooFewBlindedHops => SendError::TooFewBlindedHops,
			nativeSendError::InvalidFirstHop (mut a, ) => {
				SendError::InvalidFirstHop (
					crate::c_types::PublicKey::from_rust(&a),
				)
			},
			nativeSendError::PathNotFound => SendError::PathNotFound,
			nativeSendError::InvalidMessage => SendError::InvalidMessage,
			nativeSendError::BufferFull => SendError::BufferFull,
			nativeSendError::GetNodeIdFailed => SendError::GetNodeIdFailed,
			nativeSendError::UnresolvedIntroductionNode => SendError::UnresolvedIntroductionNode,
			nativeSendError::BlindedPathAdvanceFailed => SendError::BlindedPathAdvanceFailed,
		}
	}
}
/// Frees any resources used by the SendError
#[no_mangle]
pub extern "C" fn SendError_free(this_ptr: SendError) { }
/// Creates a copy of the SendError
#[no_mangle]
pub extern "C" fn SendError_clone(orig: &SendError) -> SendError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SendError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const SendError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SendError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut SendError) };
}
#[no_mangle]
/// Utility method to constructs a new Secp256k1-variant SendError
pub extern "C" fn SendError_secp256k1(a: crate::c_types::Secp256k1Error) -> SendError {
	SendError::Secp256k1(a, )
}
#[no_mangle]
/// Utility method to constructs a new TooBigPacket-variant SendError
pub extern "C" fn SendError_too_big_packet() -> SendError {
	SendError::TooBigPacket}
#[no_mangle]
/// Utility method to constructs a new TooFewBlindedHops-variant SendError
pub extern "C" fn SendError_too_few_blinded_hops() -> SendError {
	SendError::TooFewBlindedHops}
#[no_mangle]
/// Utility method to constructs a new InvalidFirstHop-variant SendError
pub extern "C" fn SendError_invalid_first_hop(a: crate::c_types::PublicKey) -> SendError {
	SendError::InvalidFirstHop(a, )
}
#[no_mangle]
/// Utility method to constructs a new PathNotFound-variant SendError
pub extern "C" fn SendError_path_not_found() -> SendError {
	SendError::PathNotFound}
#[no_mangle]
/// Utility method to constructs a new InvalidMessage-variant SendError
pub extern "C" fn SendError_invalid_message() -> SendError {
	SendError::InvalidMessage}
#[no_mangle]
/// Utility method to constructs a new BufferFull-variant SendError
pub extern "C" fn SendError_buffer_full() -> SendError {
	SendError::BufferFull}
#[no_mangle]
/// Utility method to constructs a new GetNodeIdFailed-variant SendError
pub extern "C" fn SendError_get_node_id_failed() -> SendError {
	SendError::GetNodeIdFailed}
#[no_mangle]
/// Utility method to constructs a new UnresolvedIntroductionNode-variant SendError
pub extern "C" fn SendError_unresolved_introduction_node() -> SendError {
	SendError::UnresolvedIntroductionNode}
#[no_mangle]
/// Utility method to constructs a new BlindedPathAdvanceFailed-variant SendError
pub extern "C" fn SendError_blinded_path_advance_failed() -> SendError {
	SendError::BlindedPathAdvanceFailed}
/// Generates a non-cryptographic 64-bit hash of the SendError.
#[no_mangle]
pub extern "C" fn SendError_hash(o: &SendError) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Get a string which allows debug introspection of a SendError object
pub extern "C" fn SendError_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::messenger::SendError }).into()}
/// Checks if two SendErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SendError_eq(a: &SendError, b: &SendError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Handler for custom onion messages. If you are using [`SimpleArcOnionMessenger`],
/// [`SimpleRefOnionMessenger`], or prefer to ignore inbound custom onion messages,
/// [`IgnoringMessageHandler`] must be provided to [`OnionMessenger::new`]. Otherwise, a custom
/// implementation of this trait must be provided, with [`CustomMessage`] specifying the supported
/// message types.
///
/// See [`OnionMessenger`] for example usage.
///
/// [`IgnoringMessageHandler`]: crate::ln::peer_handler::IgnoringMessageHandler
/// [`CustomMessage`]: Self::CustomMessage
#[repr(C)]
pub struct CustomOnionMessageHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Called with the custom message that was received, returning a response to send, if any.
	///
	/// The returned [`Self::CustomMessage`], if any, is enqueued to be sent by [`OnionMessenger`].
	///
	/// Note that responder (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub handle_custom_message: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::packet::OnionMessageContents, context: crate::c_types::derived::COption_CVec_u8ZZ, responder: crate::lightning::onion_message::messenger::Responder) -> crate::c_types::derived::COption_C2Tuple_OnionMessageContentsResponseInstructionZZ,
	/// Read a custom message of type `message_type` from `buffer`, returning `Ok(None)` if the
	/// message type is unknown.
	pub read_custom_message: extern "C" fn (this_arg: *const c_void, message_type: u64, buffer: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_OnionMessageContentsZDecodeErrorZ,
	/// Releases any [`Self::CustomMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a message flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_custom_message`].
	pub release_pending_custom_messages: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C2Tuple_OnionMessageContentsMessageSendInstructionsZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CustomOnionMessageHandler {}
unsafe impl Sync for CustomOnionMessageHandler {}
#[allow(unused)]
pub(crate) fn CustomOnionMessageHandler_clone_fields(orig: &CustomOnionMessageHandler) -> CustomOnionMessageHandler {
	CustomOnionMessageHandler {
		this_arg: orig.this_arg,
		handle_custom_message: Clone::clone(&orig.handle_custom_message),
		read_custom_message: Clone::clone(&orig.read_custom_message),
		release_pending_custom_messages: Clone::clone(&orig.release_pending_custom_messages),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::messenger::CustomOnionMessageHandler as rustCustomOnionMessageHandler;
impl rustCustomOnionMessageHandler for CustomOnionMessageHandler {
	type CustomMessage = crate::lightning::onion_message::packet::OnionMessageContents;
	fn handle_custom_message(&self, mut message: crate::lightning::onion_message::packet::OnionMessageContents, mut context: Option<Vec<u8>>, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(crate::lightning::onion_message::packet::OnionMessageContents, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_context = if context.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some( { let mut local_context_0 = Vec::new(); for mut item in context.unwrap().drain(..) { local_context_0.push( { item }); }; local_context_0.into() }) };
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.handle_custom_message)(self.this_arg, Into::into(message), local_context, local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (orig_ret_0_0, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn read_custom_message<R:crate::c_types::io::Read>(&self, mut message_type: u64, mut buffer: &mut R) -> Result<Option<crate::lightning::onion_message::packet::OnionMessageContents>, lightning::ln::msgs::DecodeError> {
		let mut ret = (self.read_custom_message)(self.this_arg, message_type, crate::c_types::u8slice::from_vec(&crate::c_types::reader_to_vec(buffer)));
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = { /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ let ret_0_opt = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }); if ret_0_opt.is_none() { None } else { Some({ { { ret_0_opt.take() } }})} }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn release_pending_custom_messages(&self) -> Vec<(crate::lightning::onion_message::packet::OnionMessageContents, lightning::onion_message::messenger::MessageSendInstructions)> {
		let mut ret = (self.release_pending_custom_messages)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_ret_0 = (orig_ret_0_0, orig_ret_0_1.into_native()); local_ret_0 }); };
		local_ret
	}
}

pub struct CustomOnionMessageHandlerRef(CustomOnionMessageHandler);
impl rustCustomOnionMessageHandler for CustomOnionMessageHandlerRef {
	type CustomMessage = crate::lightning::onion_message::packet::OnionMessageContents;
	fn handle_custom_message(&self, mut message: crate::lightning::onion_message::packet::OnionMessageContents, mut context: Option<Vec<u8>>, mut responder: Option<lightning::onion_message::messenger::Responder>) -> Option<(crate::lightning::onion_message::packet::OnionMessageContents, lightning::onion_message::messenger::ResponseInstruction)> {
		let mut local_context = if context.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some( { let mut local_context_0 = Vec::new(); for mut item in context.unwrap().drain(..) { local_context_0.push( { item }); }; local_context_0.into() }) };
		let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
		let mut ret = (self.0.handle_custom_message)(self.0.this_arg, Into::into(message), local_context, local_responder);
		let mut local_ret = if ret.is_some() { Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = ret.take().to_rust(); let mut local_ret_0 = (orig_ret_0_0, *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) }); local_ret_0 }) } else { None };
		local_ret
	}
	fn read_custom_message<R:crate::c_types::io::Read>(&self, mut message_type: u64, mut buffer: &mut R) -> Result<Option<crate::lightning::onion_message::packet::OnionMessageContents>, lightning::ln::msgs::DecodeError> {
		let mut ret = (self.0.read_custom_message)(self.0.this_arg, message_type, crate::c_types::u8slice::from_vec(&crate::c_types::reader_to_vec(buffer)));
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = { /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ let ret_0_opt = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }); if ret_0_opt.is_none() { None } else { Some({ { { ret_0_opt.take() } }})} }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn release_pending_custom_messages(&self) -> Vec<(crate::lightning::onion_message::packet::OnionMessageContents, lightning::onion_message::messenger::MessageSendInstructions)> {
		let mut ret = (self.0.release_pending_custom_messages)(self.0.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_ret_0 = (orig_ret_0_0, orig_ret_0_1.into_native()); local_ret_0 }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for CustomOnionMessageHandler {
	type Target = CustomOnionMessageHandlerRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const CustomOnionMessageHandlerRef) }
	}
}
impl core::ops::DerefMut for CustomOnionMessageHandler {
	fn deref_mut(&mut self) -> &mut CustomOnionMessageHandlerRef {
		unsafe { &mut *(self as *mut _ as *mut CustomOnionMessageHandlerRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn CustomOnionMessageHandler_free(this_ptr: CustomOnionMessageHandler) { }
impl Drop for CustomOnionMessageHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A processed incoming onion message, containing either a Forward (another onion message)
/// or a Receive payload with decrypted contents.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PeeledOnion {
	/// Forwarded onion, with the next node id and a new onion
	Forward(
		crate::lightning::blinded_path::message::NextMessageHop,
		crate::lightning::ln::msgs::OnionMessage),
	/// Received onion message, with decrypted contents, context, and reply path
	Receive(
		crate::lightning::onion_message::packet::ParsedOnionMessageContents,
		crate::c_types::derived::COption_MessageContextZ,
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		crate::lightning::blinded_path::message::BlindedMessagePath),
}
use lightning::onion_message::messenger::PeeledOnion as PeeledOnionImport;
pub(crate) type nativePeeledOnion = PeeledOnionImport<crate::lightning::onion_message::packet::OnionMessageContents, >;

impl PeeledOnion {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePeeledOnion {
		match self {
			PeeledOnion::Forward (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativePeeledOnion::Forward (
					a_nonref.into_native(),
					*unsafe { Box::from_raw(b_nonref.take_inner()) },
				)
			},
			PeeledOnion::Receive (ref a, ref b, ref c, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				let mut local_b_nonref = { /*b_nonref*/ let b_nonref_opt = b_nonref; if b_nonref_opt.is_none() { None } else { Some({ { { b_nonref_opt.take() }.into_native() }})} };
				let mut c_nonref = Clone::clone(c);
				let mut local_c_nonref = if c_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(c_nonref.take_inner()) } }) };
				nativePeeledOnion::Receive (
					a_nonref.into_native(),
					local_b_nonref,
					local_c_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePeeledOnion {
		match self {
			PeeledOnion::Forward (mut a, mut b, ) => {
				nativePeeledOnion::Forward (
					a.into_native(),
					*unsafe { Box::from_raw(b.take_inner()) },
				)
			},
			PeeledOnion::Receive (mut a, mut b, mut c, ) => {
				let mut local_b = { /*b*/ let b_opt = b; if b_opt.is_none() { None } else { Some({ { { b_opt.take() }.into_native() }})} };
				let mut local_c = if c.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(c.take_inner()) } }) };
				nativePeeledOnion::Receive (
					a.into_native(),
					local_b,
					local_c,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &PeeledOnionImport<crate::lightning::onion_message::packet::OnionMessageContents, >) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativePeeledOnion) };
		match native {
			nativePeeledOnion::Forward (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				PeeledOnion::Forward (
					crate::lightning::blinded_path::message::NextMessageHop::native_into(a_nonref),
					crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(b_nonref), is_owned: true },
				)
			},
			nativePeeledOnion::Receive (ref a, ref b, ref c, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				let mut local_b_nonref = if b_nonref.is_none() { crate::c_types::derived::COption_MessageContextZ::None } else { crate::c_types::derived::COption_MessageContextZ::Some( { crate::lightning::blinded_path::message::MessageContext::native_into(b_nonref.unwrap()) }) };
				let mut c_nonref = Clone::clone(c);
				let mut local_c_nonref = crate::lightning::blinded_path::message::BlindedMessagePath { inner: if c_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((c_nonref.unwrap())) } }, is_owned: true };
				PeeledOnion::Receive (
					crate::lightning::onion_message::packet::ParsedOnionMessageContents::native_into(a_nonref),
					local_b_nonref,
					local_c_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePeeledOnion) -> Self {
		match native {
			nativePeeledOnion::Forward (mut a, mut b, ) => {
				PeeledOnion::Forward (
					crate::lightning::blinded_path::message::NextMessageHop::native_into(a),
					crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(b), is_owned: true },
				)
			},
			nativePeeledOnion::Receive (mut a, mut b, mut c, ) => {
				let mut local_b = if b.is_none() { crate::c_types::derived::COption_MessageContextZ::None } else { crate::c_types::derived::COption_MessageContextZ::Some( { crate::lightning::blinded_path::message::MessageContext::native_into(b.unwrap()) }) };
				let mut local_c = crate::lightning::blinded_path::message::BlindedMessagePath { inner: if c.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((c.unwrap())) } }, is_owned: true };
				PeeledOnion::Receive (
					crate::lightning::onion_message::packet::ParsedOnionMessageContents::native_into(a),
					local_b,
					local_c,
				)
			},
		}
	}
}
/// Frees any resources used by the PeeledOnion
#[no_mangle]
pub extern "C" fn PeeledOnion_free(this_ptr: PeeledOnion) { }
/// Creates a copy of the PeeledOnion
#[no_mangle]
pub extern "C" fn PeeledOnion_clone(orig: &PeeledOnion) -> PeeledOnion {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PeeledOnion_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const PeeledOnion)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PeeledOnion_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut PeeledOnion) };
}
#[no_mangle]
/// Utility method to constructs a new Forward-variant PeeledOnion
pub extern "C" fn PeeledOnion_forward(a: crate::lightning::blinded_path::message::NextMessageHop,b: crate::lightning::ln::msgs::OnionMessage) -> PeeledOnion {
	PeeledOnion::Forward(a, b, )
}
#[no_mangle]
/// Utility method to constructs a new Receive-variant PeeledOnion
pub extern "C" fn PeeledOnion_receive(a: crate::lightning::onion_message::packet::ParsedOnionMessageContents,b: crate::c_types::derived::COption_MessageContextZ,c: crate::lightning::blinded_path::message::BlindedMessagePath) -> PeeledOnion {
	PeeledOnion::Receive(a, b, c, )
}
/// Get a string which allows debug introspection of a PeeledOnion object
pub extern "C" fn PeeledOnion_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::onion_message::messenger::PeeledOnion }).into()}
/// Creates an [`OnionMessage`] with the given `contents` for sending to the destination of
/// `path`, first calling [`Destination::resolve`] on `path.destination` with the given
/// [`ReadOnlyNetworkGraph`].
///
/// Returns the node id of the peer to send the message to, the message itself, and any addresses
/// needed to connect to the first node.
///
/// Note that reply_path (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn create_onion_message_resolving_destination(entropy_source: &crate::lightning::sign::EntropySource, node_signer: &crate::lightning::sign::NodeSigner, node_id_lookup: &crate::lightning::blinded_path::NodeIdLookUp, network_graph: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph, mut path: crate::lightning::onion_message::messenger::OnionMessagePath, mut contents: crate::lightning::onion_message::packet::OnionMessageContents, mut reply_path: crate::lightning::blinded_path::message::BlindedMessagePath) -> crate::c_types::derived::CResult_C3Tuple_PublicKeyOnionMessageCOption_CVec_SocketAddressZZZSendErrorZ {
	let mut local_reply_path = if reply_path.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(reply_path.take_inner()) } }) };
	let mut ret = lightning::onion_message::messenger::create_onion_message_resolving_destination::<crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::blinded_path::NodeIdLookUp, crate::lightning::onion_message::packet::OnionMessageContents, >(entropy_source, node_signer, node_id_lookup, network_graph.get_native_ref(), secp256k1::global::SECP256K1, *unsafe { Box::from_raw(path.take_inner()) }, contents, local_reply_path);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = o; let mut local_orig_ret_0_2 = if orig_ret_0_2.is_none() { crate::c_types::derived::COption_CVec_SocketAddressZZ::None } else { crate::c_types::derived::COption_CVec_SocketAddressZZ::Some( { let mut local_orig_ret_0_2_0 = Vec::new(); for mut item in orig_ret_0_2.unwrap().drain(..) { local_orig_ret_0_2_0.push( { crate::lightning::ln::msgs::SocketAddress::native_into(item) }); }; local_orig_ret_0_2_0.into() }) }; let mut local_ret_0 = (crate::c_types::PublicKey::from_rust(&orig_ret_0_0), crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }, local_orig_ret_0_2).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

/// Creates an [`OnionMessage`] with the given `contents` for sending to the destination of
/// `path`.
///
/// Returns the node id of the peer to send the message to, the message itself, and any addresses
/// needed to connect to the first node.
///
/// Returns [`SendError::UnresolvedIntroductionNode`] if:
/// - `destination` contains a blinded path with an [`IntroductionNode::DirectedShortChannelId`],
/// - unless it can be resolved by [`NodeIdLookUp::next_node_id`].
/// Use [`create_onion_message_resolving_destination`] instead to resolve the introduction node
/// first with a [`ReadOnlyNetworkGraph`].
///
/// Note that reply_path (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn create_onion_message(entropy_source: &crate::lightning::sign::EntropySource, node_signer: &crate::lightning::sign::NodeSigner, node_id_lookup: &crate::lightning::blinded_path::NodeIdLookUp, mut path: crate::lightning::onion_message::messenger::OnionMessagePath, mut contents: crate::lightning::onion_message::packet::OnionMessageContents, mut reply_path: crate::lightning::blinded_path::message::BlindedMessagePath) -> crate::c_types::derived::CResult_C3Tuple_PublicKeyOnionMessageCOption_CVec_SocketAddressZZZSendErrorZ {
	let mut local_reply_path = if reply_path.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(reply_path.take_inner()) } }) };
	let mut ret = lightning::onion_message::messenger::create_onion_message::<crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::blinded_path::NodeIdLookUp, crate::lightning::onion_message::packet::OnionMessageContents, >(entropy_source, node_signer, node_id_lookup, secp256k1::global::SECP256K1, *unsafe { Box::from_raw(path.take_inner()) }, contents, local_reply_path);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = o; let mut local_orig_ret_0_2 = if orig_ret_0_2.is_none() { crate::c_types::derived::COption_CVec_SocketAddressZZ::None } else { crate::c_types::derived::COption_CVec_SocketAddressZZ::Some( { let mut local_orig_ret_0_2_0 = Vec::new(); for mut item in orig_ret_0_2.unwrap().drain(..) { local_orig_ret_0_2_0.push( { crate::lightning::ln::msgs::SocketAddress::native_into(item) }); }; local_orig_ret_0_2_0.into() }) }; let mut local_ret_0 = (crate::c_types::PublicKey::from_rust(&orig_ret_0_0), crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }, local_orig_ret_0_2).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

/// Decode one layer of an incoming [`OnionMessage`].
///
/// Returns either the next layer of the onion for forwarding or the decrypted content for the
/// receiver.
#[no_mangle]
pub extern "C" fn peel_onion_message(msg: &crate::lightning::ln::msgs::OnionMessage, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut custom_handler: crate::lightning::onion_message::messenger::CustomOnionMessageHandler) -> crate::c_types::derived::CResult_PeeledOnionNoneZ {
	let mut ret = lightning::onion_message::messenger::peel_onion_message::<crate::lightning::sign::NodeSigner, crate::lightning::util::logger::Logger, crate::lightning::onion_message::messenger::CustomOnionMessageHandler, >(msg.get_native_ref(), secp256k1::global::SECP256K1, node_signer, logger, custom_handler);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::PeeledOnion::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
/// their respective handlers.
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_new(mut entropy_source: crate::lightning::sign::EntropySource, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut node_id_lookup: crate::lightning::blinded_path::NodeIdLookUp, mut message_router: crate::lightning::onion_message::messenger::MessageRouter, mut offers_handler: crate::lightning::onion_message::offers::OffersMessageHandler, mut async_payments_handler: crate::lightning::onion_message::async_payments::AsyncPaymentsMessageHandler, mut dns_resolver: crate::lightning::onion_message::dns_resolution::DNSResolverMessageHandler, mut custom_handler: crate::lightning::onion_message::messenger::CustomOnionMessageHandler) -> crate::lightning::onion_message::messenger::OnionMessenger {
	let mut ret = lightning::onion_message::messenger::OnionMessenger::new(entropy_source, node_signer, logger, node_id_lookup, message_router, offers_handler, async_payments_handler, dns_resolver, custom_handler);
	crate::lightning::onion_message::messenger::OnionMessenger { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Similar to [`Self::new`], but rather than dropping onion messages that are
/// intended to be forwarded to offline peers, we will intercept them for
/// later forwarding.
///
/// Interception flow:
/// 1. If an onion message for an offline peer is received, `OnionMessenger` will
///    generate an [`Event::OnionMessageIntercepted`]. Event handlers can
///    then choose to persist this onion message for later forwarding, or drop
///    it.
/// 2. When the offline peer later comes back online, `OnionMessenger` will
///    generate an [`Event::OnionMessagePeerConnected`]. Event handlers will
///    then fetch all previously intercepted onion messages for this peer.
/// 3. Once the stored onion messages are fetched, they can finally be
///    forwarded to the now-online peer via [`Self::forward_onion_message`].
///
/// # Note
///
/// LDK will not rate limit how many [`Event::OnionMessageIntercepted`]s
/// are generated, so it is the caller's responsibility to limit how many
/// onion messages are persisted and only persist onion messages for relevant
/// peers.
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_new_with_offline_peer_interception(mut entropy_source: crate::lightning::sign::EntropySource, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut node_id_lookup: crate::lightning::blinded_path::NodeIdLookUp, mut message_router: crate::lightning::onion_message::messenger::MessageRouter, mut offers_handler: crate::lightning::onion_message::offers::OffersMessageHandler, mut async_payments_handler: crate::lightning::onion_message::async_payments::AsyncPaymentsMessageHandler, mut dns_resolver: crate::lightning::onion_message::dns_resolution::DNSResolverMessageHandler, mut custom_handler: crate::lightning::onion_message::messenger::CustomOnionMessageHandler) -> crate::lightning::onion_message::messenger::OnionMessenger {
	let mut ret = lightning::onion_message::messenger::OnionMessenger::new_with_offline_peer_interception(entropy_source, node_signer, logger, node_id_lookup, message_router, offers_handler, async_payments_handler, dns_resolver, custom_handler);
	crate::lightning::onion_message::messenger::OnionMessenger { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Sends an [`OnionMessage`] based on its [`MessageSendInstructions`].
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_send_onion_message(this_arg: &crate::lightning::onion_message::messenger::OnionMessenger, mut contents: crate::lightning::onion_message::packet::OnionMessageContents, mut instructions: crate::lightning::onion_message::messenger::MessageSendInstructions) -> crate::c_types::derived::CResult_SendSuccessSendErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.send_onion_message(contents, instructions.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::SendSuccess::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

/// Forwards an [`OnionMessage`] to `peer_node_id`. Useful if we initialized
/// the [`OnionMessenger`] with [`Self::new_with_offline_peer_interception`]
/// and want to forward a previously intercepted onion message to a peer that
/// has just come online.
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_forward_onion_message(this_arg: &crate::lightning::onion_message::messenger::OnionMessenger, mut message: crate::lightning::ln::msgs::OnionMessage, mut peer_node_id: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_NoneSendErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.forward_onion_message(*unsafe { Box::from_raw(message.take_inner()) }, &peer_node_id.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

/// Handles the response to an [`OnionMessage`] based on its [`ResponseInstruction`],
/// enqueueing any response for sending.
///
/// This function is useful for asynchronous handling of [`OnionMessage`]s.
/// Handlers have the option to return `None`, indicating that no immediate response should be
/// sent. Then, they can transfer the associated [`Responder`] to another task responsible for
/// generating the response asynchronously. Subsequently, when the response is prepared and
/// ready for sending, that task can invoke this method to enqueue the response for delivery.
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_handle_onion_message_response(this_arg: &crate::lightning::onion_message::messenger::OnionMessenger, mut response: crate::lightning::onion_message::packet::OnionMessageContents, mut instructions: crate::lightning::onion_message::messenger::ResponseInstruction) -> crate::c_types::derived::CResult_SendSuccessSendErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_onion_message_response(response, *unsafe { Box::from_raw(instructions.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::SendSuccess::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

/// Gets a [`Future`] that completes when an event is available via
/// [`EventsProvider::process_pending_events`] or [`Self::process_pending_events_async`].
///
/// Note that callbacks registered on the [`Future`] MUST NOT call back into this
/// [`OnionMessenger`] and should instead register actions to be taken later.
///
/// [`EventsProvider::process_pending_events`]: crate::events::EventsProvider::process_pending_events
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_get_update_future(this_arg: &crate::lightning::onion_message::messenger::OnionMessenger) -> crate::lightning::util::wakers::Future {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_update_future();
	crate::lightning::util::wakers::Future { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeOnionMessenger> for crate::lightning::events::EventsProvider {
	fn from(obj: nativeOnionMessenger) -> Self {
		let rust_obj = crate::lightning::onion_message::messenger::OnionMessenger { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OnionMessenger_as_EventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(OnionMessenger_free_void);
		ret
	}
}
/// Constructs a new EventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn OnionMessenger_as_EventsProvider(this_arg: &OnionMessenger) -> crate::lightning::events::EventsProvider {
	crate::lightning::events::EventsProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		process_pending_events: OnionMessenger_EventsProvider_process_pending_events,
	}
}

extern "C" fn OnionMessenger_EventsProvider_process_pending_events(this_arg: *const c_void, mut handler: crate::lightning::events::EventHandler) {
	<nativeOnionMessenger as lightning::events::EventsProvider>::process_pending_events(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, handler)
}

impl From<nativeOnionMessenger> for crate::lightning::ln::msgs::OnionMessageHandler {
	fn from(obj: nativeOnionMessenger) -> Self {
		let rust_obj = crate::lightning::onion_message::messenger::OnionMessenger { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OnionMessenger_as_OnionMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(OnionMessenger_free_void);
		ret
	}
}
/// Constructs a new OnionMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn OnionMessenger_as_OnionMessageHandler(this_arg: &OnionMessenger) -> crate::lightning::ln::msgs::OnionMessageHandler {
	crate::lightning::ln::msgs::OnionMessageHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_onion_message: OnionMessenger_OnionMessageHandler_handle_onion_message,
		next_onion_message_for_peer: OnionMessenger_OnionMessageHandler_next_onion_message_for_peer,
		peer_connected: OnionMessenger_OnionMessageHandler_peer_connected,
		peer_disconnected: OnionMessenger_OnionMessageHandler_peer_disconnected,
		timer_tick_occurred: OnionMessenger_OnionMessageHandler_timer_tick_occurred,
		provided_node_features: OnionMessenger_OnionMessageHandler_provided_node_features,
		provided_init_features: OnionMessenger_OnionMessageHandler_provided_init_features,
	}
}

extern "C" fn OnionMessenger_OnionMessageHandler_handle_onion_message(this_arg: *const c_void, mut peer_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::OnionMessage) {
	<nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler>::handle_onion_message(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, peer_node_id.into_rust(), msg.get_native_ref())
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_next_onion_message_for_peer(this_arg: *const c_void, mut peer_node_id: crate::c_types::PublicKey) -> crate::lightning::ln::msgs::OnionMessage {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler>::next_onion_message_for_peer(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, peer_node_id.into_rust());
	let mut local_ret = crate::lightning::ln::msgs::OnionMessage { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_peer_connected(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, init: &crate::lightning::ln::msgs::Init, mut inbound: bool) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler>::peer_connected(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, their_node_id.into_rust(), init.get_native_ref(), inbound);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
extern "C" fn OnionMessenger_OnionMessageHandler_peer_disconnected(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey) {
	<nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler>::peer_disconnected(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, their_node_id.into_rust())
}
extern "C" fn OnionMessenger_OnionMessageHandler_timer_tick_occurred(this_arg: *const c_void) {
	<nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler>::timer_tick_occurred(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, )
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_provided_node_features(this_arg: *const c_void) -> crate::lightning_types::features::NodeFeatures {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler>::provided_node_features(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, );
	crate::lightning_types::features::NodeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_provided_init_features(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey) -> crate::lightning_types::features::InitFeatures {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler>::provided_init_features(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, their_node_id.into_rust());
	crate::lightning_types::features::InitFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

