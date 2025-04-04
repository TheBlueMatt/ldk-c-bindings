// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Holds types and traits used to implement message queues for [`LSPSMessage`]s.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_liquidity::message_queue::MessageQueue as nativeMessageQueueImport;
pub(crate) type nativeMessageQueue = nativeMessageQueueImport;

/// The default [`MessageQueue`] Implementation used by [`LiquidityManager`].
///
/// [`LiquidityManager`]: crate::LiquidityManager
#[must_use]
#[repr(C)]
pub struct MessageQueue {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMessageQueue,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for MessageQueue {
	type Target = nativeMessageQueue;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for MessageQueue { }
unsafe impl core::marker::Sync for MessageQueue { }
impl Drop for MessageQueue {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMessageQueue>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MessageQueue, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MessageQueue_free(this_obj: MessageQueue) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageQueue_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMessageQueue) };
}
#[allow(unused)]
impl MessageQueue {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMessageQueue {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMessageQueue {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMessageQueue {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// A callback which will be called to trigger network message processing.
///
/// Usually, this should call [`PeerManager::process_events`].
///
/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
#[repr(C)]
pub struct ProcessMessagesCallback {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// The method which is called.
	pub call: extern "C" fn (this_arg: *const c_void),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for ProcessMessagesCallback {}
unsafe impl Sync for ProcessMessagesCallback {}
#[allow(unused)]
pub(crate) fn ProcessMessagesCallback_clone_fields(orig: &ProcessMessagesCallback) -> ProcessMessagesCallback {
	ProcessMessagesCallback {
		this_arg: orig.this_arg,
		call: Clone::clone(&orig.call),
		free: Clone::clone(&orig.free),
	}
}

use lightning_liquidity::message_queue::ProcessMessagesCallback as rustProcessMessagesCallback;
impl rustProcessMessagesCallback for ProcessMessagesCallback {
	fn call(&self) {
		(self.call)(self.this_arg)
	}
}

pub struct ProcessMessagesCallbackRef(ProcessMessagesCallback);
impl rustProcessMessagesCallback for ProcessMessagesCallbackRef {
	fn call(&self) {
		(self.0.call)(self.0.this_arg)
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for ProcessMessagesCallback {
	type Target = ProcessMessagesCallbackRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const ProcessMessagesCallbackRef) }
	}
}
impl core::ops::DerefMut for ProcessMessagesCallback {
	fn deref_mut(&mut self) -> &mut ProcessMessagesCallbackRef {
		unsafe { &mut *(self as *mut _ as *mut ProcessMessagesCallbackRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ProcessMessagesCallback_free(this_ptr: ProcessMessagesCallback) { }
impl Drop for ProcessMessagesCallback {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
