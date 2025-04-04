// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Events are surfaced by the library to indicate some action must be taken
//! by the end-user.
//!
//! Because we don't have a built-in runtime, it's up to the end-user to poll
//! [`LiquidityManager::get_and_clear_pending_events`] to receive events.
//!
//! [`LiquidityManager::get_and_clear_pending_events`]: crate::LiquidityManager::get_and_clear_pending_events

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// The maximum queue size we allow before starting to drop events.

#[no_mangle]
pub static MAX_EVENT_QUEUE_SIZE: usize = lightning_liquidity::events::MAX_EVENT_QUEUE_SIZE;
/// An event which you should probably take some action in response to.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LiquidityEvent {
	/// An LSPS0 client event.
	LSPS0Client(
		crate::lightning_liquidity::lsps0::event::LSPS0ClientEvent),
	/// An LSPS1 (Channel Request) client event.
	LSPS1Client(
		crate::lightning_liquidity::lsps1::event::LSPS1ClientEvent),
	/// An LSPS2 (JIT Channel) client event.
	LSPS2Client(
		crate::lightning_liquidity::lsps2::event::LSPS2ClientEvent),
	/// An LSPS2 (JIT Channel) server event.
	LSPS2Service(
		crate::lightning_liquidity::lsps2::event::LSPS2ServiceEvent),
}
use lightning_liquidity::events::LiquidityEvent as LiquidityEventImport;
pub(crate) type nativeLiquidityEvent = LiquidityEventImport;

impl LiquidityEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLiquidityEvent {
		match self {
			LiquidityEvent::LSPS0Client (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLiquidityEvent::LSPS0Client (
					a_nonref.into_native(),
				)
			},
			LiquidityEvent::LSPS1Client (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLiquidityEvent::LSPS1Client (
					a_nonref.into_native(),
				)
			},
			LiquidityEvent::LSPS2Client (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLiquidityEvent::LSPS2Client (
					a_nonref.into_native(),
				)
			},
			LiquidityEvent::LSPS2Service (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeLiquidityEvent::LSPS2Service (
					a_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLiquidityEvent {
		match self {
			LiquidityEvent::LSPS0Client (mut a, ) => {
				nativeLiquidityEvent::LSPS0Client (
					a.into_native(),
				)
			},
			LiquidityEvent::LSPS1Client (mut a, ) => {
				nativeLiquidityEvent::LSPS1Client (
					a.into_native(),
				)
			},
			LiquidityEvent::LSPS2Client (mut a, ) => {
				nativeLiquidityEvent::LSPS2Client (
					a.into_native(),
				)
			},
			LiquidityEvent::LSPS2Service (mut a, ) => {
				nativeLiquidityEvent::LSPS2Service (
					a.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LiquidityEventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLiquidityEvent) };
		match native {
			nativeLiquidityEvent::LSPS0Client (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LiquidityEvent::LSPS0Client (
					crate::lightning_liquidity::lsps0::event::LSPS0ClientEvent::native_into(a_nonref),
				)
			},
			nativeLiquidityEvent::LSPS1Client (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LiquidityEvent::LSPS1Client (
					crate::lightning_liquidity::lsps1::event::LSPS1ClientEvent::native_into(a_nonref),
				)
			},
			nativeLiquidityEvent::LSPS2Client (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LiquidityEvent::LSPS2Client (
					crate::lightning_liquidity::lsps2::event::LSPS2ClientEvent::native_into(a_nonref),
				)
			},
			nativeLiquidityEvent::LSPS2Service (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				LiquidityEvent::LSPS2Service (
					crate::lightning_liquidity::lsps2::event::LSPS2ServiceEvent::native_into(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLiquidityEvent) -> Self {
		match native {
			nativeLiquidityEvent::LSPS0Client (mut a, ) => {
				LiquidityEvent::LSPS0Client (
					crate::lightning_liquidity::lsps0::event::LSPS0ClientEvent::native_into(a),
				)
			},
			nativeLiquidityEvent::LSPS1Client (mut a, ) => {
				LiquidityEvent::LSPS1Client (
					crate::lightning_liquidity::lsps1::event::LSPS1ClientEvent::native_into(a),
				)
			},
			nativeLiquidityEvent::LSPS2Client (mut a, ) => {
				LiquidityEvent::LSPS2Client (
					crate::lightning_liquidity::lsps2::event::LSPS2ClientEvent::native_into(a),
				)
			},
			nativeLiquidityEvent::LSPS2Service (mut a, ) => {
				LiquidityEvent::LSPS2Service (
					crate::lightning_liquidity::lsps2::event::LSPS2ServiceEvent::native_into(a),
				)
			},
		}
	}
}
/// Frees any resources used by the LiquidityEvent
#[no_mangle]
pub extern "C" fn LiquidityEvent_free(this_ptr: LiquidityEvent) { }
/// Creates a copy of the LiquidityEvent
#[no_mangle]
pub extern "C" fn LiquidityEvent_clone(orig: &LiquidityEvent) -> LiquidityEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LiquidityEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LiquidityEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LiquidityEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LiquidityEvent) };
}
#[no_mangle]
/// Utility method to constructs a new LSPS0Client-variant LiquidityEvent
pub extern "C" fn LiquidityEvent_lsps0_client(a: crate::lightning_liquidity::lsps0::event::LSPS0ClientEvent) -> LiquidityEvent {
	LiquidityEvent::LSPS0Client(a, )
}
#[no_mangle]
/// Utility method to constructs a new LSPS1Client-variant LiquidityEvent
pub extern "C" fn LiquidityEvent_lsps1_client(a: crate::lightning_liquidity::lsps1::event::LSPS1ClientEvent) -> LiquidityEvent {
	LiquidityEvent::LSPS1Client(a, )
}
#[no_mangle]
/// Utility method to constructs a new LSPS2Client-variant LiquidityEvent
pub extern "C" fn LiquidityEvent_lsps2_client(a: crate::lightning_liquidity::lsps2::event::LSPS2ClientEvent) -> LiquidityEvent {
	LiquidityEvent::LSPS2Client(a, )
}
#[no_mangle]
/// Utility method to constructs a new LSPS2Service-variant LiquidityEvent
pub extern "C" fn LiquidityEvent_lsps2_service(a: crate::lightning_liquidity::lsps2::event::LSPS2ServiceEvent) -> LiquidityEvent {
	LiquidityEvent::LSPS2Service(a, )
}
/// Get a string which allows debug introspection of a LiquidityEvent object
pub extern "C" fn LiquidityEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::events::LiquidityEvent }).into()}
/// Checks if two LiquidityEvents contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LiquidityEvent_eq(a: &LiquidityEvent, b: &LiquidityEvent) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
