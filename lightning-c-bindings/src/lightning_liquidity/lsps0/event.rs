// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Contains bLIP-50 / LSPS0 event types.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An event which an bLIP-50 / LSPS0 client may want to take some action in response to.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum LSPS0ClientEvent {
	/// Information from the LSP about the protocols they support.
	ListProtocolsResponse {
		/// The node id of the LSP.
		counterparty_node_id: crate::c_types::PublicKey,
		/// A list of supported protocols.
		protocols: crate::c_types::derived::CVec_u16Z,
	},
}
use lightning_liquidity::lsps0::event::LSPS0ClientEvent as LSPS0ClientEventImport;
pub(crate) type nativeLSPS0ClientEvent = LSPS0ClientEventImport;

impl LSPS0ClientEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLSPS0ClientEvent {
		match self {
			LSPS0ClientEvent::ListProtocolsResponse {ref counterparty_node_id, ref protocols, } => {
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut protocols_nonref = Clone::clone(protocols);
				let mut local_protocols_nonref = Vec::new(); for mut item in protocols_nonref.into_rust().drain(..) { local_protocols_nonref.push( { item }); };
				nativeLSPS0ClientEvent::ListProtocolsResponse {
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					protocols: local_protocols_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLSPS0ClientEvent {
		match self {
			LSPS0ClientEvent::ListProtocolsResponse {mut counterparty_node_id, mut protocols, } => {
				let mut local_protocols = Vec::new(); for mut item in protocols.into_rust().drain(..) { local_protocols.push( { item }); };
				nativeLSPS0ClientEvent::ListProtocolsResponse {
					counterparty_node_id: counterparty_node_id.into_rust(),
					protocols: local_protocols,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LSPS0ClientEventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLSPS0ClientEvent) };
		match native {
			nativeLSPS0ClientEvent::ListProtocolsResponse {ref counterparty_node_id, ref protocols, } => {
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut protocols_nonref = Clone::clone(protocols);
				let mut local_protocols_nonref = Vec::new(); for mut item in protocols_nonref.drain(..) { local_protocols_nonref.push( { item }); };
				LSPS0ClientEvent::ListProtocolsResponse {
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					protocols: local_protocols_nonref.into(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLSPS0ClientEvent) -> Self {
		match native {
			nativeLSPS0ClientEvent::ListProtocolsResponse {mut counterparty_node_id, mut protocols, } => {
				let mut local_protocols = Vec::new(); for mut item in protocols.drain(..) { local_protocols.push( { item }); };
				LSPS0ClientEvent::ListProtocolsResponse {
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					protocols: local_protocols.into(),
				}
			},
		}
	}
}
/// Frees any resources used by the LSPS0ClientEvent
#[no_mangle]
pub extern "C" fn LSPS0ClientEvent_free(this_ptr: LSPS0ClientEvent) { }
/// Creates a copy of the LSPS0ClientEvent
#[no_mangle]
pub extern "C" fn LSPS0ClientEvent_clone(orig: &LSPS0ClientEvent) -> LSPS0ClientEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ClientEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const LSPS0ClientEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LSPS0ClientEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut LSPS0ClientEvent) };
}
#[no_mangle]
/// Utility method to constructs a new ListProtocolsResponse-variant LSPS0ClientEvent
pub extern "C" fn LSPS0ClientEvent_list_protocols_response(counterparty_node_id: crate::c_types::PublicKey, protocols: crate::c_types::derived::CVec_u16Z) -> LSPS0ClientEvent {
	LSPS0ClientEvent::ListProtocolsResponse {
		counterparty_node_id,
		protocols,
	}
}
/// Get a string which allows debug introspection of a LSPS0ClientEvent object
pub extern "C" fn LSPS0ClientEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_liquidity::lsps0::event::LSPS0ClientEvent }).into()}
/// Checks if two LSPS0ClientEvents contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn LSPS0ClientEvent_eq(a: &LSPS0ClientEvent, b: &LSPS0ClientEvent) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
