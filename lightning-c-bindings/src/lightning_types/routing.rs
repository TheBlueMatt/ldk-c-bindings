// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Various types which describe routes or information about partial routes within the lightning
//! network.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_types::routing::RoutingFees as nativeRoutingFeesImport;
pub(crate) type nativeRoutingFees = nativeRoutingFeesImport;

/// Fees for routing via a given channel or a node
#[must_use]
#[repr(C)]
pub struct RoutingFees {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRoutingFees,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for RoutingFees {
	type Target = nativeRoutingFees;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for RoutingFees { }
unsafe impl core::marker::Sync for RoutingFees { }
impl Drop for RoutingFees {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRoutingFees>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RoutingFees, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RoutingFees_free(this_obj: RoutingFees) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RoutingFees_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRoutingFees) };
}
#[allow(unused)]
impl RoutingFees {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRoutingFees {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRoutingFees {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRoutingFees {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Flat routing fee in millisatoshis.
#[no_mangle]
pub extern "C" fn RoutingFees_get_base_msat(this_ptr: &RoutingFees) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_msat;
	*inner_val
}
/// Flat routing fee in millisatoshis.
#[no_mangle]
pub extern "C" fn RoutingFees_set_base_msat(this_ptr: &mut RoutingFees, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_msat = val;
}
/// Liquidity-based routing fee in millionths of a routed amount.
/// In other words, 10000 is 1%.
#[no_mangle]
pub extern "C" fn RoutingFees_get_proportional_millionths(this_ptr: &RoutingFees) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().proportional_millionths;
	*inner_val
}
/// Liquidity-based routing fee in millionths of a routed amount.
/// In other words, 10000 is 1%.
#[no_mangle]
pub extern "C" fn RoutingFees_set_proportional_millionths(this_ptr: &mut RoutingFees, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.proportional_millionths = val;
}
/// Constructs a new RoutingFees given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RoutingFees_new(mut base_msat_arg: u32, mut proportional_millionths_arg: u32) -> RoutingFees {
	RoutingFees { inner: ObjOps::heap_alloc(nativeRoutingFees {
		base_msat: base_msat_arg,
		proportional_millionths: proportional_millionths_arg,
	}), is_owned: true }
}
/// Checks if two RoutingFeess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RoutingFees_eq(a: &RoutingFees, b: &RoutingFees) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for RoutingFees {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRoutingFees>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RoutingFees_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRoutingFees)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RoutingFees
pub extern "C" fn RoutingFees_clone(orig: &RoutingFees) -> RoutingFees {
	orig.clone()
}
/// Get a string which allows debug introspection of a RoutingFees object
pub extern "C" fn RoutingFees_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_types::routing::RoutingFees }).into()}
/// Generates a non-cryptographic 64-bit hash of the RoutingFees.
#[no_mangle]
pub extern "C" fn RoutingFees_hash(o: &RoutingFees) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning_types::routing::RouteHint as nativeRouteHintImport;
pub(crate) type nativeRouteHint = nativeRouteHintImport;

/// A list of hops along a payment path terminating with a channel to the recipient.
#[must_use]
#[repr(C)]
pub struct RouteHint {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHint,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for RouteHint {
	type Target = nativeRouteHint;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for RouteHint { }
unsafe impl core::marker::Sync for RouteHint { }
impl Drop for RouteHint {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHint>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteHint, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHint_free(this_obj: RouteHint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHint_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRouteHint) };
}
#[allow(unused)]
impl RouteHint {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHint {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHint {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHint {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
#[no_mangle]
pub extern "C" fn RouteHint_get_a(this_ptr: &RouteHint) -> crate::c_types::derived::CVec_RouteHintHopZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning_types::routing::RouteHintHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning_types::routing::RouteHintHop<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
#[no_mangle]
pub extern "C" fn RouteHint_set_a(this_ptr: &mut RouteHint, mut val: crate::c_types::derived::CVec_RouteHintHopZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = local_val;
}
/// Constructs a new RouteHint given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHint_new(mut a_arg: crate::c_types::derived::CVec_RouteHintHopZ) -> RouteHint {
	let mut local_a_arg = Vec::new(); for mut item in a_arg.into_rust().drain(..) { local_a_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	RouteHint { inner: ObjOps::heap_alloc(lightning_types::routing::RouteHint (
		local_a_arg,
	)), is_owned: true }
}
impl Clone for RouteHint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHint>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRouteHint)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHint
pub extern "C" fn RouteHint_clone(orig: &RouteHint) -> RouteHint {
	orig.clone()
}
/// Get a string which allows debug introspection of a RouteHint object
pub extern "C" fn RouteHint_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_types::routing::RouteHint }).into()}
/// Generates a non-cryptographic 64-bit hash of the RouteHint.
#[no_mangle]
pub extern "C" fn RouteHint_hash(o: &RouteHint) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHint_eq(a: &RouteHint, b: &RouteHint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_types::routing::RouteHintHop as nativeRouteHintHopImport;
pub(crate) type nativeRouteHintHop = nativeRouteHintHopImport;

/// A channel descriptor for a hop along a payment path.
///
/// While this generally comes from BOLT 11's `r` field, this struct includes more fields than are
/// available in BOLT 11. Thus, encoding and decoding this via `lightning-invoice` is lossy, as
/// fields not supported in BOLT 11 will be stripped.
#[must_use]
#[repr(C)]
pub struct RouteHintHop {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHintHop,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for RouteHintHop {
	type Target = nativeRouteHintHop;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for RouteHintHop { }
unsafe impl core::marker::Sync for RouteHintHop { }
impl Drop for RouteHintHop {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHintHop>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteHintHop, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHintHop_free(this_obj: RouteHintHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHintHop_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRouteHintHop) };
}
#[allow(unused)]
impl RouteHintHop {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHintHop {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHintHop {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHintHop {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHintHop_get_src_node_id(this_ptr: &RouteHintHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().src_node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHintHop_set_src_node_id(this_ptr: &mut RouteHintHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.src_node_id = val.into_rust();
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_get_short_channel_id(this_ptr: &RouteHintHop) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_set_short_channel_id(this_ptr: &mut RouteHintHop, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_get_fees(this_ptr: &RouteHintHop) -> crate::lightning_types::routing::RoutingFees {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fees;
	crate::lightning_types::routing::RoutingFees { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_types::routing::RoutingFees<>) as *mut _) }, is_owned: false }
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_set_fees(this_ptr: &mut RouteHintHop, mut val: crate::lightning_types::routing::RoutingFees) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fees = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_cltv_expiry_delta(this_ptr: &RouteHintHop) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_cltv_expiry_delta(this_ptr: &mut RouteHintHop, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_htlc_minimum_msat(this_ptr: &RouteHintHop) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_htlc_minimum_msat(this_ptr: &mut RouteHintHop, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = local_val;
}
/// The maximum value in msat available for routing with a single HTLC.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_htlc_maximum_msat(this_ptr: &RouteHintHop) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The maximum value in msat available for routing with a single HTLC.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_htlc_maximum_msat(this_ptr: &mut RouteHintHop, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = local_val;
}
/// Constructs a new RouteHintHop given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHintHop_new(mut src_node_id_arg: crate::c_types::PublicKey, mut short_channel_id_arg: u64, mut fees_arg: crate::lightning_types::routing::RoutingFees, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: crate::c_types::derived::COption_u64Z, mut htlc_maximum_msat_arg: crate::c_types::derived::COption_u64Z) -> RouteHintHop {
	let mut local_htlc_minimum_msat_arg = if htlc_minimum_msat_arg.is_some() { Some( { htlc_minimum_msat_arg.take() }) } else { None };
	let mut local_htlc_maximum_msat_arg = if htlc_maximum_msat_arg.is_some() { Some( { htlc_maximum_msat_arg.take() }) } else { None };
	RouteHintHop { inner: ObjOps::heap_alloc(nativeRouteHintHop {
		src_node_id: src_node_id_arg.into_rust(),
		short_channel_id: short_channel_id_arg,
		fees: *unsafe { Box::from_raw(fees_arg.take_inner()) },
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: local_htlc_minimum_msat_arg,
		htlc_maximum_msat: local_htlc_maximum_msat_arg,
	}), is_owned: true }
}
impl Clone for RouteHintHop {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHintHop>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHintHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRouteHintHop)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHintHop
pub extern "C" fn RouteHintHop_clone(orig: &RouteHintHop) -> RouteHintHop {
	orig.clone()
}
/// Get a string which allows debug introspection of a RouteHintHop object
pub extern "C" fn RouteHintHop_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_types::routing::RouteHintHop }).into()}
/// Generates a non-cryptographic 64-bit hash of the RouteHintHop.
#[no_mangle]
pub extern "C" fn RouteHintHop_hash(o: &RouteHintHop) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHintHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHintHop_eq(a: &RouteHintHop, b: &RouteHintHop) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
