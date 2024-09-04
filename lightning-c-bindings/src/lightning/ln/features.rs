// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Feature flag definitions for the Lightning protocol according to [BOLT #9].
//!
//! See [`lightning_types::features`] for the list of features currently supported.
//!
//! Note that the use of types via this module is deprecated and will be removed in a future
//! version. Instead, use feature objects via [`lightning::types::features`].
//!
//! [`lightning::types::features`]: crate::types::features
//! [BOLT #9]: https://github.com/lightning/bolts/blob/master/09-features.md

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

#[no_mangle]
/// Serialize the InitFeatures object into a byte array which can be read by InitFeatures_read
pub extern "C" fn InitFeatures_write(obj: &crate::lightning_types::features::InitFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn InitFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::features::nativeInitFeatures) })
}
#[no_mangle]
/// Read a InitFeatures from a byte array, created by InitFeatures_write
pub extern "C" fn InitFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InitFeaturesDecodeErrorZ {
	let res: Result<lightning_types::features::InitFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::features::InitFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelFeatures object into a byte array which can be read by ChannelFeatures_read
pub extern "C" fn ChannelFeatures_write(obj: &crate::lightning_types::features::ChannelFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::features::nativeChannelFeatures) })
}
#[no_mangle]
/// Read a ChannelFeatures from a byte array, created by ChannelFeatures_write
pub extern "C" fn ChannelFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelFeaturesDecodeErrorZ {
	let res: Result<lightning_types::features::ChannelFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::features::ChannelFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the NodeFeatures object into a byte array which can be read by NodeFeatures_read
pub extern "C" fn NodeFeatures_write(obj: &crate::lightning_types::features::NodeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn NodeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::features::nativeNodeFeatures) })
}
#[no_mangle]
/// Read a NodeFeatures from a byte array, created by NodeFeatures_write
pub extern "C" fn NodeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeFeaturesDecodeErrorZ {
	let res: Result<lightning_types::features::NodeFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::features::NodeFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the Bolt11InvoiceFeatures object into a byte array which can be read by Bolt11InvoiceFeatures_read
pub extern "C" fn Bolt11InvoiceFeatures_write(obj: &crate::lightning_types::features::Bolt11InvoiceFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt11InvoiceFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::features::nativeBolt11InvoiceFeatures) })
}
#[no_mangle]
/// Read a Bolt11InvoiceFeatures from a byte array, created by Bolt11InvoiceFeatures_write
pub extern "C" fn Bolt11InvoiceFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_Bolt11InvoiceFeaturesDecodeErrorZ {
	let res: Result<lightning_types::features::Bolt11InvoiceFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::features::Bolt11InvoiceFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the Bolt12InvoiceFeatures object into a byte array which can be read by Bolt12InvoiceFeatures_read
pub extern "C" fn Bolt12InvoiceFeatures_write(obj: &crate::lightning_types::features::Bolt12InvoiceFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt12InvoiceFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::features::nativeBolt12InvoiceFeatures) })
}
#[no_mangle]
/// Read a Bolt12InvoiceFeatures from a byte array, created by Bolt12InvoiceFeatures_write
pub extern "C" fn Bolt12InvoiceFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_Bolt12InvoiceFeaturesDecodeErrorZ {
	let res: Result<lightning_types::features::Bolt12InvoiceFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::features::Bolt12InvoiceFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the BlindedHopFeatures object into a byte array which can be read by BlindedHopFeatures_read
pub extern "C" fn BlindedHopFeatures_write(obj: &crate::lightning_types::features::BlindedHopFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedHopFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::features::nativeBlindedHopFeatures) })
}
#[no_mangle]
/// Read a BlindedHopFeatures from a byte array, created by BlindedHopFeatures_write
pub extern "C" fn BlindedHopFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedHopFeaturesDecodeErrorZ {
	let res: Result<lightning_types::features::BlindedHopFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::features::BlindedHopFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelTypeFeatures object into a byte array which can be read by ChannelTypeFeatures_read
pub extern "C" fn ChannelTypeFeatures_write(obj: &crate::lightning_types::features::ChannelTypeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelTypeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning_types::features::nativeChannelTypeFeatures) })
}
#[no_mangle]
/// Read a ChannelTypeFeatures from a byte array, created by ChannelTypeFeatures_write
pub extern "C" fn ChannelTypeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelTypeFeaturesDecodeErrorZ {
	let res: Result<lightning_types::features::ChannelTypeFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_types::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
