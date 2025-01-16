// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Error types live here.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Indicates an error on the client's part (usually some variant of attempting to use too-low or
/// too-high values)
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum APIError {
	/// Indicates the API was wholly misused (see err for more). Cases where these can be returned
	/// are documented, but generally indicates some precondition of a function was violated.
	APIMisuseError {
		/// A human-readable error message
		err: crate::c_types::Str,
	},
	/// Due to a high feerate, we were unable to complete the request.
	/// For example, this may be returned if the feerate implies we cannot open a channel at the
	/// requested value, but opening a larger channel would succeed.
	FeeRateTooHigh {
		/// A human-readable error message
		err: crate::c_types::Str,
		/// The feerate which was too high.
		feerate: u32,
	},
	/// A malformed Route was provided (eg overflowed value, node id mismatch, overly-looped route,
	/// too-many-hops, etc).
	InvalidRoute {
		/// A human-readable error message
		err: crate::c_types::Str,
	},
	/// We were unable to complete the request as the Channel required to do so is unable to
	/// complete the request (or was not found). This can take many forms, including disconnected
	/// peer, channel at capacity, channel shutting down, etc.
	ChannelUnavailable {
		/// A human-readable error message
		err: crate::c_types::Str,
	},
	/// An attempt to call [`chain::Watch::watch_channel`]/[`chain::Watch::update_channel`]
	/// returned a [`ChannelMonitorUpdateStatus::InProgress`] indicating the persistence of a
	/// monitor update is awaiting async resolution. Once it resolves the attempted action should
	/// complete automatically.
	///
	/// [`chain::Watch::watch_channel`]: crate::chain::Watch::watch_channel
	/// [`chain::Watch::update_channel`]: crate::chain::Watch::update_channel
	/// [`ChannelMonitorUpdateStatus::InProgress`]: crate::chain::ChannelMonitorUpdateStatus::InProgress
	MonitorUpdateInProgress,
	/// [`SignerProvider::get_shutdown_scriptpubkey`] returned a shutdown scriptpubkey incompatible
	/// with the channel counterparty as negotiated in [`InitFeatures`].
	///
	/// Using a SegWit v0 script should resolve this issue. If you cannot, you won't be able to open
	/// a channel or cooperatively close one with this peer (and will have to force-close instead).
	///
	/// [`SignerProvider::get_shutdown_scriptpubkey`]: crate::sign::SignerProvider::get_shutdown_scriptpubkey
	/// [`InitFeatures`]: crate::types::features::InitFeatures
	IncompatibleShutdownScript {
		/// The incompatible shutdown script.
		script: crate::lightning::ln::script::ShutdownScript,
	},
}
use lightning::util::errors::APIError as APIErrorImport;
pub(crate) type nativeAPIError = APIErrorImport;

impl APIError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeAPIError {
		match self {
			APIError::APIMisuseError {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				nativeAPIError::APIMisuseError {
					err: err_nonref.into_string(),
				}
			},
			APIError::FeeRateTooHigh {ref err, ref feerate, } => {
				let mut err_nonref = Clone::clone(err);
				let mut feerate_nonref = Clone::clone(feerate);
				nativeAPIError::FeeRateTooHigh {
					err: err_nonref.into_string(),
					feerate: feerate_nonref,
				}
			},
			APIError::InvalidRoute {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				nativeAPIError::InvalidRoute {
					err: err_nonref.into_string(),
				}
			},
			APIError::ChannelUnavailable {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				nativeAPIError::ChannelUnavailable {
					err: err_nonref.into_string(),
				}
			},
			APIError::MonitorUpdateInProgress => nativeAPIError::MonitorUpdateInProgress,
			APIError::IncompatibleShutdownScript {ref script, } => {
				let mut script_nonref = Clone::clone(script);
				nativeAPIError::IncompatibleShutdownScript {
					script: *unsafe { Box::from_raw(script_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeAPIError {
		match self {
			APIError::APIMisuseError {mut err, } => {
				nativeAPIError::APIMisuseError {
					err: err.into_string(),
				}
			},
			APIError::FeeRateTooHigh {mut err, mut feerate, } => {
				nativeAPIError::FeeRateTooHigh {
					err: err.into_string(),
					feerate: feerate,
				}
			},
			APIError::InvalidRoute {mut err, } => {
				nativeAPIError::InvalidRoute {
					err: err.into_string(),
				}
			},
			APIError::ChannelUnavailable {mut err, } => {
				nativeAPIError::ChannelUnavailable {
					err: err.into_string(),
				}
			},
			APIError::MonitorUpdateInProgress => nativeAPIError::MonitorUpdateInProgress,
			APIError::IncompatibleShutdownScript {mut script, } => {
				nativeAPIError::IncompatibleShutdownScript {
					script: *unsafe { Box::from_raw(script.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &APIErrorImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeAPIError) };
		match native {
			nativeAPIError::APIMisuseError {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				APIError::APIMisuseError {
					err: err_nonref.into(),
				}
			},
			nativeAPIError::FeeRateTooHigh {ref err, ref feerate, } => {
				let mut err_nonref = Clone::clone(err);
				let mut feerate_nonref = Clone::clone(feerate);
				APIError::FeeRateTooHigh {
					err: err_nonref.into(),
					feerate: feerate_nonref,
				}
			},
			nativeAPIError::InvalidRoute {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				APIError::InvalidRoute {
					err: err_nonref.into(),
				}
			},
			nativeAPIError::ChannelUnavailable {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				APIError::ChannelUnavailable {
					err: err_nonref.into(),
				}
			},
			nativeAPIError::MonitorUpdateInProgress => APIError::MonitorUpdateInProgress,
			nativeAPIError::IncompatibleShutdownScript {ref script, } => {
				let mut script_nonref = Clone::clone(script);
				APIError::IncompatibleShutdownScript {
					script: crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(script_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeAPIError) -> Self {
		match native {
			nativeAPIError::APIMisuseError {mut err, } => {
				APIError::APIMisuseError {
					err: err.into(),
				}
			},
			nativeAPIError::FeeRateTooHigh {mut err, mut feerate, } => {
				APIError::FeeRateTooHigh {
					err: err.into(),
					feerate: feerate,
				}
			},
			nativeAPIError::InvalidRoute {mut err, } => {
				APIError::InvalidRoute {
					err: err.into(),
				}
			},
			nativeAPIError::ChannelUnavailable {mut err, } => {
				APIError::ChannelUnavailable {
					err: err.into(),
				}
			},
			nativeAPIError::MonitorUpdateInProgress => APIError::MonitorUpdateInProgress,
			nativeAPIError::IncompatibleShutdownScript {mut script, } => {
				APIError::IncompatibleShutdownScript {
					script: crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(script), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the APIError
#[no_mangle]
pub extern "C" fn APIError_free(this_ptr: APIError) { }
/// Creates a copy of the APIError
#[no_mangle]
pub extern "C" fn APIError_clone(orig: &APIError) -> APIError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn APIError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const APIError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn APIError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut APIError) };
}
#[no_mangle]
/// Utility method to constructs a new APIMisuseError-variant APIError
pub extern "C" fn APIError_apimisuse_error(err: crate::c_types::Str) -> APIError {
	APIError::APIMisuseError {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new FeeRateTooHigh-variant APIError
pub extern "C" fn APIError_fee_rate_too_high(err: crate::c_types::Str, feerate: u32) -> APIError {
	APIError::FeeRateTooHigh {
		err,
		feerate,
	}
}
#[no_mangle]
/// Utility method to constructs a new InvalidRoute-variant APIError
pub extern "C" fn APIError_invalid_route(err: crate::c_types::Str) -> APIError {
	APIError::InvalidRoute {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelUnavailable-variant APIError
pub extern "C" fn APIError_channel_unavailable(err: crate::c_types::Str) -> APIError {
	APIError::ChannelUnavailable {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new MonitorUpdateInProgress-variant APIError
pub extern "C" fn APIError_monitor_update_in_progress() -> APIError {
	APIError::MonitorUpdateInProgress}
#[no_mangle]
/// Utility method to constructs a new IncompatibleShutdownScript-variant APIError
pub extern "C" fn APIError_incompatible_shutdown_script(script: crate::lightning::ln::script::ShutdownScript) -> APIError {
	APIError::IncompatibleShutdownScript {
		script,
	}
}
/// Checks if two APIErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn APIError_eq(a: &APIError, b: &APIError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Get a string which allows debug introspection of a APIError object
pub extern "C" fn APIError_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::errors::APIError }).into()}
#[no_mangle]
/// Serialize the APIError object into a byte array which can be read by APIError_read
pub extern "C" fn APIError_write(obj: &crate::lightning::util::errors::APIError) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn APIError_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	APIError_write(unsafe { &*(obj as *const APIError) })
}
#[no_mangle]
/// Read a APIError from a byte array, created by APIError_write
pub extern "C" fn APIError_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_APIErrorZDecodeErrorZ {
	let res: Result<Option<lightning::util::errors::APIError>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_APIErrorZ::None } else { crate::c_types::derived::COption_APIErrorZ::Some( { crate::lightning::util::errors::APIError::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
