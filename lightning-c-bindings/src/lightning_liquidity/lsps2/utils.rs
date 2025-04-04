// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for implementing the bLIP-52 / LSPS2 standard.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Determines if the given parameters are valid given the secret used to generate the promise.
#[no_mangle]
pub extern "C" fn is_valid_opening_fee_params(fee_params: &crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams, promise_secret: *const [u8; 32]) -> bool {
	let mut ret = lightning_liquidity::lsps2::utils::is_valid_opening_fee_params(fee_params.get_native_ref(), unsafe { &*promise_secret});
	ret
}

/// Determines if the given parameters are expired, or still valid.
#[no_mangle]
pub extern "C" fn is_expired_opening_fee_params(fee_params: &crate::lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams) -> bool {
	let mut ret = lightning_liquidity::lsps2::utils::is_expired_opening_fee_params(fee_params.get_native_ref());
	ret
}

/// Computes the opening fee given a payment size and the fee parameters.
///
/// Returns [`Option::None`] when the computation overflows.
///
/// See the [`specification`](https://github.com/lightning/blips/blob/master/blip-0052.md#computing-the-opening_fee) for more details.
#[no_mangle]
pub extern "C" fn compute_opening_fee(mut payment_size_msat: u64, mut opening_fee_min_fee_msat: u64, mut opening_fee_proportional: u64) -> crate::c_types::derived::COption_u64Z {
	let mut ret = lightning_liquidity::lsps2::utils::compute_opening_fee(payment_size_msat, opening_fee_min_fee_msat, opening_fee_proportional);
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

