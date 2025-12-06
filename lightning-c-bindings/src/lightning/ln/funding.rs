// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Types pertaining to funding channels.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// The components of a splice's funding transaction that are contributed by one party.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SpliceContribution {
	/// When funds are added to a channel.
	SpliceIn {
		/// The amount to contribute to the splice.
		value: u64,
		/// The inputs included in the splice's funding transaction to meet the contributed amount
		/// plus fees. Any excess amount will be sent to a change output.
		inputs: crate::c_types::derived::CVec_FundingTxInputZ,
		/// An optional change output script. This will be used if needed or, when not set,
		/// generated using [`SignerProvider::get_destination_script`].
		///
		/// [`SignerProvider::get_destination_script`]: crate::sign::SignerProvider::get_destination_script
		change_script: crate::c_types::derived::COption_CVec_u8ZZ,
	},
	/// When funds are removed from a channel.
	SpliceOut {
		/// The outputs to include in the splice's funding transaction. The total value of all
		/// outputs plus fees will be the amount that is removed.
		outputs: crate::c_types::derived::CVec_TxOutZ,
	},
}
use lightning::ln::funding::SpliceContribution as SpliceContributionImport;
pub(crate) type nativeSpliceContribution = SpliceContributionImport;

impl SpliceContribution {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSpliceContribution {
		match self {
			SpliceContribution::SpliceIn {ref value, ref inputs, ref change_script, } => {
				let mut value_nonref = Clone::clone(value);
				let mut inputs_nonref = Clone::clone(inputs);
				let mut local_inputs_nonref = Vec::new(); for mut item in inputs_nonref.into_rust().drain(..) { local_inputs_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut change_script_nonref = Clone::clone(change_script);
				let mut local_change_script_nonref = { /*change_script_nonref*/ let change_script_nonref_opt = change_script_nonref; if change_script_nonref_opt.is_none() { None } else { Some({ { ::bitcoin::script::ScriptBuf::from({ change_script_nonref_opt.take() }.into_rust()) }})} };
				nativeSpliceContribution::SpliceIn {
					value: ::bitcoin::amount::Amount::from_sat(value_nonref),
					inputs: local_inputs_nonref,
					change_script: local_change_script_nonref,
				}
			},
			SpliceContribution::SpliceOut {ref outputs, } => {
				let mut outputs_nonref = Clone::clone(outputs);
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.into_rust().drain(..) { local_outputs_nonref.push( { item.into_rust() }); };
				nativeSpliceContribution::SpliceOut {
					outputs: local_outputs_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSpliceContribution {
		match self {
			SpliceContribution::SpliceIn {mut value, mut inputs, mut change_script, } => {
				let mut local_inputs = Vec::new(); for mut item in inputs.into_rust().drain(..) { local_inputs.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut local_change_script = { /*change_script*/ let change_script_opt = change_script; if change_script_opt.is_none() { None } else { Some({ { ::bitcoin::script::ScriptBuf::from({ change_script_opt.take() }.into_rust()) }})} };
				nativeSpliceContribution::SpliceIn {
					value: ::bitcoin::amount::Amount::from_sat(value),
					inputs: local_inputs,
					change_script: local_change_script,
				}
			},
			SpliceContribution::SpliceOut {mut outputs, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_rust() }); };
				nativeSpliceContribution::SpliceOut {
					outputs: local_outputs,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &SpliceContributionImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeSpliceContribution) };
		match native {
			nativeSpliceContribution::SpliceIn {ref value, ref inputs, ref change_script, } => {
				let mut value_nonref = Clone::clone(value);
				let mut inputs_nonref = Clone::clone(inputs);
				let mut local_inputs_nonref = Vec::new(); for mut item in inputs_nonref.drain(..) { local_inputs_nonref.push( { crate::lightning::ln::funding::FundingTxInput { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut change_script_nonref = Clone::clone(change_script);
				let mut local_change_script_nonref = if change_script_nonref.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some( { change_script_nonref.unwrap().to_bytes().into() }) };
				SpliceContribution::SpliceIn {
					value: value_nonref.to_sat(),
					inputs: local_inputs_nonref.into(),
					change_script: local_change_script_nonref,
				}
			},
			nativeSpliceContribution::SpliceOut {ref outputs, } => {
				let mut outputs_nonref = Clone::clone(outputs);
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.drain(..) { local_outputs_nonref.push( { crate::c_types::TxOut::from_rust(&item) }); };
				SpliceContribution::SpliceOut {
					outputs: local_outputs_nonref.into(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSpliceContribution) -> Self {
		match native {
			nativeSpliceContribution::SpliceIn {mut value, mut inputs, mut change_script, } => {
				let mut local_inputs = Vec::new(); for mut item in inputs.drain(..) { local_inputs.push( { crate::lightning::ln::funding::FundingTxInput { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut local_change_script = if change_script.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some( { change_script.unwrap().to_bytes().into() }) };
				SpliceContribution::SpliceIn {
					value: value.to_sat(),
					inputs: local_inputs.into(),
					change_script: local_change_script,
				}
			},
			nativeSpliceContribution::SpliceOut {mut outputs, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.drain(..) { local_outputs.push( { crate::c_types::TxOut::from_rust(&item) }); };
				SpliceContribution::SpliceOut {
					outputs: local_outputs.into(),
				}
			},
		}
	}
}
/// Frees any resources used by the SpliceContribution
#[no_mangle]
pub extern "C" fn SpliceContribution_free(this_ptr: SpliceContribution) { }
/// Creates a copy of the SpliceContribution
#[no_mangle]
pub extern "C" fn SpliceContribution_clone(orig: &SpliceContribution) -> SpliceContribution {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SpliceContribution_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const SpliceContribution)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SpliceContribution_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut SpliceContribution) };
}
#[no_mangle]
/// Utility method to constructs a new SpliceIn-variant SpliceContribution
pub extern "C" fn SpliceContribution_splice_in(value: u64, inputs: crate::c_types::derived::CVec_FundingTxInputZ, change_script: crate::c_types::derived::COption_CVec_u8ZZ) -> SpliceContribution {
	SpliceContribution::SpliceIn {
		value,
		inputs,
		change_script,
	}
}
#[no_mangle]
/// Utility method to constructs a new SpliceOut-variant SpliceContribution
pub extern "C" fn SpliceContribution_splice_out(outputs: crate::c_types::derived::CVec_TxOutZ) -> SpliceContribution {
	SpliceContribution::SpliceOut {
		outputs,
	}
}
/// Get a string which allows debug introspection of a SpliceContribution object
pub extern "C" fn SpliceContribution_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::funding::SpliceContribution }).into()}

use lightning::ln::funding::FundingTxInput as nativeFundingTxInputImport;
pub(crate) type nativeFundingTxInput = nativeFundingTxInputImport;

/// An input to contribute to a channel's funding transaction either when using the v2 channel
/// establishment protocol or when splicing.
#[must_use]
#[repr(C)]
pub struct FundingTxInput {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFundingTxInput,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for FundingTxInput {
	type Target = nativeFundingTxInput;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for FundingTxInput { }
unsafe impl core::marker::Sync for FundingTxInput { }
impl Drop for FundingTxInput {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeFundingTxInput>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the FundingTxInput, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn FundingTxInput_free(this_obj: FundingTxInput) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FundingTxInput_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeFundingTxInput) };
}
#[allow(unused)]
impl FundingTxInput {
	pub(crate) fn get_native_ref(&self) -> &'static nativeFundingTxInput {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeFundingTxInput {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeFundingTxInput {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Get a string which allows debug introspection of a FundingTxInput object
pub extern "C" fn FundingTxInput_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::funding::FundingTxInput }).into()}
impl Clone for FundingTxInput {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeFundingTxInput>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(Clone::clone(unsafe { &*ObjOps::untweak_ptr(self.inner) })) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FundingTxInput_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(Clone::clone(unsafe { &*(this_ptr as *const nativeFundingTxInput) }))) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the FundingTxInput
pub extern "C" fn FundingTxInput_clone(orig: &FundingTxInput) -> FundingTxInput {
	Clone::clone(orig)
}
#[no_mangle]
/// Serialize the FundingTxInput object into a byte array which can be read by FundingTxInput_read
pub extern "C" fn FundingTxInput_write(obj: &crate::lightning::ln::funding::FundingTxInput) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn FundingTxInput_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::ln::funding::nativeFundingTxInput) })
}
#[no_mangle]
/// Read a FundingTxInput from a byte array, created by FundingTxInput_write
pub extern "C" fn FundingTxInput_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_FundingTxInputDecodeErrorZ {
	let res: Result<lightning::ln::funding::FundingTxInput, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::funding::FundingTxInput { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Creates an input spending a P2WPKH output from the given `prevtx` at index `vout`.
///
/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
/// by [`set_sequence`].
///
/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
///
/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
/// [`set_sequence`]: Self::set_sequence
#[must_use]
#[no_mangle]
pub extern "C" fn FundingTxInput_new_p2wpkh(mut prevtx: crate::c_types::Transaction, mut vout: u32) -> crate::c_types::derived::CResult_FundingTxInputNoneZ {
	let mut ret = lightning::ln::funding::FundingTxInput::new_p2wpkh(prevtx.into_bitcoin(), vout);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::funding::FundingTxInput { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Creates an input spending a P2WSH output from the given `prevtx` at index `vout`.
///
/// Requires passing the weight of witness needed to satisfy the output's script.
///
/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
/// by [`set_sequence`].
///
/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
///
/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
/// [`set_sequence`]: Self::set_sequence
#[must_use]
#[no_mangle]
pub extern "C" fn FundingTxInput_new_p2wsh(mut prevtx: crate::c_types::Transaction, mut vout: u32, mut witness_weight: u64) -> crate::c_types::derived::CResult_FundingTxInputNoneZ {
	let mut ret = lightning::ln::funding::FundingTxInput::new_p2wsh(prevtx.into_bitcoin(), vout, ::bitcoin::Weight::from_wu(witness_weight));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::funding::FundingTxInput { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Creates an input spending a P2TR output from the given `prevtx` at index `vout`.
///
/// This is meant for inputs spending a taproot output using the key path. See
/// [`new_p2tr_script_spend`] for when spending using a script path.
///
/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
/// by [`set_sequence`].
///
/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
///
/// [`new_p2tr_script_spend`]: Self::new_p2tr_script_spend
///
/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
/// [`set_sequence`]: Self::set_sequence
#[must_use]
#[no_mangle]
pub extern "C" fn FundingTxInput_new_p2tr_key_spend(mut prevtx: crate::c_types::Transaction, mut vout: u32) -> crate::c_types::derived::CResult_FundingTxInputNoneZ {
	let mut ret = lightning::ln::funding::FundingTxInput::new_p2tr_key_spend(prevtx.into_bitcoin(), vout);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::funding::FundingTxInput { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Creates an input spending a P2TR output from the given `prevtx` at index `vout`.
///
/// Requires passing the weight of witness needed to satisfy a script path of the taproot
/// output. See [`new_p2tr_key_spend`] for when spending using the key path.
///
/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
/// by [`set_sequence`].
///
/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
///
/// [`new_p2tr_key_spend`]: Self::new_p2tr_key_spend
///
/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
/// [`set_sequence`]: Self::set_sequence
#[must_use]
#[no_mangle]
pub extern "C" fn FundingTxInput_new_p2tr_script_spend(mut prevtx: crate::c_types::Transaction, mut vout: u32, mut witness_weight: u64) -> crate::c_types::derived::CResult_FundingTxInputNoneZ {
	let mut ret = lightning::ln::funding::FundingTxInput::new_p2tr_script_spend(prevtx.into_bitcoin(), vout, ::bitcoin::Weight::from_wu(witness_weight));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::funding::FundingTxInput { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// The outpoint of the UTXO being spent.
#[must_use]
#[no_mangle]
pub extern "C" fn FundingTxInput_outpoint(this_arg: &crate::lightning::ln::funding::FundingTxInput) -> crate::lightning::chain::transaction::OutPoint {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.outpoint();
	crate::c_types::bitcoin_to_C_outpoint(&ret)
}

/// The sequence number to use in the [`TxIn`].
///
/// [`TxIn`]: bitcoin::TxIn
#[must_use]
#[no_mangle]
pub extern "C" fn FundingTxInput_sequence(this_arg: &crate::lightning::ln::funding::FundingTxInput) -> u32 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sequence();
	ret.0
}

/// Sets the sequence number to use in the [`TxIn`].
///
/// [`TxIn`]: bitcoin::TxIn
#[no_mangle]
pub extern "C" fn FundingTxInput_set_sequence(this_arg: &mut crate::lightning::ln::funding::FundingTxInput, mut sequence: u32) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::funding::nativeFundingTxInput)) }.set_sequence(::bitcoin::Sequence(sequence))
}

/// Converts the [`FundingTxInput`] into a [`Utxo`] for coin selection.
#[must_use]
#[no_mangle]
pub extern "C" fn FundingTxInput_into_utxo(mut this_arg: crate::lightning::ln::funding::FundingTxInput) -> crate::lightning::events::bump_transaction::Utxo {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_utxo();
	crate::lightning::events::bump_transaction::Utxo { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

