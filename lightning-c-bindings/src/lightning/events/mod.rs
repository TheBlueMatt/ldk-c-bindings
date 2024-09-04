// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Events are returned from various bits in the library which indicate some action must be taken
//! by the client.
//!
//! Because we don't have a built-in runtime, it's up to the client to call events at a time in the
//! future, as well as generate and broadcast funding transactions handle payment preimages and a
//! few other things.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod bump_transaction;
/// `FundingInfo` holds information about a channel's funding transaction.
///
/// When LDK is set to manual propagation of the funding transaction
/// (via [`ChannelManager::unsafe_manual_funding_transaction_generated`),
/// LDK does not have the full transaction data. Instead, the `OutPoint`
/// for the funding is provided here.
///
/// [`ChannelManager::unsafe_manual_funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::unsafe_manual_funding_transaction_generated
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum FundingInfo {
	/// The full funding `Transaction`.
	Tx {
		/// The funding transaction
		transaction: crate::c_types::Transaction,
	},
	/// The `OutPoint` of the funding.
	OutPoint {
		/// The outpoint of the funding
		outpoint: crate::lightning::chain::transaction::OutPoint,
	},
}
use lightning::events::FundingInfo as FundingInfoImport;
pub(crate) type nativeFundingInfo = FundingInfoImport;

impl FundingInfo {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeFundingInfo {
		match self {
			FundingInfo::Tx {ref transaction, } => {
				let mut transaction_nonref = Clone::clone(transaction);
				nativeFundingInfo::Tx {
					transaction: transaction_nonref.into_bitcoin(),
				}
			},
			FundingInfo::OutPoint {ref outpoint, } => {
				let mut outpoint_nonref = Clone::clone(outpoint);
				nativeFundingInfo::OutPoint {
					outpoint: *unsafe { Box::from_raw(outpoint_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeFundingInfo {
		match self {
			FundingInfo::Tx {mut transaction, } => {
				nativeFundingInfo::Tx {
					transaction: transaction.into_bitcoin(),
				}
			},
			FundingInfo::OutPoint {mut outpoint, } => {
				nativeFundingInfo::OutPoint {
					outpoint: *unsafe { Box::from_raw(outpoint.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &FundingInfoImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeFundingInfo) };
		match native {
			nativeFundingInfo::Tx {ref transaction, } => {
				let mut transaction_nonref = Clone::clone(transaction);
				FundingInfo::Tx {
					transaction: crate::c_types::Transaction::from_bitcoin(&transaction_nonref),
				}
			},
			nativeFundingInfo::OutPoint {ref outpoint, } => {
				let mut outpoint_nonref = Clone::clone(outpoint);
				FundingInfo::OutPoint {
					outpoint: crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(outpoint_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeFundingInfo) -> Self {
		match native {
			nativeFundingInfo::Tx {mut transaction, } => {
				FundingInfo::Tx {
					transaction: crate::c_types::Transaction::from_bitcoin(&transaction),
				}
			},
			nativeFundingInfo::OutPoint {mut outpoint, } => {
				FundingInfo::OutPoint {
					outpoint: crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(outpoint), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the FundingInfo
#[no_mangle]
pub extern "C" fn FundingInfo_free(this_ptr: FundingInfo) { }
/// Creates a copy of the FundingInfo
#[no_mangle]
pub extern "C" fn FundingInfo_clone(orig: &FundingInfo) -> FundingInfo {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FundingInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const FundingInfo)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FundingInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut FundingInfo) };
}
#[no_mangle]
/// Utility method to constructs a new Tx-variant FundingInfo
pub extern "C" fn FundingInfo_tx(transaction: crate::c_types::Transaction) -> FundingInfo {
	FundingInfo::Tx {
		transaction,
	}
}
#[no_mangle]
/// Utility method to constructs a new OutPoint-variant FundingInfo
pub extern "C" fn FundingInfo_out_point(outpoint: crate::lightning::chain::transaction::OutPoint) -> FundingInfo {
	FundingInfo::OutPoint {
		outpoint,
	}
}
/// Get a string which allows debug introspection of a FundingInfo object
pub extern "C" fn FundingInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::FundingInfo }).into()}
/// Checks if two FundingInfos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn FundingInfo_eq(a: &FundingInfo, b: &FundingInfo) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the FundingInfo object into a byte array which can be read by FundingInfo_read
pub extern "C" fn FundingInfo_write(obj: &crate::lightning::events::FundingInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn FundingInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	FundingInfo_write(unsafe { &*(obj as *const FundingInfo) })
}
#[no_mangle]
/// Read a FundingInfo from a byte array, created by FundingInfo_write
pub extern "C" fn FundingInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_FundingInfoDecodeErrorZ {
	let res: Result<lightning::events::FundingInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::events::FundingInfo::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Some information provided on receipt of payment depends on whether the payment received is a
/// spontaneous payment or a \"conventional\" lightning payment that's paying an invoice.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PaymentPurpose {
	/// A payment for a BOLT 11 invoice.
	Bolt11InvoicePayment {
		/// The preimage to the payment_hash, if the payment hash (and secret) were fetched via
		/// [`ChannelManager::create_inbound_payment`]. When handling [`Event::PaymentClaimable`],
		/// this can be passed directly to [`ChannelManager::claim_funds`] to claim the payment. No
		/// action is needed when seen in [`Event::PaymentClaimed`].
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		payment_preimage: crate::c_types::derived::COption_ThirtyTwoBytesZ,
		/// The \"payment secret\". This authenticates the sender to the recipient, preventing a
		/// number of deanonymization attacks during the routing process.
		/// It is provided here for your reference, however its accuracy is enforced directly by
		/// [`ChannelManager`] using the values you previously provided to
		/// [`ChannelManager::create_inbound_payment`] or
		/// [`ChannelManager::create_inbound_payment_for_hash`].
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
		payment_secret: crate::c_types::ThirtyTwoBytes,
	},
	/// A payment for a BOLT 12 [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	Bolt12OfferPayment {
		/// The preimage to the payment hash. When handling [`Event::PaymentClaimable`], this can be
		/// passed directly to [`ChannelManager::claim_funds`], if provided. No action is needed
		/// when seen in [`Event::PaymentClaimed`].
		///
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		payment_preimage: crate::c_types::derived::COption_ThirtyTwoBytesZ,
		/// The secret used to authenticate the sender to the recipient, preventing a number of
		/// de-anonymization attacks while routing a payment.
		///
		/// See [`PaymentPurpose::Bolt11InvoicePayment::payment_secret`] for further details.
		payment_secret: crate::c_types::ThirtyTwoBytes,
		/// The context of the payment such as information about the corresponding [`Offer`] and
		/// [`InvoiceRequest`].
		///
		/// [`Offer`]: crate::offers::offer::Offer
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		payment_context: crate::lightning::blinded_path::payment::Bolt12OfferContext,
	},
	/// A payment for a BOLT 12 [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	Bolt12RefundPayment {
		/// The preimage to the payment hash. When handling [`Event::PaymentClaimable`], this can be
		/// passed directly to [`ChannelManager::claim_funds`], if provided. No action is needed
		/// when seen in [`Event::PaymentClaimed`].
		///
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		payment_preimage: crate::c_types::derived::COption_ThirtyTwoBytesZ,
		/// The secret used to authenticate the sender to the recipient, preventing a number of
		/// de-anonymization attacks while routing a payment.
		///
		/// See [`PaymentPurpose::Bolt11InvoicePayment::payment_secret`] for further details.
		payment_secret: crate::c_types::ThirtyTwoBytes,
		/// The context of the payment such as information about the corresponding [`Refund`].
		///
		/// [`Refund`]: crate::offers::refund::Refund
		payment_context: crate::lightning::blinded_path::payment::Bolt12RefundContext,
	},
	/// Because this is a spontaneous payment, the payer generated their own preimage rather than us
	/// (the payee) providing a preimage.
	SpontaneousPayment(
		crate::c_types::ThirtyTwoBytes),
}
use lightning::events::PaymentPurpose as PaymentPurposeImport;
pub(crate) type nativePaymentPurpose = PaymentPurposeImport;

impl PaymentPurpose {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentPurpose {
		match self {
			PaymentPurpose::Bolt11InvoicePayment {ref payment_preimage, ref payment_secret, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = { /*payment_preimage_nonref*/ let payment_preimage_nonref_opt = payment_preimage_nonref; if payment_preimage_nonref_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentPreimage({ payment_preimage_nonref_opt.take() }.data) }})} };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				nativePaymentPurpose::Bolt11InvoicePayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: ::lightning::ln::types::PaymentSecret(payment_secret_nonref.data),
				}
			},
			PaymentPurpose::Bolt12OfferPayment {ref payment_preimage, ref payment_secret, ref payment_context, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = { /*payment_preimage_nonref*/ let payment_preimage_nonref_opt = payment_preimage_nonref; if payment_preimage_nonref_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentPreimage({ payment_preimage_nonref_opt.take() }.data) }})} };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				let mut payment_context_nonref = Clone::clone(payment_context);
				nativePaymentPurpose::Bolt12OfferPayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: ::lightning::ln::types::PaymentSecret(payment_secret_nonref.data),
					payment_context: *unsafe { Box::from_raw(payment_context_nonref.take_inner()) },
				}
			},
			PaymentPurpose::Bolt12RefundPayment {ref payment_preimage, ref payment_secret, ref payment_context, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = { /*payment_preimage_nonref*/ let payment_preimage_nonref_opt = payment_preimage_nonref; if payment_preimage_nonref_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentPreimage({ payment_preimage_nonref_opt.take() }.data) }})} };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				let mut payment_context_nonref = Clone::clone(payment_context);
				nativePaymentPurpose::Bolt12RefundPayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: ::lightning::ln::types::PaymentSecret(payment_secret_nonref.data),
					payment_context: *unsafe { Box::from_raw(payment_context_nonref.take_inner()) },
				}
			},
			PaymentPurpose::SpontaneousPayment (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentPurpose::SpontaneousPayment (
					::lightning::ln::types::PaymentPreimage(a_nonref.data),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePaymentPurpose {
		match self {
			PaymentPurpose::Bolt11InvoicePayment {mut payment_preimage, mut payment_secret, } => {
				let mut local_payment_preimage = { /*payment_preimage*/ let payment_preimage_opt = payment_preimage; if payment_preimage_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentPreimage({ payment_preimage_opt.take() }.data) }})} };
				nativePaymentPurpose::Bolt11InvoicePayment {
					payment_preimage: local_payment_preimage,
					payment_secret: ::lightning::ln::types::PaymentSecret(payment_secret.data),
				}
			},
			PaymentPurpose::Bolt12OfferPayment {mut payment_preimage, mut payment_secret, mut payment_context, } => {
				let mut local_payment_preimage = { /*payment_preimage*/ let payment_preimage_opt = payment_preimage; if payment_preimage_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentPreimage({ payment_preimage_opt.take() }.data) }})} };
				nativePaymentPurpose::Bolt12OfferPayment {
					payment_preimage: local_payment_preimage,
					payment_secret: ::lightning::ln::types::PaymentSecret(payment_secret.data),
					payment_context: *unsafe { Box::from_raw(payment_context.take_inner()) },
				}
			},
			PaymentPurpose::Bolt12RefundPayment {mut payment_preimage, mut payment_secret, mut payment_context, } => {
				let mut local_payment_preimage = { /*payment_preimage*/ let payment_preimage_opt = payment_preimage; if payment_preimage_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentPreimage({ payment_preimage_opt.take() }.data) }})} };
				nativePaymentPurpose::Bolt12RefundPayment {
					payment_preimage: local_payment_preimage,
					payment_secret: ::lightning::ln::types::PaymentSecret(payment_secret.data),
					payment_context: *unsafe { Box::from_raw(payment_context.take_inner()) },
				}
			},
			PaymentPurpose::SpontaneousPayment (mut a, ) => {
				nativePaymentPurpose::SpontaneousPayment (
					::lightning::ln::types::PaymentPreimage(a.data),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &PaymentPurposeImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativePaymentPurpose) };
		match native {
			nativePaymentPurpose::Bolt11InvoicePayment {ref payment_preimage, ref payment_secret, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = if payment_preimage_nonref.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_preimage_nonref.unwrap().0 } }) };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret_nonref.0 },
				}
			},
			nativePaymentPurpose::Bolt12OfferPayment {ref payment_preimage, ref payment_secret, ref payment_context, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = if payment_preimage_nonref.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_preimage_nonref.unwrap().0 } }) };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				let mut payment_context_nonref = Clone::clone(payment_context);
				PaymentPurpose::Bolt12OfferPayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret_nonref.0 },
					payment_context: crate::lightning::blinded_path::payment::Bolt12OfferContext { inner: ObjOps::heap_alloc(payment_context_nonref), is_owned: true },
				}
			},
			nativePaymentPurpose::Bolt12RefundPayment {ref payment_preimage, ref payment_secret, ref payment_context, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = if payment_preimage_nonref.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_preimage_nonref.unwrap().0 } }) };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				let mut payment_context_nonref = Clone::clone(payment_context);
				PaymentPurpose::Bolt12RefundPayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret_nonref.0 },
					payment_context: crate::lightning::blinded_path::payment::Bolt12RefundContext { inner: ObjOps::heap_alloc(payment_context_nonref), is_owned: true },
				}
			},
			nativePaymentPurpose::SpontaneousPayment (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentPurpose::SpontaneousPayment (
					crate::c_types::ThirtyTwoBytes { data: a_nonref.0 },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePaymentPurpose) -> Self {
		match native {
			nativePaymentPurpose::Bolt11InvoicePayment {mut payment_preimage, mut payment_secret, } => {
				let mut local_payment_preimage = if payment_preimage.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_preimage.unwrap().0 } }) };
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage: local_payment_preimage,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret.0 },
				}
			},
			nativePaymentPurpose::Bolt12OfferPayment {mut payment_preimage, mut payment_secret, mut payment_context, } => {
				let mut local_payment_preimage = if payment_preimage.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_preimage.unwrap().0 } }) };
				PaymentPurpose::Bolt12OfferPayment {
					payment_preimage: local_payment_preimage,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret.0 },
					payment_context: crate::lightning::blinded_path::payment::Bolt12OfferContext { inner: ObjOps::heap_alloc(payment_context), is_owned: true },
				}
			},
			nativePaymentPurpose::Bolt12RefundPayment {mut payment_preimage, mut payment_secret, mut payment_context, } => {
				let mut local_payment_preimage = if payment_preimage.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_preimage.unwrap().0 } }) };
				PaymentPurpose::Bolt12RefundPayment {
					payment_preimage: local_payment_preimage,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret.0 },
					payment_context: crate::lightning::blinded_path::payment::Bolt12RefundContext { inner: ObjOps::heap_alloc(payment_context), is_owned: true },
				}
			},
			nativePaymentPurpose::SpontaneousPayment (mut a, ) => {
				PaymentPurpose::SpontaneousPayment (
					crate::c_types::ThirtyTwoBytes { data: a.0 },
				)
			},
		}
	}
}
/// Frees any resources used by the PaymentPurpose
#[no_mangle]
pub extern "C" fn PaymentPurpose_free(this_ptr: PaymentPurpose) { }
/// Creates a copy of the PaymentPurpose
#[no_mangle]
pub extern "C" fn PaymentPurpose_clone(orig: &PaymentPurpose) -> PaymentPurpose {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentPurpose_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const PaymentPurpose)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentPurpose_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut PaymentPurpose) };
}
#[no_mangle]
/// Utility method to constructs a new Bolt11InvoicePayment-variant PaymentPurpose
pub extern "C" fn PaymentPurpose_bolt11_invoice_payment(payment_preimage: crate::c_types::derived::COption_ThirtyTwoBytesZ, payment_secret: crate::c_types::ThirtyTwoBytes) -> PaymentPurpose {
	PaymentPurpose::Bolt11InvoicePayment {
		payment_preimage,
		payment_secret,
	}
}
#[no_mangle]
/// Utility method to constructs a new Bolt12OfferPayment-variant PaymentPurpose
pub extern "C" fn PaymentPurpose_bolt12_offer_payment(payment_preimage: crate::c_types::derived::COption_ThirtyTwoBytesZ, payment_secret: crate::c_types::ThirtyTwoBytes, payment_context: crate::lightning::blinded_path::payment::Bolt12OfferContext) -> PaymentPurpose {
	PaymentPurpose::Bolt12OfferPayment {
		payment_preimage,
		payment_secret,
		payment_context,
	}
}
#[no_mangle]
/// Utility method to constructs a new Bolt12RefundPayment-variant PaymentPurpose
pub extern "C" fn PaymentPurpose_bolt12_refund_payment(payment_preimage: crate::c_types::derived::COption_ThirtyTwoBytesZ, payment_secret: crate::c_types::ThirtyTwoBytes, payment_context: crate::lightning::blinded_path::payment::Bolt12RefundContext) -> PaymentPurpose {
	PaymentPurpose::Bolt12RefundPayment {
		payment_preimage,
		payment_secret,
		payment_context,
	}
}
#[no_mangle]
/// Utility method to constructs a new SpontaneousPayment-variant PaymentPurpose
pub extern "C" fn PaymentPurpose_spontaneous_payment(a: crate::c_types::ThirtyTwoBytes) -> PaymentPurpose {
	PaymentPurpose::SpontaneousPayment(a, )
}
/// Get a string which allows debug introspection of a PaymentPurpose object
pub extern "C" fn PaymentPurpose_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::PaymentPurpose }).into()}
/// Checks if two PaymentPurposes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn PaymentPurpose_eq(a: &PaymentPurpose, b: &PaymentPurpose) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Returns the preimage for this payment, if it is known.
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentPurpose_preimage(this_arg: &crate::lightning::events::PaymentPurpose) -> crate::c_types::derived::COption_ThirtyTwoBytesZ {
	let mut ret = this_arg.to_native().preimage();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: ret.unwrap().0 } }) };
	local_ret
}

#[no_mangle]
/// Serialize the PaymentPurpose object into a byte array which can be read by PaymentPurpose_read
pub extern "C" fn PaymentPurpose_write(obj: &crate::lightning::events::PaymentPurpose) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentPurpose_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	PaymentPurpose_write(unsafe { &*(obj as *const PaymentPurpose) })
}
#[no_mangle]
/// Read a PaymentPurpose from a byte array, created by PaymentPurpose_write
pub extern "C" fn PaymentPurpose_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PaymentPurposeDecodeErrorZ {
	let res: Result<lightning::events::PaymentPurpose, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::events::PaymentPurpose::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::events::ClaimedHTLC as nativeClaimedHTLCImport;
pub(crate) type nativeClaimedHTLC = nativeClaimedHTLCImport;

/// Information about an HTLC that is part of a payment that can be claimed.
#[must_use]
#[repr(C)]
pub struct ClaimedHTLC {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeClaimedHTLC,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ClaimedHTLC {
	type Target = nativeClaimedHTLC;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ClaimedHTLC { }
unsafe impl core::marker::Sync for ClaimedHTLC { }
impl Drop for ClaimedHTLC {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeClaimedHTLC>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ClaimedHTLC, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_free(this_obj: ClaimedHTLC) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ClaimedHTLC_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeClaimedHTLC) };
}
#[allow(unused)]
impl ClaimedHTLC {
	pub(crate) fn get_native_ref(&self) -> &'static nativeClaimedHTLC {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeClaimedHTLC {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeClaimedHTLC {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The `channel_id` of the channel over which the HTLC was received.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_get_channel_id(this_ptr: &ClaimedHTLC) -> crate::lightning::ln::types::ChannelId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_id;
	crate::lightning::ln::types::ChannelId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::types::ChannelId<>) as *mut _) }, is_owned: false }
}
/// The `channel_id` of the channel over which the HTLC was received.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_set_channel_id(this_ptr: &mut ClaimedHTLC, mut val: crate::lightning::ln::types::ChannelId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_id = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The `user_channel_id` of the channel over which the HTLC was received. This is the value
/// passed in to [`ChannelManager::create_channel`] for outbound channels, or to
/// [`ChannelManager::accept_inbound_channel`] for inbound channels if
/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
/// `user_channel_id` will be randomized for an inbound channel.
///
/// This field will be zero for a payment that was serialized prior to LDK version 0.0.117. (This
/// should only happen in the case that a payment was claimable prior to LDK version 0.0.117, but
/// was not actually claimed until after upgrading.)
///
/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
#[no_mangle]
pub extern "C" fn ClaimedHTLC_get_user_channel_id(this_ptr: &ClaimedHTLC) -> crate::c_types::U128 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().user_channel_id;
	inner_val.into()
}
/// The `user_channel_id` of the channel over which the HTLC was received. This is the value
/// passed in to [`ChannelManager::create_channel`] for outbound channels, or to
/// [`ChannelManager::accept_inbound_channel`] for inbound channels if
/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
/// `user_channel_id` will be randomized for an inbound channel.
///
/// This field will be zero for a payment that was serialized prior to LDK version 0.0.117. (This
/// should only happen in the case that a payment was claimable prior to LDK version 0.0.117, but
/// was not actually claimed until after upgrading.)
///
/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
#[no_mangle]
pub extern "C" fn ClaimedHTLC_set_user_channel_id(this_ptr: &mut ClaimedHTLC, mut val: crate::c_types::U128) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.user_channel_id = val.into();
}
/// The block height at which this HTLC expires.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_get_cltv_expiry(this_ptr: &ClaimedHTLC) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry;
	*inner_val
}
/// The block height at which this HTLC expires.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_set_cltv_expiry(this_ptr: &mut ClaimedHTLC, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry = val;
}
/// The amount (in msats) of this part of an MPP.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_get_value_msat(this_ptr: &ClaimedHTLC) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().value_msat;
	*inner_val
}
/// The amount (in msats) of this part of an MPP.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_set_value_msat(this_ptr: &mut ClaimedHTLC, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.value_msat = val;
}
/// The extra fee our counterparty skimmed off the top of this HTLC, if any.
///
/// This value will always be 0 for [`ClaimedHTLC`]s serialized with LDK versions prior to
/// 0.0.119.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_get_counterparty_skimmed_fee_msat(this_ptr: &ClaimedHTLC) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().counterparty_skimmed_fee_msat;
	*inner_val
}
/// The extra fee our counterparty skimmed off the top of this HTLC, if any.
///
/// This value will always be 0 for [`ClaimedHTLC`]s serialized with LDK versions prior to
/// 0.0.119.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_set_counterparty_skimmed_fee_msat(this_ptr: &mut ClaimedHTLC, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.counterparty_skimmed_fee_msat = val;
}
/// Constructs a new ClaimedHTLC given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ClaimedHTLC_new(mut channel_id_arg: crate::lightning::ln::types::ChannelId, mut user_channel_id_arg: crate::c_types::U128, mut cltv_expiry_arg: u32, mut value_msat_arg: u64, mut counterparty_skimmed_fee_msat_arg: u64) -> ClaimedHTLC {
	ClaimedHTLC { inner: ObjOps::heap_alloc(nativeClaimedHTLC {
		channel_id: *unsafe { Box::from_raw(channel_id_arg.take_inner()) },
		user_channel_id: user_channel_id_arg.into(),
		cltv_expiry: cltv_expiry_arg,
		value_msat: value_msat_arg,
		counterparty_skimmed_fee_msat: counterparty_skimmed_fee_msat_arg,
	}), is_owned: true }
}
impl Clone for ClaimedHTLC {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeClaimedHTLC>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ClaimedHTLC_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeClaimedHTLC)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ClaimedHTLC
pub extern "C" fn ClaimedHTLC_clone(orig: &ClaimedHTLC) -> ClaimedHTLC {
	orig.clone()
}
/// Get a string which allows debug introspection of a ClaimedHTLC object
pub extern "C" fn ClaimedHTLC_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::ClaimedHTLC }).into()}
/// Checks if two ClaimedHTLCs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ClaimedHTLC_eq(a: &ClaimedHTLC, b: &ClaimedHTLC) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the ClaimedHTLC object into a byte array which can be read by ClaimedHTLC_read
pub extern "C" fn ClaimedHTLC_write(obj: &crate::lightning::events::ClaimedHTLC) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ClaimedHTLC_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const crate::lightning::events::nativeClaimedHTLC) })
}
#[no_mangle]
/// Read a ClaimedHTLC from a byte array, created by ClaimedHTLC_write
pub extern "C" fn ClaimedHTLC_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ClaimedHTLCDecodeErrorZ {
	let res: Result<lightning::events::ClaimedHTLC, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::events::ClaimedHTLC { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// When the payment path failure took place and extra details about it. [`PathFailure::OnPath`] may
/// contain a [`NetworkUpdate`] that needs to be applied to the [`NetworkGraph`].
///
/// [`NetworkUpdate`]: crate::routing::gossip::NetworkUpdate
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PathFailure {
	/// We failed to initially send the payment and no HTLC was committed to. Contains the relevant
	/// error.
	InitialSend {
		/// The error surfaced from initial send.
		err: crate::lightning::util::errors::APIError,
	},
	/// A hop on the path failed to forward our payment.
	OnPath {
		/// If present, this [`NetworkUpdate`] should be applied to the [`NetworkGraph`] so that routing
		/// decisions can take into account the update.
		///
		/// [`NetworkUpdate`]: crate::routing::gossip::NetworkUpdate
		/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
		network_update: crate::c_types::derived::COption_NetworkUpdateZ,
	},
}
use lightning::events::PathFailure as PathFailureImport;
pub(crate) type nativePathFailure = PathFailureImport;

impl PathFailure {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePathFailure {
		match self {
			PathFailure::InitialSend {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				nativePathFailure::InitialSend {
					err: err_nonref.into_native(),
				}
			},
			PathFailure::OnPath {ref network_update, } => {
				let mut network_update_nonref = Clone::clone(network_update);
				let mut local_network_update_nonref = { /*network_update_nonref*/ let network_update_nonref_opt = network_update_nonref; if network_update_nonref_opt.is_none() { None } else { Some({ { { network_update_nonref_opt.take() }.into_native() }})} };
				nativePathFailure::OnPath {
					network_update: local_network_update_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePathFailure {
		match self {
			PathFailure::InitialSend {mut err, } => {
				nativePathFailure::InitialSend {
					err: err.into_native(),
				}
			},
			PathFailure::OnPath {mut network_update, } => {
				let mut local_network_update = { /*network_update*/ let network_update_opt = network_update; if network_update_opt.is_none() { None } else { Some({ { { network_update_opt.take() }.into_native() }})} };
				nativePathFailure::OnPath {
					network_update: local_network_update,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &PathFailureImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativePathFailure) };
		match native {
			nativePathFailure::InitialSend {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				PathFailure::InitialSend {
					err: crate::lightning::util::errors::APIError::native_into(err_nonref),
				}
			},
			nativePathFailure::OnPath {ref network_update, } => {
				let mut network_update_nonref = Clone::clone(network_update);
				let mut local_network_update_nonref = if network_update_nonref.is_none() { crate::c_types::derived::COption_NetworkUpdateZ::None } else { crate::c_types::derived::COption_NetworkUpdateZ::Some( { crate::lightning::routing::gossip::NetworkUpdate::native_into(network_update_nonref.unwrap()) }) };
				PathFailure::OnPath {
					network_update: local_network_update_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePathFailure) -> Self {
		match native {
			nativePathFailure::InitialSend {mut err, } => {
				PathFailure::InitialSend {
					err: crate::lightning::util::errors::APIError::native_into(err),
				}
			},
			nativePathFailure::OnPath {mut network_update, } => {
				let mut local_network_update = if network_update.is_none() { crate::c_types::derived::COption_NetworkUpdateZ::None } else { crate::c_types::derived::COption_NetworkUpdateZ::Some( { crate::lightning::routing::gossip::NetworkUpdate::native_into(network_update.unwrap()) }) };
				PathFailure::OnPath {
					network_update: local_network_update,
				}
			},
		}
	}
}
/// Frees any resources used by the PathFailure
#[no_mangle]
pub extern "C" fn PathFailure_free(this_ptr: PathFailure) { }
/// Creates a copy of the PathFailure
#[no_mangle]
pub extern "C" fn PathFailure_clone(orig: &PathFailure) -> PathFailure {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PathFailure_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const PathFailure)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PathFailure_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut PathFailure) };
}
#[no_mangle]
/// Utility method to constructs a new InitialSend-variant PathFailure
pub extern "C" fn PathFailure_initial_send(err: crate::lightning::util::errors::APIError) -> PathFailure {
	PathFailure::InitialSend {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new OnPath-variant PathFailure
pub extern "C" fn PathFailure_on_path(network_update: crate::c_types::derived::COption_NetworkUpdateZ) -> PathFailure {
	PathFailure::OnPath {
		network_update,
	}
}
/// Get a string which allows debug introspection of a PathFailure object
pub extern "C" fn PathFailure_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::PathFailure }).into()}
/// Checks if two PathFailures contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn PathFailure_eq(a: &PathFailure, b: &PathFailure) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the PathFailure object into a byte array which can be read by PathFailure_read
pub extern "C" fn PathFailure_write(obj: &crate::lightning::events::PathFailure) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn PathFailure_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	PathFailure_write(unsafe { &*(obj as *const PathFailure) })
}
#[no_mangle]
/// Read a PathFailure from a byte array, created by PathFailure_write
pub extern "C" fn PathFailure_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_PathFailureZDecodeErrorZ {
	let res: Result<Option<lightning::events::PathFailure>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_PathFailureZ::None } else { crate::c_types::derived::COption_PathFailureZ::Some( { crate::lightning::events::PathFailure::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// The reason the channel was closed. See individual variants for more details.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ClosureReason {
	/// Closure generated from receiving a peer error message.
	///
	/// Our counterparty may have broadcasted their latest commitment state, and we have
	/// as well.
	CounterpartyForceClosed {
		/// The error which the peer sent us.
		///
		/// Be careful about printing the peer_msg, a well-crafted message could exploit
		/// a security vulnerability in the terminal emulator or the logging subsystem.
		/// To be safe, use `Display` on `UntrustedString`
		///
		/// [`UntrustedString`]: crate::util::string::UntrustedString
		peer_msg: crate::lightning_types::string::UntrustedString,
	},
	/// Closure generated from [`ChannelManager::force_close_channel`], called by the user.
	///
	/// [`ChannelManager::force_close_channel`]: crate::ln::channelmanager::ChannelManager::force_close_channel.
	HolderForceClosed {
		/// Whether or not the latest transaction was broadcasted when the channel was force
		/// closed.
		///
		/// Channels closed using [`ChannelManager::force_close_broadcasting_latest_txn`] will have
		/// this field set to true, whereas channels closed using [`ChannelManager::force_close_without_broadcasting_txn`]
		/// or force-closed prior to being funded will have this field set to false.
		///
		/// This will be `None` for objects generated or written by LDK 0.0.123 and
		/// earlier.
		///
		/// [`ChannelManager::force_close_broadcasting_latest_txn`]: crate::ln::channelmanager::ChannelManager::force_close_broadcasting_latest_txn.
		/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn.
		broadcasted_latest_txn: crate::c_types::derived::COption_boolZ,
	},
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. Note the shutdown may have been initiated by us.
	///
	/// This was only set in versions of LDK prior to 0.0.122.
	LegacyCooperativeClosure,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. This indicates that the shutdown was initiated by our
	/// counterparty.
	///
	/// In rare cases where we initiated closure immediately prior to shutting down without
	/// persisting, this value may be provided for channels we initiated closure for.
	CounterpartyInitiatedCooperativeClosure,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. This indicates that the shutdown was initiated by us.
	LocallyInitiatedCooperativeClosure,
	/// A commitment transaction was confirmed on chain, closing the channel. Most likely this
	/// commitment transaction came from our counterparty, but it may also have come from
	/// a copy of our own `ChannelMonitor`.
	CommitmentTxConfirmed,
	/// The funding transaction failed to confirm in a timely manner on an inbound channel.
	FundingTimedOut,
	/// Closure generated from processing an event, likely a HTLC forward/relay/reception.
	ProcessingError {
		/// A developer-readable error message which we generated.
		err: crate::c_types::Str,
	},
	/// The peer disconnected prior to funding completing. In this case the spec mandates that we
	/// forget the channel entirely - we can attempt again if the peer reconnects.
	///
	/// This includes cases where we restarted prior to funding completion, including prior to the
	/// initial [`ChannelMonitor`] persistence completing.
	///
	/// In LDK versions prior to 0.0.107 this could also occur if we were unable to connect to the
	/// peer because of mutual incompatibility between us and our channel counterparty.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	DisconnectedPeer,
	/// Closure generated from `ChannelManager::read` if the [`ChannelMonitor`] is newer than
	/// the [`ChannelManager`] deserialized.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	OutdatedChannelManager,
	/// The counterparty requested a cooperative close of a channel that had not been funded yet.
	/// The channel has been immediately closed.
	CounterpartyCoopClosedUnfundedChannel,
	/// Another channel in the same funding batch closed before the funding transaction
	/// was ready to be broadcast.
	FundingBatchClosure,
	/// One of our HTLCs timed out in a channel, causing us to force close the channel.
	HTLCsTimedOut,
	/// Our peer provided a feerate which violated our required minimum (fetched from our
	/// [`FeeEstimator`] either as [`ConfirmationTarget::MinAllowedAnchorChannelRemoteFee`] or
	/// [`ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee`]).
	///
	/// [`FeeEstimator`]: crate::chain::chaininterface::FeeEstimator
	/// [`ConfirmationTarget::MinAllowedAnchorChannelRemoteFee`]: crate::chain::chaininterface::ConfirmationTarget::MinAllowedAnchorChannelRemoteFee
	/// [`ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee`]: crate::chain::chaininterface::ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee
	PeerFeerateTooLow {
		/// The feerate on our channel set by our peer.
		peer_feerate_sat_per_kw: u32,
		/// The required feerate we enforce, from our [`FeeEstimator`].
		///
		/// [`FeeEstimator`]: crate::chain::chaininterface::FeeEstimator
		required_feerate_sat_per_kw: u32,
	},
}
use lightning::events::ClosureReason as ClosureReasonImport;
pub(crate) type nativeClosureReason = ClosureReasonImport;

impl ClosureReason {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeClosureReason {
		match self {
			ClosureReason::CounterpartyForceClosed {ref peer_msg, } => {
				let mut peer_msg_nonref = Clone::clone(peer_msg);
				nativeClosureReason::CounterpartyForceClosed {
					peer_msg: *unsafe { Box::from_raw(peer_msg_nonref.take_inner()) },
				}
			},
			ClosureReason::HolderForceClosed {ref broadcasted_latest_txn, } => {
				let mut broadcasted_latest_txn_nonref = Clone::clone(broadcasted_latest_txn);
				let mut local_broadcasted_latest_txn_nonref = if broadcasted_latest_txn_nonref.is_some() { Some( { broadcasted_latest_txn_nonref.take() }) } else { None };
				nativeClosureReason::HolderForceClosed {
					broadcasted_latest_txn: local_broadcasted_latest_txn_nonref,
				}
			},
			ClosureReason::LegacyCooperativeClosure => nativeClosureReason::LegacyCooperativeClosure,
			ClosureReason::CounterpartyInitiatedCooperativeClosure => nativeClosureReason::CounterpartyInitiatedCooperativeClosure,
			ClosureReason::LocallyInitiatedCooperativeClosure => nativeClosureReason::LocallyInitiatedCooperativeClosure,
			ClosureReason::CommitmentTxConfirmed => nativeClosureReason::CommitmentTxConfirmed,
			ClosureReason::FundingTimedOut => nativeClosureReason::FundingTimedOut,
			ClosureReason::ProcessingError {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				nativeClosureReason::ProcessingError {
					err: err_nonref.into_string(),
				}
			},
			ClosureReason::DisconnectedPeer => nativeClosureReason::DisconnectedPeer,
			ClosureReason::OutdatedChannelManager => nativeClosureReason::OutdatedChannelManager,
			ClosureReason::CounterpartyCoopClosedUnfundedChannel => nativeClosureReason::CounterpartyCoopClosedUnfundedChannel,
			ClosureReason::FundingBatchClosure => nativeClosureReason::FundingBatchClosure,
			ClosureReason::HTLCsTimedOut => nativeClosureReason::HTLCsTimedOut,
			ClosureReason::PeerFeerateTooLow {ref peer_feerate_sat_per_kw, ref required_feerate_sat_per_kw, } => {
				let mut peer_feerate_sat_per_kw_nonref = Clone::clone(peer_feerate_sat_per_kw);
				let mut required_feerate_sat_per_kw_nonref = Clone::clone(required_feerate_sat_per_kw);
				nativeClosureReason::PeerFeerateTooLow {
					peer_feerate_sat_per_kw: peer_feerate_sat_per_kw_nonref,
					required_feerate_sat_per_kw: required_feerate_sat_per_kw_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeClosureReason {
		match self {
			ClosureReason::CounterpartyForceClosed {mut peer_msg, } => {
				nativeClosureReason::CounterpartyForceClosed {
					peer_msg: *unsafe { Box::from_raw(peer_msg.take_inner()) },
				}
			},
			ClosureReason::HolderForceClosed {mut broadcasted_latest_txn, } => {
				let mut local_broadcasted_latest_txn = if broadcasted_latest_txn.is_some() { Some( { broadcasted_latest_txn.take() }) } else { None };
				nativeClosureReason::HolderForceClosed {
					broadcasted_latest_txn: local_broadcasted_latest_txn,
				}
			},
			ClosureReason::LegacyCooperativeClosure => nativeClosureReason::LegacyCooperativeClosure,
			ClosureReason::CounterpartyInitiatedCooperativeClosure => nativeClosureReason::CounterpartyInitiatedCooperativeClosure,
			ClosureReason::LocallyInitiatedCooperativeClosure => nativeClosureReason::LocallyInitiatedCooperativeClosure,
			ClosureReason::CommitmentTxConfirmed => nativeClosureReason::CommitmentTxConfirmed,
			ClosureReason::FundingTimedOut => nativeClosureReason::FundingTimedOut,
			ClosureReason::ProcessingError {mut err, } => {
				nativeClosureReason::ProcessingError {
					err: err.into_string(),
				}
			},
			ClosureReason::DisconnectedPeer => nativeClosureReason::DisconnectedPeer,
			ClosureReason::OutdatedChannelManager => nativeClosureReason::OutdatedChannelManager,
			ClosureReason::CounterpartyCoopClosedUnfundedChannel => nativeClosureReason::CounterpartyCoopClosedUnfundedChannel,
			ClosureReason::FundingBatchClosure => nativeClosureReason::FundingBatchClosure,
			ClosureReason::HTLCsTimedOut => nativeClosureReason::HTLCsTimedOut,
			ClosureReason::PeerFeerateTooLow {mut peer_feerate_sat_per_kw, mut required_feerate_sat_per_kw, } => {
				nativeClosureReason::PeerFeerateTooLow {
					peer_feerate_sat_per_kw: peer_feerate_sat_per_kw,
					required_feerate_sat_per_kw: required_feerate_sat_per_kw,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &ClosureReasonImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeClosureReason) };
		match native {
			nativeClosureReason::CounterpartyForceClosed {ref peer_msg, } => {
				let mut peer_msg_nonref = Clone::clone(peer_msg);
				ClosureReason::CounterpartyForceClosed {
					peer_msg: crate::lightning_types::string::UntrustedString { inner: ObjOps::heap_alloc(peer_msg_nonref), is_owned: true },
				}
			},
			nativeClosureReason::HolderForceClosed {ref broadcasted_latest_txn, } => {
				let mut broadcasted_latest_txn_nonref = Clone::clone(broadcasted_latest_txn);
				let mut local_broadcasted_latest_txn_nonref = if broadcasted_latest_txn_nonref.is_none() { crate::c_types::derived::COption_boolZ::None } else { crate::c_types::derived::COption_boolZ::Some( { broadcasted_latest_txn_nonref.unwrap() }) };
				ClosureReason::HolderForceClosed {
					broadcasted_latest_txn: local_broadcasted_latest_txn_nonref,
				}
			},
			nativeClosureReason::LegacyCooperativeClosure => ClosureReason::LegacyCooperativeClosure,
			nativeClosureReason::CounterpartyInitiatedCooperativeClosure => ClosureReason::CounterpartyInitiatedCooperativeClosure,
			nativeClosureReason::LocallyInitiatedCooperativeClosure => ClosureReason::LocallyInitiatedCooperativeClosure,
			nativeClosureReason::CommitmentTxConfirmed => ClosureReason::CommitmentTxConfirmed,
			nativeClosureReason::FundingTimedOut => ClosureReason::FundingTimedOut,
			nativeClosureReason::ProcessingError {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				ClosureReason::ProcessingError {
					err: err_nonref.into(),
				}
			},
			nativeClosureReason::DisconnectedPeer => ClosureReason::DisconnectedPeer,
			nativeClosureReason::OutdatedChannelManager => ClosureReason::OutdatedChannelManager,
			nativeClosureReason::CounterpartyCoopClosedUnfundedChannel => ClosureReason::CounterpartyCoopClosedUnfundedChannel,
			nativeClosureReason::FundingBatchClosure => ClosureReason::FundingBatchClosure,
			nativeClosureReason::HTLCsTimedOut => ClosureReason::HTLCsTimedOut,
			nativeClosureReason::PeerFeerateTooLow {ref peer_feerate_sat_per_kw, ref required_feerate_sat_per_kw, } => {
				let mut peer_feerate_sat_per_kw_nonref = Clone::clone(peer_feerate_sat_per_kw);
				let mut required_feerate_sat_per_kw_nonref = Clone::clone(required_feerate_sat_per_kw);
				ClosureReason::PeerFeerateTooLow {
					peer_feerate_sat_per_kw: peer_feerate_sat_per_kw_nonref,
					required_feerate_sat_per_kw: required_feerate_sat_per_kw_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeClosureReason) -> Self {
		match native {
			nativeClosureReason::CounterpartyForceClosed {mut peer_msg, } => {
				ClosureReason::CounterpartyForceClosed {
					peer_msg: crate::lightning_types::string::UntrustedString { inner: ObjOps::heap_alloc(peer_msg), is_owned: true },
				}
			},
			nativeClosureReason::HolderForceClosed {mut broadcasted_latest_txn, } => {
				let mut local_broadcasted_latest_txn = if broadcasted_latest_txn.is_none() { crate::c_types::derived::COption_boolZ::None } else { crate::c_types::derived::COption_boolZ::Some( { broadcasted_latest_txn.unwrap() }) };
				ClosureReason::HolderForceClosed {
					broadcasted_latest_txn: local_broadcasted_latest_txn,
				}
			},
			nativeClosureReason::LegacyCooperativeClosure => ClosureReason::LegacyCooperativeClosure,
			nativeClosureReason::CounterpartyInitiatedCooperativeClosure => ClosureReason::CounterpartyInitiatedCooperativeClosure,
			nativeClosureReason::LocallyInitiatedCooperativeClosure => ClosureReason::LocallyInitiatedCooperativeClosure,
			nativeClosureReason::CommitmentTxConfirmed => ClosureReason::CommitmentTxConfirmed,
			nativeClosureReason::FundingTimedOut => ClosureReason::FundingTimedOut,
			nativeClosureReason::ProcessingError {mut err, } => {
				ClosureReason::ProcessingError {
					err: err.into(),
				}
			},
			nativeClosureReason::DisconnectedPeer => ClosureReason::DisconnectedPeer,
			nativeClosureReason::OutdatedChannelManager => ClosureReason::OutdatedChannelManager,
			nativeClosureReason::CounterpartyCoopClosedUnfundedChannel => ClosureReason::CounterpartyCoopClosedUnfundedChannel,
			nativeClosureReason::FundingBatchClosure => ClosureReason::FundingBatchClosure,
			nativeClosureReason::HTLCsTimedOut => ClosureReason::HTLCsTimedOut,
			nativeClosureReason::PeerFeerateTooLow {mut peer_feerate_sat_per_kw, mut required_feerate_sat_per_kw, } => {
				ClosureReason::PeerFeerateTooLow {
					peer_feerate_sat_per_kw: peer_feerate_sat_per_kw,
					required_feerate_sat_per_kw: required_feerate_sat_per_kw,
				}
			},
		}
	}
}
/// Frees any resources used by the ClosureReason
#[no_mangle]
pub extern "C" fn ClosureReason_free(this_ptr: ClosureReason) { }
/// Creates a copy of the ClosureReason
#[no_mangle]
pub extern "C" fn ClosureReason_clone(orig: &ClosureReason) -> ClosureReason {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ClosureReason_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const ClosureReason)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ClosureReason_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut ClosureReason) };
}
#[no_mangle]
/// Utility method to constructs a new CounterpartyForceClosed-variant ClosureReason
pub extern "C" fn ClosureReason_counterparty_force_closed(peer_msg: crate::lightning_types::string::UntrustedString) -> ClosureReason {
	ClosureReason::CounterpartyForceClosed {
		peer_msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new HolderForceClosed-variant ClosureReason
pub extern "C" fn ClosureReason_holder_force_closed(broadcasted_latest_txn: crate::c_types::derived::COption_boolZ) -> ClosureReason {
	ClosureReason::HolderForceClosed {
		broadcasted_latest_txn,
	}
}
#[no_mangle]
/// Utility method to constructs a new LegacyCooperativeClosure-variant ClosureReason
pub extern "C" fn ClosureReason_legacy_cooperative_closure() -> ClosureReason {
	ClosureReason::LegacyCooperativeClosure}
#[no_mangle]
/// Utility method to constructs a new CounterpartyInitiatedCooperativeClosure-variant ClosureReason
pub extern "C" fn ClosureReason_counterparty_initiated_cooperative_closure() -> ClosureReason {
	ClosureReason::CounterpartyInitiatedCooperativeClosure}
#[no_mangle]
/// Utility method to constructs a new LocallyInitiatedCooperativeClosure-variant ClosureReason
pub extern "C" fn ClosureReason_locally_initiated_cooperative_closure() -> ClosureReason {
	ClosureReason::LocallyInitiatedCooperativeClosure}
#[no_mangle]
/// Utility method to constructs a new CommitmentTxConfirmed-variant ClosureReason
pub extern "C" fn ClosureReason_commitment_tx_confirmed() -> ClosureReason {
	ClosureReason::CommitmentTxConfirmed}
#[no_mangle]
/// Utility method to constructs a new FundingTimedOut-variant ClosureReason
pub extern "C" fn ClosureReason_funding_timed_out() -> ClosureReason {
	ClosureReason::FundingTimedOut}
#[no_mangle]
/// Utility method to constructs a new ProcessingError-variant ClosureReason
pub extern "C" fn ClosureReason_processing_error(err: crate::c_types::Str) -> ClosureReason {
	ClosureReason::ProcessingError {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new DisconnectedPeer-variant ClosureReason
pub extern "C" fn ClosureReason_disconnected_peer() -> ClosureReason {
	ClosureReason::DisconnectedPeer}
#[no_mangle]
/// Utility method to constructs a new OutdatedChannelManager-variant ClosureReason
pub extern "C" fn ClosureReason_outdated_channel_manager() -> ClosureReason {
	ClosureReason::OutdatedChannelManager}
#[no_mangle]
/// Utility method to constructs a new CounterpartyCoopClosedUnfundedChannel-variant ClosureReason
pub extern "C" fn ClosureReason_counterparty_coop_closed_unfunded_channel() -> ClosureReason {
	ClosureReason::CounterpartyCoopClosedUnfundedChannel}
#[no_mangle]
/// Utility method to constructs a new FundingBatchClosure-variant ClosureReason
pub extern "C" fn ClosureReason_funding_batch_closure() -> ClosureReason {
	ClosureReason::FundingBatchClosure}
#[no_mangle]
/// Utility method to constructs a new HTLCsTimedOut-variant ClosureReason
pub extern "C" fn ClosureReason_htlcs_timed_out() -> ClosureReason {
	ClosureReason::HTLCsTimedOut}
#[no_mangle]
/// Utility method to constructs a new PeerFeerateTooLow-variant ClosureReason
pub extern "C" fn ClosureReason_peer_feerate_too_low(peer_feerate_sat_per_kw: u32, required_feerate_sat_per_kw: u32) -> ClosureReason {
	ClosureReason::PeerFeerateTooLow {
		peer_feerate_sat_per_kw,
		required_feerate_sat_per_kw,
	}
}
/// Get a string which allows debug introspection of a ClosureReason object
pub extern "C" fn ClosureReason_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::ClosureReason }).into()}
/// Checks if two ClosureReasons contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ClosureReason_eq(a: &ClosureReason, b: &ClosureReason) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Get the string representation of a ClosureReason object
pub extern "C" fn ClosureReason_to_str(o: &crate::lightning::events::ClosureReason) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
#[no_mangle]
/// Serialize the ClosureReason object into a byte array which can be read by ClosureReason_read
pub extern "C" fn ClosureReason_write(obj: &crate::lightning::events::ClosureReason) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn ClosureReason_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	ClosureReason_write(unsafe { &*(obj as *const ClosureReason) })
}
#[no_mangle]
/// Read a ClosureReason from a byte array, created by ClosureReason_write
pub extern "C" fn ClosureReason_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_ClosureReasonZDecodeErrorZ {
	let res: Result<Option<lightning::events::ClosureReason>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_ClosureReasonZ::None } else { crate::c_types::derived::COption_ClosureReasonZ::Some( { crate::lightning::events::ClosureReason::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Intended destination of a failed HTLC as indicated in [`Event::HTLCHandlingFailed`].
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum HTLCDestination {
	/// We tried forwarding to a channel but failed to do so. An example of such an instance is when
	/// there is insufficient capacity in our outbound channel.
	NextHopChannel {
		/// The `node_id` of the next node. For backwards compatibility, this field is
		/// marked as optional, versions prior to 0.0.110 may not always be able to provide
		/// counterparty node information.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		node_id: crate::c_types::PublicKey,
		/// The outgoing `channel_id` between us and the next node.
		channel_id: crate::lightning::ln::types::ChannelId,
	},
	/// Scenario where we are unsure of the next node to forward the HTLC to.
	UnknownNextHop {
		/// Short channel id we are requesting to forward an HTLC to.
		requested_forward_scid: u64,
	},
	/// We couldn't forward to the outgoing scid. An example would be attempting to send a duplicate
	/// intercept HTLC.
	InvalidForward {
		/// Short channel id we are requesting to forward an HTLC to.
		requested_forward_scid: u64,
	},
	/// We couldn't decode the incoming onion to obtain the forwarding details.
	InvalidOnion,
	/// Failure scenario where an HTLC may have been forwarded to be intended for us,
	/// but is invalid for some reason, so we reject it.
	///
	/// Some of the reasons may include:
	/// * HTLC Timeouts
	/// * Excess HTLCs for a payment that we have already fully received, over-paying for the
	///   payment,
	/// * The counterparty node modified the HTLC in transit,
	/// * A probing attack where an intermediary node is trying to detect if we are the ultimate
	///   recipient for a payment.
	FailedPayment {
		/// The payment hash of the payment we attempted to process.
		payment_hash: crate::c_types::ThirtyTwoBytes,
	},
}
use lightning::events::HTLCDestination as HTLCDestinationImport;
pub(crate) type nativeHTLCDestination = HTLCDestinationImport;

impl HTLCDestination {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeHTLCDestination {
		match self {
			HTLCDestination::NextHopChannel {ref node_id, ref channel_id, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut local_node_id_nonref = if node_id_nonref.is_null() { None } else { Some( { node_id_nonref.into_rust() }) };
				let mut channel_id_nonref = Clone::clone(channel_id);
				nativeHTLCDestination::NextHopChannel {
					node_id: local_node_id_nonref,
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
				}
			},
			HTLCDestination::UnknownNextHop {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				nativeHTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			HTLCDestination::InvalidForward {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				nativeHTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			HTLCDestination::InvalidOnion => nativeHTLCDestination::InvalidOnion,
			HTLCDestination::FailedPayment {ref payment_hash, } => {
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				nativeHTLCDestination::FailedPayment {
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeHTLCDestination {
		match self {
			HTLCDestination::NextHopChannel {mut node_id, mut channel_id, } => {
				let mut local_node_id = if node_id.is_null() { None } else { Some( { node_id.into_rust() }) };
				nativeHTLCDestination::NextHopChannel {
					node_id: local_node_id,
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
				}
			},
			HTLCDestination::UnknownNextHop {mut requested_forward_scid, } => {
				nativeHTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid,
				}
			},
			HTLCDestination::InvalidForward {mut requested_forward_scid, } => {
				nativeHTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid,
				}
			},
			HTLCDestination::InvalidOnion => nativeHTLCDestination::InvalidOnion,
			HTLCDestination::FailedPayment {mut payment_hash, } => {
				nativeHTLCDestination::FailedPayment {
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &HTLCDestinationImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeHTLCDestination) };
		match native {
			nativeHTLCDestination::NextHopChannel {ref node_id, ref channel_id, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut local_node_id_nonref = if node_id_nonref.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(node_id_nonref.unwrap())) } };
				let mut channel_id_nonref = Clone::clone(channel_id);
				HTLCDestination::NextHopChannel {
					node_id: local_node_id_nonref,
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
				}
			},
			nativeHTLCDestination::UnknownNextHop {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				HTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			nativeHTLCDestination::InvalidForward {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				HTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			nativeHTLCDestination::InvalidOnion => HTLCDestination::InvalidOnion,
			nativeHTLCDestination::FailedPayment {ref payment_hash, } => {
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				HTLCDestination::FailedPayment {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeHTLCDestination) -> Self {
		match native {
			nativeHTLCDestination::NextHopChannel {mut node_id, mut channel_id, } => {
				let mut local_node_id = if node_id.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(node_id.unwrap())) } };
				HTLCDestination::NextHopChannel {
					node_id: local_node_id,
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
				}
			},
			nativeHTLCDestination::UnknownNextHop {mut requested_forward_scid, } => {
				HTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid,
				}
			},
			nativeHTLCDestination::InvalidForward {mut requested_forward_scid, } => {
				HTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid,
				}
			},
			nativeHTLCDestination::InvalidOnion => HTLCDestination::InvalidOnion,
			nativeHTLCDestination::FailedPayment {mut payment_hash, } => {
				HTLCDestination::FailedPayment {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
				}
			},
		}
	}
}
/// Frees any resources used by the HTLCDestination
#[no_mangle]
pub extern "C" fn HTLCDestination_free(this_ptr: HTLCDestination) { }
/// Creates a copy of the HTLCDestination
#[no_mangle]
pub extern "C" fn HTLCDestination_clone(orig: &HTLCDestination) -> HTLCDestination {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCDestination_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const HTLCDestination)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCDestination_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut HTLCDestination) };
}
#[no_mangle]
/// Utility method to constructs a new NextHopChannel-variant HTLCDestination
pub extern "C" fn HTLCDestination_next_hop_channel(node_id: crate::c_types::PublicKey, channel_id: crate::lightning::ln::types::ChannelId) -> HTLCDestination {
	HTLCDestination::NextHopChannel {
		node_id,
		channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new UnknownNextHop-variant HTLCDestination
pub extern "C" fn HTLCDestination_unknown_next_hop(requested_forward_scid: u64) -> HTLCDestination {
	HTLCDestination::UnknownNextHop {
		requested_forward_scid,
	}
}
#[no_mangle]
/// Utility method to constructs a new InvalidForward-variant HTLCDestination
pub extern "C" fn HTLCDestination_invalid_forward(requested_forward_scid: u64) -> HTLCDestination {
	HTLCDestination::InvalidForward {
		requested_forward_scid,
	}
}
#[no_mangle]
/// Utility method to constructs a new InvalidOnion-variant HTLCDestination
pub extern "C" fn HTLCDestination_invalid_onion() -> HTLCDestination {
	HTLCDestination::InvalidOnion}
#[no_mangle]
/// Utility method to constructs a new FailedPayment-variant HTLCDestination
pub extern "C" fn HTLCDestination_failed_payment(payment_hash: crate::c_types::ThirtyTwoBytes) -> HTLCDestination {
	HTLCDestination::FailedPayment {
		payment_hash,
	}
}
/// Get a string which allows debug introspection of a HTLCDestination object
pub extern "C" fn HTLCDestination_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::HTLCDestination }).into()}
/// Checks if two HTLCDestinations contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn HTLCDestination_eq(a: &HTLCDestination, b: &HTLCDestination) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the HTLCDestination object into a byte array which can be read by HTLCDestination_read
pub extern "C" fn HTLCDestination_write(obj: &crate::lightning::events::HTLCDestination) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn HTLCDestination_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	HTLCDestination_write(unsafe { &*(obj as *const HTLCDestination) })
}
#[no_mangle]
/// Read a HTLCDestination from a byte array, created by HTLCDestination_write
pub extern "C" fn HTLCDestination_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_HTLCDestinationZDecodeErrorZ {
	let res: Result<Option<lightning::events::HTLCDestination>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_HTLCDestinationZ::None } else { crate::c_types::derived::COption_HTLCDestinationZ::Some( { crate::lightning::events::HTLCDestination::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// The reason the payment failed. Used in [`Event::PaymentFailed`].
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PaymentFailureReason {
	/// The intended recipient rejected our payment.
	///
	/// Also used for [`UnknownRequiredFeatures`] and [`InvoiceRequestRejected`] when downgrading to
	/// version prior to 0.0.124.
	///
	/// [`UnknownRequiredFeatures`]: Self::UnknownRequiredFeatures
	/// [`InvoiceRequestRejected`]: Self::InvoiceRequestRejected
	RecipientRejected,
	/// The user chose to abandon this payment by calling [`ChannelManager::abandon_payment`].
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	UserAbandoned,
	/// We exhausted all of our retry attempts while trying to send the payment, or we
	/// exhausted the [`Retry::Timeout`] if the user set one. If at any point a retry
	/// attempt failed while being forwarded along the path, an [`Event::PaymentPathFailed`] will
	/// have come before this.
	///
	/// [`Retry::Timeout`]: crate::ln::channelmanager::Retry::Timeout
	RetriesExhausted,
	/// The payment expired while retrying, based on the provided
	/// [`PaymentParameters::expiry_time`].
	///
	/// Also used for [`InvoiceRequestExpired`] when downgrading to version prior to 0.0.124.
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
	/// [`InvoiceRequestExpired`]: Self::InvoiceRequestExpired
	PaymentExpired,
	/// We failed to find a route while retrying the payment.
	///
	/// Note that this generally indicates that we've exhausted the available set of possible
	/// routes - we tried the payment over a few routes but were not able to find any further
	/// candidate routes beyond those.
	RouteNotFound,
	/// This error should generally never happen. This likely means that there is a problem with
	/// your router.
	UnexpectedError,
	/// An invoice was received that required unknown features.
	UnknownRequiredFeatures,
	/// A [`Bolt12Invoice`] was not received in a reasonable amount of time.
	InvoiceRequestExpired,
	/// An [`InvoiceRequest`] for the payment was rejected by the recipient.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	InvoiceRequestRejected,
}
use lightning::events::PaymentFailureReason as PaymentFailureReasonImport;
pub(crate) type nativePaymentFailureReason = PaymentFailureReasonImport;

impl PaymentFailureReason {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentFailureReason {
		match self {
			PaymentFailureReason::RecipientRejected => nativePaymentFailureReason::RecipientRejected,
			PaymentFailureReason::UserAbandoned => nativePaymentFailureReason::UserAbandoned,
			PaymentFailureReason::RetriesExhausted => nativePaymentFailureReason::RetriesExhausted,
			PaymentFailureReason::PaymentExpired => nativePaymentFailureReason::PaymentExpired,
			PaymentFailureReason::RouteNotFound => nativePaymentFailureReason::RouteNotFound,
			PaymentFailureReason::UnexpectedError => nativePaymentFailureReason::UnexpectedError,
			PaymentFailureReason::UnknownRequiredFeatures => nativePaymentFailureReason::UnknownRequiredFeatures,
			PaymentFailureReason::InvoiceRequestExpired => nativePaymentFailureReason::InvoiceRequestExpired,
			PaymentFailureReason::InvoiceRequestRejected => nativePaymentFailureReason::InvoiceRequestRejected,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePaymentFailureReason {
		match self {
			PaymentFailureReason::RecipientRejected => nativePaymentFailureReason::RecipientRejected,
			PaymentFailureReason::UserAbandoned => nativePaymentFailureReason::UserAbandoned,
			PaymentFailureReason::RetriesExhausted => nativePaymentFailureReason::RetriesExhausted,
			PaymentFailureReason::PaymentExpired => nativePaymentFailureReason::PaymentExpired,
			PaymentFailureReason::RouteNotFound => nativePaymentFailureReason::RouteNotFound,
			PaymentFailureReason::UnexpectedError => nativePaymentFailureReason::UnexpectedError,
			PaymentFailureReason::UnknownRequiredFeatures => nativePaymentFailureReason::UnknownRequiredFeatures,
			PaymentFailureReason::InvoiceRequestExpired => nativePaymentFailureReason::InvoiceRequestExpired,
			PaymentFailureReason::InvoiceRequestRejected => nativePaymentFailureReason::InvoiceRequestRejected,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &PaymentFailureReasonImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativePaymentFailureReason) };
		match native {
			nativePaymentFailureReason::RecipientRejected => PaymentFailureReason::RecipientRejected,
			nativePaymentFailureReason::UserAbandoned => PaymentFailureReason::UserAbandoned,
			nativePaymentFailureReason::RetriesExhausted => PaymentFailureReason::RetriesExhausted,
			nativePaymentFailureReason::PaymentExpired => PaymentFailureReason::PaymentExpired,
			nativePaymentFailureReason::RouteNotFound => PaymentFailureReason::RouteNotFound,
			nativePaymentFailureReason::UnexpectedError => PaymentFailureReason::UnexpectedError,
			nativePaymentFailureReason::UnknownRequiredFeatures => PaymentFailureReason::UnknownRequiredFeatures,
			nativePaymentFailureReason::InvoiceRequestExpired => PaymentFailureReason::InvoiceRequestExpired,
			nativePaymentFailureReason::InvoiceRequestRejected => PaymentFailureReason::InvoiceRequestRejected,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePaymentFailureReason) -> Self {
		match native {
			nativePaymentFailureReason::RecipientRejected => PaymentFailureReason::RecipientRejected,
			nativePaymentFailureReason::UserAbandoned => PaymentFailureReason::UserAbandoned,
			nativePaymentFailureReason::RetriesExhausted => PaymentFailureReason::RetriesExhausted,
			nativePaymentFailureReason::PaymentExpired => PaymentFailureReason::PaymentExpired,
			nativePaymentFailureReason::RouteNotFound => PaymentFailureReason::RouteNotFound,
			nativePaymentFailureReason::UnexpectedError => PaymentFailureReason::UnexpectedError,
			nativePaymentFailureReason::UnknownRequiredFeatures => PaymentFailureReason::UnknownRequiredFeatures,
			nativePaymentFailureReason::InvoiceRequestExpired => PaymentFailureReason::InvoiceRequestExpired,
			nativePaymentFailureReason::InvoiceRequestRejected => PaymentFailureReason::InvoiceRequestRejected,
		}
	}
}
/// Creates a copy of the PaymentFailureReason
#[no_mangle]
pub extern "C" fn PaymentFailureReason_clone(orig: &PaymentFailureReason) -> PaymentFailureReason {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentFailureReason_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const PaymentFailureReason)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentFailureReason_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut PaymentFailureReason) };
}
#[no_mangle]
/// Utility method to constructs a new RecipientRejected-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_recipient_rejected() -> PaymentFailureReason {
	PaymentFailureReason::RecipientRejected}
#[no_mangle]
/// Utility method to constructs a new UserAbandoned-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_user_abandoned() -> PaymentFailureReason {
	PaymentFailureReason::UserAbandoned}
#[no_mangle]
/// Utility method to constructs a new RetriesExhausted-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_retries_exhausted() -> PaymentFailureReason {
	PaymentFailureReason::RetriesExhausted}
#[no_mangle]
/// Utility method to constructs a new PaymentExpired-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_payment_expired() -> PaymentFailureReason {
	PaymentFailureReason::PaymentExpired}
#[no_mangle]
/// Utility method to constructs a new RouteNotFound-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_route_not_found() -> PaymentFailureReason {
	PaymentFailureReason::RouteNotFound}
#[no_mangle]
/// Utility method to constructs a new UnexpectedError-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_unexpected_error() -> PaymentFailureReason {
	PaymentFailureReason::UnexpectedError}
#[no_mangle]
/// Utility method to constructs a new UnknownRequiredFeatures-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_unknown_required_features() -> PaymentFailureReason {
	PaymentFailureReason::UnknownRequiredFeatures}
#[no_mangle]
/// Utility method to constructs a new InvoiceRequestExpired-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_invoice_request_expired() -> PaymentFailureReason {
	PaymentFailureReason::InvoiceRequestExpired}
#[no_mangle]
/// Utility method to constructs a new InvoiceRequestRejected-variant PaymentFailureReason
pub extern "C" fn PaymentFailureReason_invoice_request_rejected() -> PaymentFailureReason {
	PaymentFailureReason::InvoiceRequestRejected}
/// Get a string which allows debug introspection of a PaymentFailureReason object
pub extern "C" fn PaymentFailureReason_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::PaymentFailureReason }).into()}
/// Checks if two PaymentFailureReasons contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn PaymentFailureReason_eq(a: &PaymentFailureReason, b: &PaymentFailureReason) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the PaymentFailureReason object into a byte array which can be read by PaymentFailureReason_read
pub extern "C" fn PaymentFailureReason_write(obj: &crate::lightning::events::PaymentFailureReason) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentFailureReason_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	PaymentFailureReason_write(unsafe { &*(obj as *const PaymentFailureReason) })
}
#[no_mangle]
/// Read a PaymentFailureReason from a byte array, created by PaymentFailureReason_write
pub extern "C" fn PaymentFailureReason_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_PaymentFailureReasonZDecodeErrorZ {
	let res: Result<Option<lightning::events::PaymentFailureReason>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_PaymentFailureReasonZ::None } else { crate::c_types::derived::COption_PaymentFailureReasonZ::Some( { crate::lightning::events::PaymentFailureReason::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// An Event which you should probably take some action in response to.
///
/// Note that while Writeable and Readable are implemented for Event, you probably shouldn't use
/// them directly as they don't round-trip exactly (for example FundingGenerationReady is never
/// written as it makes no sense to respond to it after reconnecting to peers).
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Event {
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call [`ChannelManager::funding_transaction_generated`].
	/// Generated in [`ChannelManager`] message handling.
	/// Note that *all inputs* in the funding transaction must spend SegWit outputs or your
	/// counterparty can steal your funds!
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`), but won't be persisted across restarts.
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
	FundingGenerationReady {
		/// The random channel_id we picked which you'll need to pass into
		/// [`ChannelManager::funding_transaction_generated`].
		///
		/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
		temporary_channel_id: crate::lightning::ln::types::ChannelId,
		/// The counterparty's node_id, which you'll need to pass back into
		/// [`ChannelManager::funding_transaction_generated`].
		///
		/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
		counterparty_node_id: crate::c_types::PublicKey,
		/// The value, in satoshis, that the output should have.
		channel_value_satoshis: u64,
		/// The script which should be used in the transaction output.
		output_script: crate::c_types::derived::CVec_u8Z,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.  This may be zero for objects
		/// serialized with LDK versions prior to 0.0.113.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: crate::c_types::U128,
	},
	/// Used to indicate that the counterparty node has provided the signature(s) required to
	/// recover our funds in case they go offline.
	///
	/// It is safe (and your responsibility) to broadcast the funding transaction upon receiving this
	/// event.
	///
	/// This event is only emitted if you called
	/// [`ChannelManager::unsafe_manual_funding_transaction_generated`] instead of
	/// [`ChannelManager::funding_transaction_generated`].
	///
	/// [`ChannelManager::unsafe_manual_funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::unsafe_manual_funding_transaction_generated
	/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
	FundingTxBroadcastSafe {
		/// The `channel_id` indicating which channel has reached this stage.
		channel_id: crate::lightning::ln::types::ChannelId,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`].
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		user_channel_id: crate::c_types::U128,
		/// The outpoint of the channel's funding transaction.
		funding_txo: crate::lightning::chain::transaction::OutPoint,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The `temporary_channel_id` this channel used to be known by during channel establishment.
		former_temporary_channel_id: crate::lightning::ln::types::ChannelId,
	},
	/// Indicates that we've been offered a payment and it needs to be claimed via calling
	/// [`ChannelManager::claim_funds`] with the preimage given in [`PaymentPurpose`].
	///
	/// Note that if the preimage is not known, you should call
	/// [`ChannelManager::fail_htlc_backwards`] or [`ChannelManager::fail_htlc_backwards_with_reason`]
	/// to free up resources for this HTLC and avoid network congestion.
	///
	/// If [`Event::PaymentClaimable::onion_fields`] is `Some`, and includes custom TLVs with even type
	/// numbers, you should use [`ChannelManager::fail_htlc_backwards_with_reason`] with
	/// [`FailureCode::InvalidOnionPayload`] if you fail to understand and handle the contents, or
	/// [`ChannelManager::claim_funds_with_known_custom_tlvs`] upon successful handling.
	/// If you don't intend to check for custom TLVs, you can simply use
	/// [`ChannelManager::claim_funds`], which will automatically fail back even custom TLVs.
	///
	/// If you fail to call [`ChannelManager::claim_funds`],
	/// [`ChannelManager::claim_funds_with_known_custom_tlvs`],
	/// [`ChannelManager::fail_htlc_backwards`], or
	/// [`ChannelManager::fail_htlc_backwards_with_reason`] within the HTLC's timeout, the HTLC will
	/// be automatically failed.
	///
	/// # Note
	/// LDK will not stop an inbound payment from being paid multiple times, so multiple
	/// `PaymentClaimable` events may be generated for the same payment. In such a case it is
	/// polite (and required in the lightning specification) to fail the payment the second time
	/// and give the sender their money back rather than accepting double payment.
	///
	/// # Note
	/// This event used to be called `PaymentReceived` in LDK versions 0.0.112 and earlier.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	/// [`ChannelManager::claim_funds_with_known_custom_tlvs`]: crate::ln::channelmanager::ChannelManager::claim_funds_with_known_custom_tlvs
	/// [`FailureCode::InvalidOnionPayload`]: crate::ln::channelmanager::FailureCode::InvalidOnionPayload
	/// [`ChannelManager::fail_htlc_backwards`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards
	/// [`ChannelManager::fail_htlc_backwards_with_reason`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards_with_reason
	PaymentClaimable {
		/// The node that will receive the payment after it has been claimed.
		/// This is useful to identify payments received via [phantom nodes].
		/// This field will always be filled in when the event was generated by LDK versions
		/// 0.0.113 and above.
		///
		/// [phantom nodes]: crate::sign::PhantomKeysManager
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		receiver_node_id: crate::c_types::PublicKey,
		/// The hash for which the preimage should be handed to the ChannelManager. Note that LDK will
		/// not stop you from registering duplicate payment hashes for inbound payments.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The fields in the onion which were received with each HTLC. Only fields which were
		/// identical in each HTLC involved in the payment will be included here.
		///
		/// Payments received on LDK versions prior to 0.0.115 will have this field unset.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		onion_fields: crate::lightning::ln::outbound_payment::RecipientOnionFields,
		/// The value, in thousandths of a satoshi, that this payment is claimable for. May be greater
		/// than the invoice amount.
		///
		/// May be less than the invoice amount if [`ChannelConfig::accept_underpaying_htlcs`] is set
		/// and the previous hop took an extra fee.
		///
		/// # Note
		/// If [`ChannelConfig::accept_underpaying_htlcs`] is set and you claim without verifying this
		/// field, you may lose money!
		///
		/// [`ChannelConfig::accept_underpaying_htlcs`]: crate::util::config::ChannelConfig::accept_underpaying_htlcs
		amount_msat: u64,
		/// The value, in thousands of a satoshi, that was skimmed off of this payment as an extra fee
		/// taken by our channel counterparty.
		///
		/// Will always be 0 unless [`ChannelConfig::accept_underpaying_htlcs`] is set.
		///
		/// [`ChannelConfig::accept_underpaying_htlcs`]: crate::util::config::ChannelConfig::accept_underpaying_htlcs
		counterparty_skimmed_fee_msat: u64,
		/// Information for claiming this received payment, based on whether the purpose of the
		/// payment is to pay an invoice or to send a spontaneous payment.
		purpose: crate::lightning::events::PaymentPurpose,
		/// The `channel_id` indicating over which channel we received the payment.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		via_channel_id: crate::lightning::ln::types::ChannelId,
		/// The `user_channel_id` indicating over which channel we received the payment.
		via_user_channel_id: crate::c_types::derived::COption_U128Z,
		/// The block height at which this payment will be failed back and will no longer be
		/// eligible for claiming.
		///
		/// Prior to this height, a call to [`ChannelManager::claim_funds`] is guaranteed to
		/// succeed, however you should wait for [`Event::PaymentClaimed`] to be sure.
		///
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		claim_deadline: crate::c_types::derived::COption_u32Z,
	},
	/// Indicates a payment has been claimed and we've received money!
	///
	/// This most likely occurs when [`ChannelManager::claim_funds`] has been called in response
	/// to an [`Event::PaymentClaimable`]. However, if we previously crashed during a
	/// [`ChannelManager::claim_funds`] call you may see this event without a corresponding
	/// [`Event::PaymentClaimable`] event.
	///
	/// # Note
	/// LDK will not stop an inbound payment from being paid multiple times, so multiple
	/// `PaymentClaimable` events may be generated for the same payment. If you then call
	/// [`ChannelManager::claim_funds`] twice for the same [`Event::PaymentClaimable`] you may get
	/// multiple `PaymentClaimed` events.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	PaymentClaimed {
		/// The node that received the payment.
		/// This is useful to identify payments which were received via [phantom nodes].
		/// This field will always be filled in when the event was generated by LDK versions
		/// 0.0.113 and above.
		///
		/// [phantom nodes]: crate::sign::PhantomKeysManager
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		receiver_node_id: crate::c_types::PublicKey,
		/// The payment hash of the claimed payment. Note that LDK will not stop you from
		/// registering duplicate payment hashes for inbound payments.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The value, in thousandths of a satoshi, that this payment is for. May be greater than the
		/// invoice amount.
		amount_msat: u64,
		/// The purpose of the claimed payment, i.e. whether the payment was for an invoice or a
		/// spontaneous payment.
		purpose: crate::lightning::events::PaymentPurpose,
		/// The HTLCs that comprise the claimed payment. This will be empty for events serialized prior
		/// to LDK version 0.0.117.
		htlcs: crate::c_types::derived::CVec_ClaimedHTLCZ,
		/// The sender-intended sum total of all the MPP parts. This will be `None` for events
		/// serialized prior to LDK version 0.0.117.
		sender_intended_total_msat: crate::c_types::derived::COption_u64Z,
		/// The fields in the onion which were received with each HTLC. Only fields which were
		/// identical in each HTLC involved in the payment will be included here.
		///
		/// Payments received on LDK versions prior to 0.0.124 will have this field unset.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		onion_fields: crate::lightning::ln::outbound_payment::RecipientOnionFields,
	},
	/// Indicates that a peer connection with a node is needed in order to send an [`OnionMessage`].
	///
	/// Typically, this happens when a [`MessageRouter`] is unable to find a complete path to a
	/// [`Destination`]. Once a connection is established, any messages buffered by an
	/// [`OnionMessageHandler`] may be sent.
	///
	/// This event will not be generated for onion message forwards; only for sends including
	/// replies. Handlers should connect to the node otherwise any buffered messages may be lost.
	///
	/// # Failure Behavior and Persistence
	/// This event won't be replayed after failures-to-handle
	/// (i.e., the event handler returning `Err(ReplayEvent ())`), and also won't be persisted
	/// across restarts.
	///
	/// [`OnionMessage`]: msgs::OnionMessage
	/// [`MessageRouter`]: crate::onion_message::messenger::MessageRouter
	/// [`Destination`]: crate::onion_message::messenger::Destination
	/// [`OnionMessageHandler`]: crate::ln::msgs::OnionMessageHandler
	ConnectionNeeded {
		/// The node id for the node needing a connection.
		node_id: crate::c_types::PublicKey,
		/// Sockets for connecting to the node.
		addresses: crate::c_types::derived::CVec_SocketAddressZ,
	},
	/// Indicates a [`Bolt12Invoice`] in response to an [`InvoiceRequest`] or a [`Refund`] was
	/// received.
	///
	/// This event will only be generated if [`UserConfig::manually_handle_bolt12_invoices`] is set.
	/// Use [`ChannelManager::send_payment_for_bolt12_invoice`] to pay the invoice or
	/// [`ChannelManager::abandon_payment`] to abandon the associated payment. See those docs for
	/// further details.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`UserConfig::manually_handle_bolt12_invoices`]: crate::util::config::UserConfig::manually_handle_bolt12_invoices
	/// [`ChannelManager::send_payment_for_bolt12_invoice`]: crate::ln::channelmanager::ChannelManager::send_payment_for_bolt12_invoice
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	InvoiceReceived {
		/// The `payment_id` associated with payment for the invoice.
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The invoice to pay.
		invoice: crate::lightning::offers::invoice::Bolt12Invoice,
		/// The context of the [`BlindedMessagePath`] used to send the invoice.
		///
		/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
		context: crate::c_types::derived::COption_OffersContextZ,
		/// A responder for replying with an [`InvoiceError`] if needed.
		///
		/// `None` if the invoice wasn't sent with a reply path.
		///
		/// [`InvoiceError`]: crate::offers::invoice_error::InvoiceError
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		responder: crate::lightning::onion_message::messenger::Responder,
	},
	/// Indicates an outbound payment we made succeeded (i.e. it made it all the way to its target
	/// and we got back the payment preimage for it).
	///
	/// Note for MPP payments: in rare cases, this event may be preceded by a `PaymentPathFailed`
	/// event. In this situation, you SHOULD treat this payment as having succeeded.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	PaymentSent {
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: crate::c_types::derived::COption_ThirtyTwoBytesZ,
		/// The preimage to the hash given to ChannelManager::send_payment.
		/// Note that this serves as a payment receipt, if you wish to have such a thing, you must
		/// store it somehow!
		payment_preimage: crate::c_types::ThirtyTwoBytes,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The total fee which was spent at intermediate hops in this payment, across all paths.
		///
		/// Note that, like [`Route::get_total_fees`] this does *not* include any potential
		/// overpayment to the recipient node.
		///
		/// If the recipient or an intermediate node misbehaves and gives us free money, this may
		/// overstate the amount paid, though this is unlikely.
		///
		/// This is only `None` for payments initiated on LDK versions prior to 0.0.103.
		///
		/// [`Route::get_total_fees`]: crate::routing::router::Route::get_total_fees
		fee_paid_msat: crate::c_types::derived::COption_u64Z,
	},
	/// Indicates an outbound payment failed. Individual [`Event::PaymentPathFailed`] events
	/// provide failure information for each path attempt in the payment, including retries.
	///
	/// This event is provided once there are no further pending HTLCs for the payment and the
	/// payment is no longer retryable, due either to the [`Retry`] provided or
	/// [`ChannelManager::abandon_payment`] having been called for the corresponding payment.
	///
	/// In exceedingly rare cases, it is possible that an [`Event::PaymentFailed`] is generated for
	/// a payment after an [`Event::PaymentSent`] event for this same payment has already been
	/// received and processed. In this case, the [`Event::PaymentFailed`] event MUST be ignored,
	/// and the payment MUST be treated as having succeeded.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`Retry`]: crate::ln::channelmanager::Retry
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	PaymentFailed {
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash that was given to [`ChannelManager::send_payment`]. `None` if the payment failed
		/// before receiving an invoice when paying a BOLT12 [`Offer`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`Offer`]: crate::offers::offer::Offer
		payment_hash: crate::c_types::derived::COption_ThirtyTwoBytesZ,
		/// The reason the payment failed. This is only `None` for events generated or serialized
		/// by versions prior to 0.0.115, or when downgrading to a version with a reason that was
		/// added after.
		reason: crate::c_types::derived::COption_PaymentFailureReasonZ,
	},
	/// Indicates that a path for an outbound payment was successful.
	///
	/// Always generated after [`Event::PaymentSent`] and thus useful for scoring channels. See
	/// [`Event::PaymentSent`] for obtaining the payment preimage.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	PaymentPathSuccessful {
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// This will be `Some` for all payments which completed on LDK 0.0.104 or later.
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: crate::c_types::derived::COption_ThirtyTwoBytesZ,
		/// The payment path that was successful.
		///
		/// May contain a closed channel if the HTLC sent along the path was fulfilled on chain.
		path: crate::lightning::routing::router::Path,
	},
	/// Indicates an outbound HTLC we sent failed, likely due to an intermediary node being unable to
	/// handle the HTLC.
	///
	/// Note that this does *not* indicate that all paths for an MPP payment have failed, see
	/// [`Event::PaymentFailed`].
	///
	/// See [`ChannelManager::abandon_payment`] for giving up on this payment before its retries have
	/// been exhausted.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	PaymentPathFailed {
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
		///
		/// This will be `Some` for all payment paths which failed on LDK 0.0.103 or later.
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
		payment_id: crate::c_types::derived::COption_ThirtyTwoBytesZ,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, the payment may
		/// be retried via a different route.
		payment_failed_permanently: bool,
		/// Extra error details based on the failure type. May contain an update that needs to be
		/// applied to the [`NetworkGraph`].
		///
		/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
		failure: crate::lightning::events::PathFailure,
		/// The payment path that failed.
		path: crate::lightning::routing::router::Path,
		/// The channel responsible for the failed payment path.
		///
		/// Note that for route hints or for the first hop in a path this may be an SCID alias and
		/// may not refer to a channel in the public network graph. These aliases may also collide
		/// with channels in the public network graph.
		///
		/// If this is `Some`, then the corresponding channel should be avoided when the payment is
		/// retried. May be `None` for older [`Event`] serializations.
		short_channel_id: crate::c_types::derived::COption_u64Z,
	},
	/// Indicates that a probe payment we sent returned successful, i.e., only failed at the destination.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	ProbeSuccessful {
		/// The id returned by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash generated by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The payment path that was successful.
		path: crate::lightning::routing::router::Path,
	},
	/// Indicates that a probe payment we sent failed at an intermediary node on the path.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	ProbeFailed {
		/// The id returned by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash generated by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The payment path that failed.
		path: crate::lightning::routing::router::Path,
		/// The channel responsible for the failed probe.
		///
		/// Note that for route hints or for the first hop in a path this may be an SCID alias and
		/// may not refer to a channel in the public network graph. These aliases may also collide
		/// with channels in the public network graph.
		short_channel_id: crate::c_types::derived::COption_u64Z,
	},
	/// Used to indicate that [`ChannelManager::process_pending_htlc_forwards`] should be called at
	/// a time in the future.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be regenerated after restarts.
	///
	/// [`ChannelManager::process_pending_htlc_forwards`]: crate::ln::channelmanager::ChannelManager::process_pending_htlc_forwards
	PendingHTLCsForwardable {
		/// The minimum amount of time that should be waited prior to calling
		/// process_pending_htlc_forwards. To increase the effort required to correlate payments,
		/// you should wait a random amount of time in roughly the range (now + time_forwardable,
		/// now + 5*time_forwardable).
		time_forwardable: u64,
	},
	/// Used to indicate that we've intercepted an HTLC forward. This event will only be generated if
	/// you've encoded an intercept scid in the receiver's invoice route hints using
	/// [`ChannelManager::get_intercept_scid`] and have set [`UserConfig::accept_intercept_htlcs`].
	///
	/// [`ChannelManager::forward_intercepted_htlc`] or
	/// [`ChannelManager::fail_intercepted_htlc`] MUST be called in response to this event. See
	/// their docs for more information.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
	/// [`UserConfig::accept_intercept_htlcs`]: crate::util::config::UserConfig::accept_intercept_htlcs
	/// [`ChannelManager::forward_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::forward_intercepted_htlc
	/// [`ChannelManager::fail_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::fail_intercepted_htlc
	HTLCIntercepted {
		/// An id to help LDK identify which HTLC is being forwarded or failed.
		intercept_id: crate::c_types::ThirtyTwoBytes,
		/// The fake scid that was programmed as the next hop's scid, generated using
		/// [`ChannelManager::get_intercept_scid`].
		///
		/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
		requested_next_hop_scid: u64,
		/// The payment hash used for this HTLC.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// How many msats were received on the inbound edge of this HTLC.
		inbound_amount_msat: u64,
		/// How many msats the payer intended to route to the next node. Depending on the reason you are
		/// intercepting this payment, you might take a fee by forwarding less than this amount.
		/// Forwarding less than this amount may break compatibility with LDK versions prior to 0.0.116.
		///
		/// Note that LDK will NOT check that expected fees were factored into this value. You MUST
		/// check that whatever fee you want has been included here or subtract it as required. Further,
		/// LDK will not stop you from forwarding more than you received.
		expected_outbound_amount_msat: u64,
	},
	/// Used to indicate that an output which you should know how to spend was confirmed on chain
	/// and is now spendable.
	///
	/// Such an output will *never* be spent directly by LDK, and are not at risk of your
	/// counterparty spending them due to some kind of timeout. Thus, you need to store them
	/// somewhere and spend them when you create on-chain transactions.
	///
	/// You may hand them to the [`OutputSweeper`] utility which will store and (re-)generate spending
	/// transactions for you.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`OutputSweeper`]: crate::util::sweep::OutputSweeper
	SpendableOutputs {
		/// The outputs which you should store as spendable by you.
		outputs: crate::c_types::derived::CVec_SpendableOutputDescriptorZ,
		/// The `channel_id` indicating which channel the spendable outputs belong to.
		///
		/// This will always be `Some` for events generated by LDK versions 0.0.117 and above.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		channel_id: crate::lightning::ln::types::ChannelId,
	},
	/// This event is generated when a payment has been successfully forwarded through us and a
	/// forwarding fee earned.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	PaymentForwarded {
		/// The channel id of the incoming channel between the previous node and us.
		///
		/// This is only `None` for events generated or serialized by versions prior to 0.0.107.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		prev_channel_id: crate::lightning::ln::types::ChannelId,
		/// The channel id of the outgoing channel between the next node and us.
		///
		/// This is only `None` for events generated or serialized by versions prior to 0.0.107.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		next_channel_id: crate::lightning::ln::types::ChannelId,
		/// The `user_channel_id` of the incoming channel between the previous node and us.
		///
		/// This is only `None` for events generated or serialized by versions prior to 0.0.122.
		prev_user_channel_id: crate::c_types::derived::COption_U128Z,
		/// The `user_channel_id` of the outgoing channel between the next node and us.
		///
		/// This will be `None` if the payment was settled via an on-chain transaction. See the
		/// caveat described for the `total_fee_earned_msat` field. Moreover it will be `None` for
		/// events generated or serialized by versions prior to 0.0.122.
		next_user_channel_id: crate::c_types::derived::COption_U128Z,
		/// The total fee, in milli-satoshis, which was earned as a result of the payment.
		///
		/// Note that if we force-closed the channel over which we forwarded an HTLC while the HTLC
		/// was pending, the amount the next hop claimed will have been rounded down to the nearest
		/// whole satoshi. Thus, the fee calculated here may be higher than expected as we still
		/// claimed the full value in millisatoshis from the source. In this case,
		/// `claim_from_onchain_tx` will be set.
		///
		/// If the channel which sent us the payment has been force-closed, we will claim the funds
		/// via an on-chain transaction. In that case we do not yet know the on-chain transaction
		/// fees which we will spend and will instead set this to `None`. It is possible duplicate
		/// `PaymentForwarded` events are generated for the same payment iff `total_fee_earned_msat` is
		/// `None`.
		total_fee_earned_msat: crate::c_types::derived::COption_u64Z,
		/// The share of the total fee, in milli-satoshis, which was withheld in addition to the
		/// forwarding fee.
		///
		/// This will only be `Some` if we forwarded an intercepted HTLC with less than the
		/// expected amount. This means our counterparty accepted to receive less than the invoice
		/// amount, e.g., by claiming the payment featuring a corresponding
		/// [`PaymentClaimable::counterparty_skimmed_fee_msat`].
		///
		/// Will also always be `None` for events serialized with LDK prior to version 0.0.122.
		///
		/// The caveat described above the `total_fee_earned_msat` field applies here as well.
		///
		/// [`PaymentClaimable::counterparty_skimmed_fee_msat`]: Self::PaymentClaimable::counterparty_skimmed_fee_msat
		skimmed_fee_msat: crate::c_types::derived::COption_u64Z,
		/// If this is `true`, the forwarded HTLC was claimed by our counterparty via an on-chain
		/// transaction.
		claim_from_onchain_tx: bool,
		/// The final amount forwarded, in milli-satoshis, after the fee is deducted.
		///
		/// The caveat described above the `total_fee_earned_msat` field applies here as well.
		outbound_amount_forwarded_msat: crate::c_types::derived::COption_u64Z,
	},
	/// Used to indicate that a channel with the given `channel_id` is being opened and pending
	/// confirmation on-chain.
	///
	/// This event is emitted when the funding transaction has been signed and is broadcast to the
	/// network. For 0conf channels it will be immediately followed by the corresponding
	/// [`Event::ChannelReady`] event.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	ChannelPending {
		/// The `channel_id` of the channel that is pending confirmation.
		channel_id: crate::lightning::ln::types::ChannelId,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: crate::c_types::U128,
		/// The `temporary_channel_id` this channel used to be known by during channel establishment.
		///
		/// Will be `None` for channels created prior to LDK version 0.0.115.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		former_temporary_channel_id: crate::lightning::ln::types::ChannelId,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The outpoint of the channel's funding transaction.
		funding_txo: crate::lightning::chain::transaction::OutPoint,
		/// The features that this channel will operate with.
		///
		/// Will be `None` for channels created prior to LDK version 0.0.122.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		channel_type: crate::lightning_types::features::ChannelTypeFeatures,
	},
	/// Used to indicate that a channel with the given `channel_id` is ready to
	/// be used. This event is emitted either when the funding transaction has been confirmed
	/// on-chain, or, in case of a 0conf channel, when both parties have confirmed the channel
	/// establishment.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	ChannelReady {
		/// The `channel_id` of the channel that is ready.
		channel_id: crate::lightning::ln::types::ChannelId,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: crate::c_types::U128,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The features that this channel will operate with.
		channel_type: crate::lightning_types::features::ChannelTypeFeatures,
	},
	/// Used to indicate that a channel that got past the initial handshake with the given `channel_id` is in the
	/// process of closure. This includes previously opened channels, and channels that time out from not being funded.
	///
	/// Note that this event is only triggered for accepted channels: if the
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true and the channel is
	/// rejected, no `ChannelClosed` event will be sent.
	///
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	ChannelClosed {
		/// The `channel_id` of the channel which has been closed. Note that on-chain transactions
		/// resolving the channel are likely still awaiting confirmation.
		channel_id: crate::lightning::ln::types::ChannelId,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for inbound channels.
		/// This may be zero for inbound channels serialized prior to 0.0.113 and will always be
		/// zero for objects serialized with LDK versions prior to 0.0.102.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: crate::c_types::U128,
		/// The reason the channel was closed.
		reason: crate::lightning::events::ClosureReason,
		/// Counterparty in the closed channel.
		///
		/// This field will be `None` for objects serialized prior to LDK 0.0.117.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		counterparty_node_id: crate::c_types::PublicKey,
		/// Channel capacity of the closing channel (sats).
		///
		/// This field will be `None` for objects serialized prior to LDK 0.0.117.
		channel_capacity_sats: crate::c_types::derived::COption_u64Z,
		/// The original channel funding TXO; this helps checking for the existence and confirmation
		/// status of the closing tx.
		/// Note that for instances serialized in v0.0.119 or prior this will be missing (None).
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		channel_funding_txo: crate::lightning::chain::transaction::OutPoint,
	},
	/// Used to indicate to the user that they can abandon the funding transaction and recycle the
	/// inputs for another purpose.
	///
	/// This event is not guaranteed to be generated for channels that are closed due to a restart.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	DiscardFunding {
		/// The channel_id of the channel which has been closed.
		channel_id: crate::lightning::ln::types::ChannelId,
		/// The full transaction received from the user
		funding_info: crate::lightning::events::FundingInfo,
	},
	/// Indicates a request to open a new channel by a peer.
	///
	/// To accept the request, call [`ChannelManager::accept_inbound_channel`]. To reject the request,
	/// call [`ChannelManager::force_close_without_broadcasting_txn`]. Note that a ['ChannelClosed`]
	/// event will _not_ be triggered if the channel is rejected.
	///
	/// The event is only triggered when a new open channel request is received and the
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	///
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	OpenChannelRequest {
		/// The temporary channel ID of the channel requested to be opened.
		///
		/// When responding to the request, the `temporary_channel_id` should be passed
		/// back to the ChannelManager through [`ChannelManager::accept_inbound_channel`] to accept,
		/// or through [`ChannelManager::force_close_without_broadcasting_txn`] to reject.
		///
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
		temporary_channel_id: crate::lightning::ln::types::ChannelId,
		/// The node_id of the counterparty requesting to open the channel.
		///
		/// When responding to the request, the `counterparty_node_id` should be passed
		/// back to the `ChannelManager` through [`ChannelManager::accept_inbound_channel`] to
		/// accept the request, or through [`ChannelManager::force_close_without_broadcasting_txn`] to reject the
		/// request.
		///
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
		counterparty_node_id: crate::c_types::PublicKey,
		/// The channel value of the requested channel.
		funding_satoshis: u64,
		/// Our starting balance in the channel if the request is accepted, in milli-satoshi.
		push_msat: u64,
		/// The features that this channel will operate with. If you reject the channel, a
		/// well-behaved counterparty may automatically re-attempt the channel with a new set of
		/// feature flags.
		///
		/// Note that if [`ChannelTypeFeatures::supports_scid_privacy`] returns true on this type,
		/// the resulting [`ChannelManager`] will not be readable by versions of LDK prior to
		/// 0.0.106.
		///
		/// Furthermore, note that if [`ChannelTypeFeatures::supports_zero_conf`] returns true on this type,
		/// the resulting [`ChannelManager`] will not be readable by versions of LDK prior to
		/// 0.0.107. Channels setting this type also need to get manually accepted via
		/// [`crate::ln::channelmanager::ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`],
		/// or will be rejected otherwise.
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		channel_type: crate::lightning_types::features::ChannelTypeFeatures,
		/// True if this channel is (or will be) publicly-announced.
		is_announced: bool,
		/// Channel parameters given by the counterparty.
		params: crate::lightning::ln::msgs::ChannelParameters,
	},
	/// Indicates that the HTLC was accepted, but could not be processed when or after attempting to
	/// forward it.
	///
	/// Some scenarios where this event may be sent include:
	/// * Insufficient capacity in the outbound channel
	/// * While waiting to forward the HTLC, the channel it is meant to be forwarded through closes
	/// * When an unknown SCID is requested for forwarding a payment.
	/// * Expected MPP amount has already been reached
	/// * The HTLC has timed out
	///
	/// This event, however, does not get generated if an HTLC fails to meet the forwarding
	/// requirements (i.e. insufficient fees paid, or a CLTV that is too soon).
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`) and will be persisted across restarts.
	HTLCHandlingFailed {
		/// The channel over which the HTLC was received.
		prev_channel_id: crate::lightning::ln::types::ChannelId,
		/// Destination of the HTLC that failed to be processed.
		failed_next_destination: crate::lightning::events::HTLCDestination,
	},
	/// Indicates that a transaction originating from LDK needs to have its fee bumped. This event
	/// requires confirmed external funds to be readily available to spend.
	///
	/// LDK does not currently generate this event unless the
	/// [`ChannelHandshakeConfig::negotiate_anchors_zero_fee_htlc_tx`] config flag is set to true.
	/// It is limited to the scope of channels with anchor outputs.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`), but will only be regenerated as needed after restarts.
	///
	/// [`ChannelHandshakeConfig::negotiate_anchors_zero_fee_htlc_tx`]: crate::util::config::ChannelHandshakeConfig::negotiate_anchors_zero_fee_htlc_tx
	BumpTransaction(
		crate::lightning::events::bump_transaction::BumpTransactionEvent),
	/// We received an onion message that is intended to be forwarded to a peer
	/// that is currently offline. This event will only be generated if the
	/// `OnionMessenger` was initialized with
	/// [`OnionMessenger::new_with_offline_peer_interception`], see its docs.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`), but won't be persisted across restarts.
	///
	/// [`OnionMessenger::new_with_offline_peer_interception`]: crate::onion_message::messenger::OnionMessenger::new_with_offline_peer_interception
	OnionMessageIntercepted {
		/// The node id of the offline peer.
		peer_node_id: crate::c_types::PublicKey,
		/// The onion message intended to be forwarded to `peer_node_id`.
		message: crate::lightning::ln::msgs::OnionMessage,
	},
	/// Indicates that an onion message supporting peer has come online and it may
	/// be time to forward any onion messages that were previously intercepted for
	/// them. This event will only be generated if the `OnionMessenger` was
	/// initialized with
	/// [`OnionMessenger::new_with_offline_peer_interception`], see its docs.
	///
	/// # Failure Behavior and Persistence
	/// This event will eventually be replayed after failures-to-handle (i.e., the event handler
	/// returning `Err(ReplayEvent ())`), but won't be persisted across restarts.
	///
	/// [`OnionMessenger::new_with_offline_peer_interception`]: crate::onion_message::messenger::OnionMessenger::new_with_offline_peer_interception
	OnionMessagePeerConnected {
		/// The node id of the peer we just connected to, who advertises support for
		/// onion messages.
		peer_node_id: crate::c_types::PublicKey,
	},
}
use lightning::events::Event as EventImport;
pub(crate) type nativeEvent = EventImport;

impl Event {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {ref temporary_channel_id, ref counterparty_node_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_value_satoshis_nonref = Clone::clone(channel_value_satoshis);
				let mut output_script_nonref = Clone::clone(output_script);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: *unsafe { Box::from_raw(temporary_channel_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: ::bitcoin::script::ScriptBuf::from(output_script_nonref.into_rust()),
					user_channel_id: user_channel_id_nonref.into(),
				}
			},
			Event::FundingTxBroadcastSafe {ref channel_id, ref user_channel_id, ref funding_txo, ref counterparty_node_id, ref former_temporary_channel_id, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut funding_txo_nonref = Clone::clone(funding_txo);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut former_temporary_channel_id_nonref = Clone::clone(former_temporary_channel_id);
				nativeEvent::FundingTxBroadcastSafe {
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
					user_channel_id: user_channel_id_nonref.into(),
					funding_txo: crate::c_types::C_to_bitcoin_outpoint(funding_txo_nonref),
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					former_temporary_channel_id: *unsafe { Box::from_raw(former_temporary_channel_id_nonref.take_inner()) },
				}
			},
			Event::PaymentClaimable {ref receiver_node_id, ref payment_hash, ref onion_fields, ref amount_msat, ref counterparty_skimmed_fee_msat, ref purpose, ref via_channel_id, ref via_user_channel_id, ref claim_deadline, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_null() { None } else { Some( { receiver_node_id_nonref.into_rust() }) };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut onion_fields_nonref = Clone::clone(onion_fields);
				let mut local_onion_fields_nonref = if onion_fields_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(onion_fields_nonref.take_inner()) } }) };
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut counterparty_skimmed_fee_msat_nonref = Clone::clone(counterparty_skimmed_fee_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				let mut via_channel_id_nonref = Clone::clone(via_channel_id);
				let mut local_via_channel_id_nonref = if via_channel_id_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(via_channel_id_nonref.take_inner()) } }) };
				let mut via_user_channel_id_nonref = Clone::clone(via_user_channel_id);
				let mut local_via_user_channel_id_nonref = { /*via_user_channel_id_nonref*/ let via_user_channel_id_nonref_opt = via_user_channel_id_nonref; if via_user_channel_id_nonref_opt.is_none() { None } else { Some({ { { via_user_channel_id_nonref_opt.take() }.into() }})} };
				let mut claim_deadline_nonref = Clone::clone(claim_deadline);
				let mut local_claim_deadline_nonref = if claim_deadline_nonref.is_some() { Some( { claim_deadline_nonref.take() }) } else { None };
				nativeEvent::PaymentClaimable {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
					onion_fields: local_onion_fields_nonref,
					amount_msat: amount_msat_nonref,
					counterparty_skimmed_fee_msat: counterparty_skimmed_fee_msat_nonref,
					purpose: purpose_nonref.into_native(),
					via_channel_id: local_via_channel_id_nonref,
					via_user_channel_id: local_via_user_channel_id_nonref,
					claim_deadline: local_claim_deadline_nonref,
				}
			},
			Event::PaymentClaimed {ref receiver_node_id, ref payment_hash, ref amount_msat, ref purpose, ref htlcs, ref sender_intended_total_msat, ref onion_fields, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_null() { None } else { Some( { receiver_node_id_nonref.into_rust() }) };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				let mut htlcs_nonref = Clone::clone(htlcs);
				let mut local_htlcs_nonref = Vec::new(); for mut item in htlcs_nonref.into_rust().drain(..) { local_htlcs_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut sender_intended_total_msat_nonref = Clone::clone(sender_intended_total_msat);
				let mut local_sender_intended_total_msat_nonref = if sender_intended_total_msat_nonref.is_some() { Some( { sender_intended_total_msat_nonref.take() }) } else { None };
				let mut onion_fields_nonref = Clone::clone(onion_fields);
				let mut local_onion_fields_nonref = if onion_fields_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(onion_fields_nonref.take_inner()) } }) };
				nativeEvent::PaymentClaimed {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
					amount_msat: amount_msat_nonref,
					purpose: purpose_nonref.into_native(),
					htlcs: local_htlcs_nonref,
					sender_intended_total_msat: local_sender_intended_total_msat_nonref,
					onion_fields: local_onion_fields_nonref,
				}
			},
			Event::ConnectionNeeded {ref node_id, ref addresses, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut addresses_nonref = Clone::clone(addresses);
				let mut local_addresses_nonref = Vec::new(); for mut item in addresses_nonref.into_rust().drain(..) { local_addresses_nonref.push( { item.into_native() }); };
				nativeEvent::ConnectionNeeded {
					node_id: node_id_nonref.into_rust(),
					addresses: local_addresses_nonref,
				}
			},
			Event::InvoiceReceived {ref payment_id, ref invoice, ref context, ref responder, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut invoice_nonref = Clone::clone(invoice);
				let mut context_nonref = Clone::clone(context);
				let mut local_context_nonref = { /*context_nonref*/ let context_nonref_opt = context_nonref; if context_nonref_opt.is_none() { None } else { Some({ { { context_nonref_opt.take() }.into_native() }})} };
				let mut responder_nonref = Clone::clone(responder);
				let mut local_responder_nonref = if responder_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(responder_nonref.take_inner()) } }) };
				nativeEvent::InvoiceReceived {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					invoice: *unsafe { Box::from_raw(invoice_nonref.take_inner()) },
					context: local_context_nonref,
					responder: local_responder_nonref,
				}
			},
			Event::PaymentSent {ref payment_id, ref payment_preimage, ref payment_hash, ref fee_paid_msat, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = { /*payment_id_nonref*/ let payment_id_nonref_opt = payment_id_nonref; if payment_id_nonref_opt.is_none() { None } else { Some({ { ::lightning::ln::channelmanager::PaymentId({ payment_id_nonref_opt.take() }.data) }})} };
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut fee_paid_msat_nonref = Clone::clone(fee_paid_msat);
				let mut local_fee_paid_msat_nonref = if fee_paid_msat_nonref.is_some() { Some( { fee_paid_msat_nonref.take() }) } else { None };
				nativeEvent::PaymentSent {
					payment_id: local_payment_id_nonref,
					payment_preimage: ::lightning::ln::types::PaymentPreimage(payment_preimage_nonref.data),
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
					fee_paid_msat: local_fee_paid_msat_nonref,
				}
			},
			Event::PaymentFailed {ref payment_id, ref payment_hash, ref reason, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut local_payment_hash_nonref = { /*payment_hash_nonref*/ let payment_hash_nonref_opt = payment_hash_nonref; if payment_hash_nonref_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentHash({ payment_hash_nonref_opt.take() }.data) }})} };
				let mut reason_nonref = Clone::clone(reason);
				let mut local_reason_nonref = { /*reason_nonref*/ let reason_nonref_opt = reason_nonref; if reason_nonref_opt.is_none() { None } else { Some({ { { reason_nonref_opt.take() }.into_native() }})} };
				nativeEvent::PaymentFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: local_payment_hash_nonref,
					reason: local_reason_nonref,
				}
			},
			Event::PaymentPathSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut local_payment_hash_nonref = { /*payment_hash_nonref*/ let payment_hash_nonref_opt = payment_hash_nonref; if payment_hash_nonref_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentHash({ payment_hash_nonref_opt.take() }.data) }})} };
				let mut path_nonref = Clone::clone(path);
				nativeEvent::PaymentPathSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: local_payment_hash_nonref,
					path: *unsafe { Box::from_raw(path_nonref.take_inner()) },
				}
			},
			Event::PaymentPathFailed {ref payment_id, ref payment_hash, ref payment_failed_permanently, ref failure, ref path, ref short_channel_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = { /*payment_id_nonref*/ let payment_id_nonref_opt = payment_id_nonref; if payment_id_nonref_opt.is_none() { None } else { Some({ { ::lightning::ln::channelmanager::PaymentId({ payment_id_nonref_opt.take() }.data) }})} };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut payment_failed_permanently_nonref = Clone::clone(payment_failed_permanently);
				let mut failure_nonref = Clone::clone(failure);
				let mut path_nonref = Clone::clone(path);
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_some() { Some( { short_channel_id_nonref.take() }) } else { None };
				nativeEvent::PaymentPathFailed {
					payment_id: local_payment_id_nonref,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
					payment_failed_permanently: payment_failed_permanently_nonref,
					failure: failure_nonref.into_native(),
					path: *unsafe { Box::from_raw(path_nonref.take_inner()) },
					short_channel_id: local_short_channel_id_nonref,
				}
			},
			Event::ProbeSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				nativeEvent::ProbeSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
					path: *unsafe { Box::from_raw(path_nonref.take_inner()) },
				}
			},
			Event::ProbeFailed {ref payment_id, ref payment_hash, ref path, ref short_channel_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_some() { Some( { short_channel_id_nonref.take() }) } else { None };
				nativeEvent::ProbeFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
					path: *unsafe { Box::from_raw(path_nonref.take_inner()) },
					short_channel_id: local_short_channel_id_nonref,
				}
			},
			Event::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = Clone::clone(time_forwardable);
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: core::time::Duration::from_secs(time_forwardable_nonref),
				}
			},
			Event::HTLCIntercepted {ref intercept_id, ref requested_next_hop_scid, ref payment_hash, ref inbound_amount_msat, ref expected_outbound_amount_msat, } => {
				let mut intercept_id_nonref = Clone::clone(intercept_id);
				let mut requested_next_hop_scid_nonref = Clone::clone(requested_next_hop_scid);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut inbound_amount_msat_nonref = Clone::clone(inbound_amount_msat);
				let mut expected_outbound_amount_msat_nonref = Clone::clone(expected_outbound_amount_msat);
				nativeEvent::HTLCIntercepted {
					intercept_id: ::lightning::ln::channelmanager::InterceptId(intercept_id_nonref.data),
					requested_next_hop_scid: requested_next_hop_scid_nonref,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash_nonref.data),
					inbound_amount_msat: inbound_amount_msat_nonref,
					expected_outbound_amount_msat: expected_outbound_amount_msat_nonref,
				}
			},
			Event::SpendableOutputs {ref outputs, ref channel_id, } => {
				let mut outputs_nonref = Clone::clone(outputs);
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.into_rust().drain(..) { local_outputs_nonref.push( { item.into_native() }); };
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut local_channel_id_nonref = if channel_id_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_id_nonref.take_inner()) } }) };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs_nonref,
					channel_id: local_channel_id_nonref,
				}
			},
			Event::PaymentForwarded {ref prev_channel_id, ref next_channel_id, ref prev_user_channel_id, ref next_user_channel_id, ref total_fee_earned_msat, ref skimmed_fee_msat, ref claim_from_onchain_tx, ref outbound_amount_forwarded_msat, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut local_prev_channel_id_nonref = if prev_channel_id_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(prev_channel_id_nonref.take_inner()) } }) };
				let mut next_channel_id_nonref = Clone::clone(next_channel_id);
				let mut local_next_channel_id_nonref = if next_channel_id_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(next_channel_id_nonref.take_inner()) } }) };
				let mut prev_user_channel_id_nonref = Clone::clone(prev_user_channel_id);
				let mut local_prev_user_channel_id_nonref = { /*prev_user_channel_id_nonref*/ let prev_user_channel_id_nonref_opt = prev_user_channel_id_nonref; if prev_user_channel_id_nonref_opt.is_none() { None } else { Some({ { { prev_user_channel_id_nonref_opt.take() }.into() }})} };
				let mut next_user_channel_id_nonref = Clone::clone(next_user_channel_id);
				let mut local_next_user_channel_id_nonref = { /*next_user_channel_id_nonref*/ let next_user_channel_id_nonref_opt = next_user_channel_id_nonref; if next_user_channel_id_nonref_opt.is_none() { None } else { Some({ { { next_user_channel_id_nonref_opt.take() }.into() }})} };
				let mut total_fee_earned_msat_nonref = Clone::clone(total_fee_earned_msat);
				let mut local_total_fee_earned_msat_nonref = if total_fee_earned_msat_nonref.is_some() { Some( { total_fee_earned_msat_nonref.take() }) } else { None };
				let mut skimmed_fee_msat_nonref = Clone::clone(skimmed_fee_msat);
				let mut local_skimmed_fee_msat_nonref = if skimmed_fee_msat_nonref.is_some() { Some( { skimmed_fee_msat_nonref.take() }) } else { None };
				let mut claim_from_onchain_tx_nonref = Clone::clone(claim_from_onchain_tx);
				let mut outbound_amount_forwarded_msat_nonref = Clone::clone(outbound_amount_forwarded_msat);
				let mut local_outbound_amount_forwarded_msat_nonref = if outbound_amount_forwarded_msat_nonref.is_some() { Some( { outbound_amount_forwarded_msat_nonref.take() }) } else { None };
				nativeEvent::PaymentForwarded {
					prev_channel_id: local_prev_channel_id_nonref,
					next_channel_id: local_next_channel_id_nonref,
					prev_user_channel_id: local_prev_user_channel_id_nonref,
					next_user_channel_id: local_next_user_channel_id_nonref,
					total_fee_earned_msat: local_total_fee_earned_msat_nonref,
					skimmed_fee_msat: local_skimmed_fee_msat_nonref,
					claim_from_onchain_tx: claim_from_onchain_tx_nonref,
					outbound_amount_forwarded_msat: local_outbound_amount_forwarded_msat_nonref,
				}
			},
			Event::ChannelPending {ref channel_id, ref user_channel_id, ref former_temporary_channel_id, ref counterparty_node_id, ref funding_txo, ref channel_type, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut former_temporary_channel_id_nonref = Clone::clone(former_temporary_channel_id);
				let mut local_former_temporary_channel_id_nonref = if former_temporary_channel_id_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(former_temporary_channel_id_nonref.take_inner()) } }) };
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut funding_txo_nonref = Clone::clone(funding_txo);
				let mut channel_type_nonref = Clone::clone(channel_type);
				let mut local_channel_type_nonref = if channel_type_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_type_nonref.take_inner()) } }) };
				nativeEvent::ChannelPending {
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
					user_channel_id: user_channel_id_nonref.into(),
					former_temporary_channel_id: local_former_temporary_channel_id_nonref,
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					funding_txo: crate::c_types::C_to_bitcoin_outpoint(funding_txo_nonref),
					channel_type: local_channel_type_nonref,
				}
			},
			Event::ChannelReady {ref channel_id, ref user_channel_id, ref counterparty_node_id, ref channel_type, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_type_nonref = Clone::clone(channel_type);
				nativeEvent::ChannelReady {
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
					user_channel_id: user_channel_id_nonref.into(),
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					channel_type: *unsafe { Box::from_raw(channel_type_nonref.take_inner()) },
				}
			},
			Event::ChannelClosed {ref channel_id, ref user_channel_id, ref reason, ref counterparty_node_id, ref channel_capacity_sats, ref channel_funding_txo, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut reason_nonref = Clone::clone(reason);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut local_counterparty_node_id_nonref = if counterparty_node_id_nonref.is_null() { None } else { Some( { counterparty_node_id_nonref.into_rust() }) };
				let mut channel_capacity_sats_nonref = Clone::clone(channel_capacity_sats);
				let mut local_channel_capacity_sats_nonref = if channel_capacity_sats_nonref.is_some() { Some( { channel_capacity_sats_nonref.take() }) } else { None };
				let mut channel_funding_txo_nonref = Clone::clone(channel_funding_txo);
				let mut local_channel_funding_txo_nonref = if channel_funding_txo_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_funding_txo_nonref.take_inner()) } }) };
				nativeEvent::ChannelClosed {
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
					user_channel_id: user_channel_id_nonref.into(),
					reason: reason_nonref.into_native(),
					counterparty_node_id: local_counterparty_node_id_nonref,
					channel_capacity_sats: local_channel_capacity_sats_nonref,
					channel_funding_txo: local_channel_funding_txo_nonref,
				}
			},
			Event::DiscardFunding {ref channel_id, ref funding_info, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut funding_info_nonref = Clone::clone(funding_info);
				nativeEvent::DiscardFunding {
					channel_id: *unsafe { Box::from_raw(channel_id_nonref.take_inner()) },
					funding_info: funding_info_nonref.into_native(),
				}
			},
			Event::OpenChannelRequest {ref temporary_channel_id, ref counterparty_node_id, ref funding_satoshis, ref push_msat, ref channel_type, ref is_announced, ref params, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut funding_satoshis_nonref = Clone::clone(funding_satoshis);
				let mut push_msat_nonref = Clone::clone(push_msat);
				let mut channel_type_nonref = Clone::clone(channel_type);
				let mut is_announced_nonref = Clone::clone(is_announced);
				let mut params_nonref = Clone::clone(params);
				nativeEvent::OpenChannelRequest {
					temporary_channel_id: *unsafe { Box::from_raw(temporary_channel_id_nonref.take_inner()) },
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					funding_satoshis: funding_satoshis_nonref,
					push_msat: push_msat_nonref,
					channel_type: *unsafe { Box::from_raw(channel_type_nonref.take_inner()) },
					is_announced: is_announced_nonref,
					params: *unsafe { Box::from_raw(params_nonref.take_inner()) },
				}
			},
			Event::HTLCHandlingFailed {ref prev_channel_id, ref failed_next_destination, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut failed_next_destination_nonref = Clone::clone(failed_next_destination);
				nativeEvent::HTLCHandlingFailed {
					prev_channel_id: *unsafe { Box::from_raw(prev_channel_id_nonref.take_inner()) },
					failed_next_destination: failed_next_destination_nonref.into_native(),
				}
			},
			Event::BumpTransaction (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeEvent::BumpTransaction (
					a_nonref.into_native(),
				)
			},
			Event::OnionMessageIntercepted {ref peer_node_id, ref message, } => {
				let mut peer_node_id_nonref = Clone::clone(peer_node_id);
				let mut message_nonref = Clone::clone(message);
				nativeEvent::OnionMessageIntercepted {
					peer_node_id: peer_node_id_nonref.into_rust(),
					message: *unsafe { Box::from_raw(message_nonref.take_inner()) },
				}
			},
			Event::OnionMessagePeerConnected {ref peer_node_id, } => {
				let mut peer_node_id_nonref = Clone::clone(peer_node_id);
				nativeEvent::OnionMessagePeerConnected {
					peer_node_id: peer_node_id_nonref.into_rust(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {mut temporary_channel_id, mut counterparty_node_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: *unsafe { Box::from_raw(temporary_channel_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					channel_value_satoshis: channel_value_satoshis,
					output_script: ::bitcoin::script::ScriptBuf::from(output_script.into_rust()),
					user_channel_id: user_channel_id.into(),
				}
			},
			Event::FundingTxBroadcastSafe {mut channel_id, mut user_channel_id, mut funding_txo, mut counterparty_node_id, mut former_temporary_channel_id, } => {
				nativeEvent::FundingTxBroadcastSafe {
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
					user_channel_id: user_channel_id.into(),
					funding_txo: crate::c_types::C_to_bitcoin_outpoint(funding_txo),
					counterparty_node_id: counterparty_node_id.into_rust(),
					former_temporary_channel_id: *unsafe { Box::from_raw(former_temporary_channel_id.take_inner()) },
				}
			},
			Event::PaymentClaimable {mut receiver_node_id, mut payment_hash, mut onion_fields, mut amount_msat, mut counterparty_skimmed_fee_msat, mut purpose, mut via_channel_id, mut via_user_channel_id, mut claim_deadline, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_null() { None } else { Some( { receiver_node_id.into_rust() }) };
				let mut local_onion_fields = if onion_fields.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(onion_fields.take_inner()) } }) };
				let mut local_via_channel_id = if via_channel_id.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(via_channel_id.take_inner()) } }) };
				let mut local_via_user_channel_id = { /*via_user_channel_id*/ let via_user_channel_id_opt = via_user_channel_id; if via_user_channel_id_opt.is_none() { None } else { Some({ { { via_user_channel_id_opt.take() }.into() }})} };
				let mut local_claim_deadline = if claim_deadline.is_some() { Some( { claim_deadline.take() }) } else { None };
				nativeEvent::PaymentClaimable {
					receiver_node_id: local_receiver_node_id,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
					onion_fields: local_onion_fields,
					amount_msat: amount_msat,
					counterparty_skimmed_fee_msat: counterparty_skimmed_fee_msat,
					purpose: purpose.into_native(),
					via_channel_id: local_via_channel_id,
					via_user_channel_id: local_via_user_channel_id,
					claim_deadline: local_claim_deadline,
				}
			},
			Event::PaymentClaimed {mut receiver_node_id, mut payment_hash, mut amount_msat, mut purpose, mut htlcs, mut sender_intended_total_msat, mut onion_fields, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_null() { None } else { Some( { receiver_node_id.into_rust() }) };
				let mut local_htlcs = Vec::new(); for mut item in htlcs.into_rust().drain(..) { local_htlcs.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut local_sender_intended_total_msat = if sender_intended_total_msat.is_some() { Some( { sender_intended_total_msat.take() }) } else { None };
				let mut local_onion_fields = if onion_fields.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(onion_fields.take_inner()) } }) };
				nativeEvent::PaymentClaimed {
					receiver_node_id: local_receiver_node_id,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
					amount_msat: amount_msat,
					purpose: purpose.into_native(),
					htlcs: local_htlcs,
					sender_intended_total_msat: local_sender_intended_total_msat,
					onion_fields: local_onion_fields,
				}
			},
			Event::ConnectionNeeded {mut node_id, mut addresses, } => {
				let mut local_addresses = Vec::new(); for mut item in addresses.into_rust().drain(..) { local_addresses.push( { item.into_native() }); };
				nativeEvent::ConnectionNeeded {
					node_id: node_id.into_rust(),
					addresses: local_addresses,
				}
			},
			Event::InvoiceReceived {mut payment_id, mut invoice, mut context, mut responder, } => {
				let mut local_context = { /*context*/ let context_opt = context; if context_opt.is_none() { None } else { Some({ { { context_opt.take() }.into_native() }})} };
				let mut local_responder = if responder.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(responder.take_inner()) } }) };
				nativeEvent::InvoiceReceived {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					invoice: *unsafe { Box::from_raw(invoice.take_inner()) },
					context: local_context,
					responder: local_responder,
				}
			},
			Event::PaymentSent {mut payment_id, mut payment_preimage, mut payment_hash, mut fee_paid_msat, } => {
				let mut local_payment_id = { /*payment_id*/ let payment_id_opt = payment_id; if payment_id_opt.is_none() { None } else { Some({ { ::lightning::ln::channelmanager::PaymentId({ payment_id_opt.take() }.data) }})} };
				let mut local_fee_paid_msat = if fee_paid_msat.is_some() { Some( { fee_paid_msat.take() }) } else { None };
				nativeEvent::PaymentSent {
					payment_id: local_payment_id,
					payment_preimage: ::lightning::ln::types::PaymentPreimage(payment_preimage.data),
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
					fee_paid_msat: local_fee_paid_msat,
				}
			},
			Event::PaymentFailed {mut payment_id, mut payment_hash, mut reason, } => {
				let mut local_payment_hash = { /*payment_hash*/ let payment_hash_opt = payment_hash; if payment_hash_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentHash({ payment_hash_opt.take() }.data) }})} };
				let mut local_reason = { /*reason*/ let reason_opt = reason; if reason_opt.is_none() { None } else { Some({ { { reason_opt.take() }.into_native() }})} };
				nativeEvent::PaymentFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: local_payment_hash,
					reason: local_reason,
				}
			},
			Event::PaymentPathSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				let mut local_payment_hash = { /*payment_hash*/ let payment_hash_opt = payment_hash; if payment_hash_opt.is_none() { None } else { Some({ { ::lightning::ln::types::PaymentHash({ payment_hash_opt.take() }.data) }})} };
				nativeEvent::PaymentPathSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: local_payment_hash,
					path: *unsafe { Box::from_raw(path.take_inner()) },
				}
			},
			Event::PaymentPathFailed {mut payment_id, mut payment_hash, mut payment_failed_permanently, mut failure, mut path, mut short_channel_id, } => {
				let mut local_payment_id = { /*payment_id*/ let payment_id_opt = payment_id; if payment_id_opt.is_none() { None } else { Some({ { ::lightning::ln::channelmanager::PaymentId({ payment_id_opt.take() }.data) }})} };
				let mut local_short_channel_id = if short_channel_id.is_some() { Some( { short_channel_id.take() }) } else { None };
				nativeEvent::PaymentPathFailed {
					payment_id: local_payment_id,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
					payment_failed_permanently: payment_failed_permanently,
					failure: failure.into_native(),
					path: *unsafe { Box::from_raw(path.take_inner()) },
					short_channel_id: local_short_channel_id,
				}
			},
			Event::ProbeSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				nativeEvent::ProbeSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
					path: *unsafe { Box::from_raw(path.take_inner()) },
				}
			},
			Event::ProbeFailed {mut payment_id, mut payment_hash, mut path, mut short_channel_id, } => {
				let mut local_short_channel_id = if short_channel_id.is_some() { Some( { short_channel_id.take() }) } else { None };
				nativeEvent::ProbeFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
					path: *unsafe { Box::from_raw(path.take_inner()) },
					short_channel_id: local_short_channel_id,
				}
			},
			Event::PendingHTLCsForwardable {mut time_forwardable, } => {
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: core::time::Duration::from_secs(time_forwardable),
				}
			},
			Event::HTLCIntercepted {mut intercept_id, mut requested_next_hop_scid, mut payment_hash, mut inbound_amount_msat, mut expected_outbound_amount_msat, } => {
				nativeEvent::HTLCIntercepted {
					intercept_id: ::lightning::ln::channelmanager::InterceptId(intercept_id.data),
					requested_next_hop_scid: requested_next_hop_scid,
					payment_hash: ::lightning::ln::types::PaymentHash(payment_hash.data),
					inbound_amount_msat: inbound_amount_msat,
					expected_outbound_amount_msat: expected_outbound_amount_msat,
				}
			},
			Event::SpendableOutputs {mut outputs, mut channel_id, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_native() }); };
				let mut local_channel_id = if channel_id.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_id.take_inner()) } }) };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs,
					channel_id: local_channel_id,
				}
			},
			Event::PaymentForwarded {mut prev_channel_id, mut next_channel_id, mut prev_user_channel_id, mut next_user_channel_id, mut total_fee_earned_msat, mut skimmed_fee_msat, mut claim_from_onchain_tx, mut outbound_amount_forwarded_msat, } => {
				let mut local_prev_channel_id = if prev_channel_id.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(prev_channel_id.take_inner()) } }) };
				let mut local_next_channel_id = if next_channel_id.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(next_channel_id.take_inner()) } }) };
				let mut local_prev_user_channel_id = { /*prev_user_channel_id*/ let prev_user_channel_id_opt = prev_user_channel_id; if prev_user_channel_id_opt.is_none() { None } else { Some({ { { prev_user_channel_id_opt.take() }.into() }})} };
				let mut local_next_user_channel_id = { /*next_user_channel_id*/ let next_user_channel_id_opt = next_user_channel_id; if next_user_channel_id_opt.is_none() { None } else { Some({ { { next_user_channel_id_opt.take() }.into() }})} };
				let mut local_total_fee_earned_msat = if total_fee_earned_msat.is_some() { Some( { total_fee_earned_msat.take() }) } else { None };
				let mut local_skimmed_fee_msat = if skimmed_fee_msat.is_some() { Some( { skimmed_fee_msat.take() }) } else { None };
				let mut local_outbound_amount_forwarded_msat = if outbound_amount_forwarded_msat.is_some() { Some( { outbound_amount_forwarded_msat.take() }) } else { None };
				nativeEvent::PaymentForwarded {
					prev_channel_id: local_prev_channel_id,
					next_channel_id: local_next_channel_id,
					prev_user_channel_id: local_prev_user_channel_id,
					next_user_channel_id: local_next_user_channel_id,
					total_fee_earned_msat: local_total_fee_earned_msat,
					skimmed_fee_msat: local_skimmed_fee_msat,
					claim_from_onchain_tx: claim_from_onchain_tx,
					outbound_amount_forwarded_msat: local_outbound_amount_forwarded_msat,
				}
			},
			Event::ChannelPending {mut channel_id, mut user_channel_id, mut former_temporary_channel_id, mut counterparty_node_id, mut funding_txo, mut channel_type, } => {
				let mut local_former_temporary_channel_id = if former_temporary_channel_id.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(former_temporary_channel_id.take_inner()) } }) };
				let mut local_channel_type = if channel_type.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_type.take_inner()) } }) };
				nativeEvent::ChannelPending {
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
					user_channel_id: user_channel_id.into(),
					former_temporary_channel_id: local_former_temporary_channel_id,
					counterparty_node_id: counterparty_node_id.into_rust(),
					funding_txo: crate::c_types::C_to_bitcoin_outpoint(funding_txo),
					channel_type: local_channel_type,
				}
			},
			Event::ChannelReady {mut channel_id, mut user_channel_id, mut counterparty_node_id, mut channel_type, } => {
				nativeEvent::ChannelReady {
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
					user_channel_id: user_channel_id.into(),
					counterparty_node_id: counterparty_node_id.into_rust(),
					channel_type: *unsafe { Box::from_raw(channel_type.take_inner()) },
				}
			},
			Event::ChannelClosed {mut channel_id, mut user_channel_id, mut reason, mut counterparty_node_id, mut channel_capacity_sats, mut channel_funding_txo, } => {
				let mut local_counterparty_node_id = if counterparty_node_id.is_null() { None } else { Some( { counterparty_node_id.into_rust() }) };
				let mut local_channel_capacity_sats = if channel_capacity_sats.is_some() { Some( { channel_capacity_sats.take() }) } else { None };
				let mut local_channel_funding_txo = if channel_funding_txo.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_funding_txo.take_inner()) } }) };
				nativeEvent::ChannelClosed {
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
					user_channel_id: user_channel_id.into(),
					reason: reason.into_native(),
					counterparty_node_id: local_counterparty_node_id,
					channel_capacity_sats: local_channel_capacity_sats,
					channel_funding_txo: local_channel_funding_txo,
				}
			},
			Event::DiscardFunding {mut channel_id, mut funding_info, } => {
				nativeEvent::DiscardFunding {
					channel_id: *unsafe { Box::from_raw(channel_id.take_inner()) },
					funding_info: funding_info.into_native(),
				}
			},
			Event::OpenChannelRequest {mut temporary_channel_id, mut counterparty_node_id, mut funding_satoshis, mut push_msat, mut channel_type, mut is_announced, mut params, } => {
				nativeEvent::OpenChannelRequest {
					temporary_channel_id: *unsafe { Box::from_raw(temporary_channel_id.take_inner()) },
					counterparty_node_id: counterparty_node_id.into_rust(),
					funding_satoshis: funding_satoshis,
					push_msat: push_msat,
					channel_type: *unsafe { Box::from_raw(channel_type.take_inner()) },
					is_announced: is_announced,
					params: *unsafe { Box::from_raw(params.take_inner()) },
				}
			},
			Event::HTLCHandlingFailed {mut prev_channel_id, mut failed_next_destination, } => {
				nativeEvent::HTLCHandlingFailed {
					prev_channel_id: *unsafe { Box::from_raw(prev_channel_id.take_inner()) },
					failed_next_destination: failed_next_destination.into_native(),
				}
			},
			Event::BumpTransaction (mut a, ) => {
				nativeEvent::BumpTransaction (
					a.into_native(),
				)
			},
			Event::OnionMessageIntercepted {mut peer_node_id, mut message, } => {
				nativeEvent::OnionMessageIntercepted {
					peer_node_id: peer_node_id.into_rust(),
					message: *unsafe { Box::from_raw(message.take_inner()) },
				}
			},
			Event::OnionMessagePeerConnected {mut peer_node_id, } => {
				nativeEvent::OnionMessagePeerConnected {
					peer_node_id: peer_node_id.into_rust(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &EventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeEvent) };
		match native {
			nativeEvent::FundingGenerationReady {ref temporary_channel_id, ref counterparty_node_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_value_satoshis_nonref = Clone::clone(channel_value_satoshis);
				let mut output_script_nonref = Clone::clone(output_script);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				Event::FundingGenerationReady {
					temporary_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(temporary_channel_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: output_script_nonref.to_bytes().into(),
					user_channel_id: user_channel_id_nonref.into(),
				}
			},
			nativeEvent::FundingTxBroadcastSafe {ref channel_id, ref user_channel_id, ref funding_txo, ref counterparty_node_id, ref former_temporary_channel_id, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut funding_txo_nonref = Clone::clone(funding_txo);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut former_temporary_channel_id_nonref = Clone::clone(former_temporary_channel_id);
				Event::FundingTxBroadcastSafe {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
					user_channel_id: user_channel_id_nonref.into(),
					funding_txo: crate::c_types::bitcoin_to_C_outpoint(&funding_txo_nonref),
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					former_temporary_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(former_temporary_channel_id_nonref), is_owned: true },
				}
			},
			nativeEvent::PaymentClaimable {ref receiver_node_id, ref payment_hash, ref onion_fields, ref amount_msat, ref counterparty_skimmed_fee_msat, ref purpose, ref via_channel_id, ref via_user_channel_id, ref claim_deadline, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id_nonref.unwrap())) } };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut onion_fields_nonref = Clone::clone(onion_fields);
				let mut local_onion_fields_nonref = crate::lightning::ln::outbound_payment::RecipientOnionFields { inner: if onion_fields_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((onion_fields_nonref.unwrap())) } }, is_owned: true };
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut counterparty_skimmed_fee_msat_nonref = Clone::clone(counterparty_skimmed_fee_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				let mut via_channel_id_nonref = Clone::clone(via_channel_id);
				let mut local_via_channel_id_nonref = crate::lightning::ln::types::ChannelId { inner: if via_channel_id_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((via_channel_id_nonref.unwrap())) } }, is_owned: true };
				let mut via_user_channel_id_nonref = Clone::clone(via_user_channel_id);
				let mut local_via_user_channel_id_nonref = if via_user_channel_id_nonref.is_none() { crate::c_types::derived::COption_U128Z::None } else { crate::c_types::derived::COption_U128Z::Some( { via_user_channel_id_nonref.unwrap().into() }) };
				let mut claim_deadline_nonref = Clone::clone(claim_deadline);
				let mut local_claim_deadline_nonref = if claim_deadline_nonref.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { claim_deadline_nonref.unwrap() }) };
				Event::PaymentClaimable {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					onion_fields: local_onion_fields_nonref,
					amount_msat: amount_msat_nonref,
					counterparty_skimmed_fee_msat: counterparty_skimmed_fee_msat_nonref,
					purpose: crate::lightning::events::PaymentPurpose::native_into(purpose_nonref),
					via_channel_id: local_via_channel_id_nonref,
					via_user_channel_id: local_via_user_channel_id_nonref,
					claim_deadline: local_claim_deadline_nonref,
				}
			},
			nativeEvent::PaymentClaimed {ref receiver_node_id, ref payment_hash, ref amount_msat, ref purpose, ref htlcs, ref sender_intended_total_msat, ref onion_fields, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id_nonref.unwrap())) } };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				let mut htlcs_nonref = Clone::clone(htlcs);
				let mut local_htlcs_nonref = Vec::new(); for mut item in htlcs_nonref.drain(..) { local_htlcs_nonref.push( { crate::lightning::events::ClaimedHTLC { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut sender_intended_total_msat_nonref = Clone::clone(sender_intended_total_msat);
				let mut local_sender_intended_total_msat_nonref = if sender_intended_total_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { sender_intended_total_msat_nonref.unwrap() }) };
				let mut onion_fields_nonref = Clone::clone(onion_fields);
				let mut local_onion_fields_nonref = crate::lightning::ln::outbound_payment::RecipientOnionFields { inner: if onion_fields_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((onion_fields_nonref.unwrap())) } }, is_owned: true };
				Event::PaymentClaimed {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					amount_msat: amount_msat_nonref,
					purpose: crate::lightning::events::PaymentPurpose::native_into(purpose_nonref),
					htlcs: local_htlcs_nonref.into(),
					sender_intended_total_msat: local_sender_intended_total_msat_nonref,
					onion_fields: local_onion_fields_nonref,
				}
			},
			nativeEvent::ConnectionNeeded {ref node_id, ref addresses, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut addresses_nonref = Clone::clone(addresses);
				let mut local_addresses_nonref = Vec::new(); for mut item in addresses_nonref.drain(..) { local_addresses_nonref.push( { crate::lightning::ln::msgs::SocketAddress::native_into(item) }); };
				Event::ConnectionNeeded {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					addresses: local_addresses_nonref.into(),
				}
			},
			nativeEvent::InvoiceReceived {ref payment_id, ref invoice, ref context, ref responder, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut invoice_nonref = Clone::clone(invoice);
				let mut context_nonref = Clone::clone(context);
				let mut local_context_nonref = if context_nonref.is_none() { crate::c_types::derived::COption_OffersContextZ::None } else { crate::c_types::derived::COption_OffersContextZ::Some( { crate::lightning::blinded_path::message::OffersContext::native_into(context_nonref.unwrap()) }) };
				let mut responder_nonref = Clone::clone(responder);
				let mut local_responder_nonref = crate::lightning::onion_message::messenger::Responder { inner: if responder_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder_nonref.unwrap())) } }, is_owned: true };
				Event::InvoiceReceived {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					invoice: crate::lightning::offers::invoice::Bolt12Invoice { inner: ObjOps::heap_alloc(invoice_nonref), is_owned: true },
					context: local_context_nonref,
					responder: local_responder_nonref,
				}
			},
			nativeEvent::PaymentSent {ref payment_id, ref payment_preimage, ref payment_hash, ref fee_paid_msat, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = if payment_id_nonref.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.unwrap().0 } }) };
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut fee_paid_msat_nonref = Clone::clone(fee_paid_msat);
				let mut local_fee_paid_msat_nonref = if fee_paid_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { fee_paid_msat_nonref.unwrap() }) };
				Event::PaymentSent {
					payment_id: local_payment_id_nonref,
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage_nonref.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					fee_paid_msat: local_fee_paid_msat_nonref,
				}
			},
			nativeEvent::PaymentFailed {ref payment_id, ref payment_hash, ref reason, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut local_payment_hash_nonref = if payment_hash_nonref.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.unwrap().0 } }) };
				let mut reason_nonref = Clone::clone(reason);
				let mut local_reason_nonref = if reason_nonref.is_none() { crate::c_types::derived::COption_PaymentFailureReasonZ::None } else { crate::c_types::derived::COption_PaymentFailureReasonZ::Some( { crate::lightning::events::PaymentFailureReason::native_into(reason_nonref.unwrap()) }) };
				Event::PaymentFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: local_payment_hash_nonref,
					reason: local_reason_nonref,
				}
			},
			nativeEvent::PaymentPathSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut local_payment_hash_nonref = if payment_hash_nonref.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.unwrap().0 } }) };
				let mut path_nonref = Clone::clone(path);
				Event::PaymentPathSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: local_payment_hash_nonref,
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path_nonref), is_owned: true },
				}
			},
			nativeEvent::PaymentPathFailed {ref payment_id, ref payment_hash, ref payment_failed_permanently, ref failure, ref path, ref short_channel_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = if payment_id_nonref.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.unwrap().0 } }) };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut payment_failed_permanently_nonref = Clone::clone(payment_failed_permanently);
				let mut failure_nonref = Clone::clone(failure);
				let mut path_nonref = Clone::clone(path);
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id_nonref.unwrap() }) };
				Event::PaymentPathFailed {
					payment_id: local_payment_id_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					payment_failed_permanently: payment_failed_permanently_nonref,
					failure: crate::lightning::events::PathFailure::native_into(failure_nonref),
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path_nonref), is_owned: true },
					short_channel_id: local_short_channel_id_nonref,
				}
			},
			nativeEvent::ProbeSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				Event::ProbeSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path_nonref), is_owned: true },
				}
			},
			nativeEvent::ProbeFailed {ref payment_id, ref payment_hash, ref path, ref short_channel_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id_nonref.unwrap() }) };
				Event::ProbeFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path_nonref), is_owned: true },
					short_channel_id: local_short_channel_id_nonref,
				}
			},
			nativeEvent::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = Clone::clone(time_forwardable);
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable_nonref.as_secs(),
				}
			},
			nativeEvent::HTLCIntercepted {ref intercept_id, ref requested_next_hop_scid, ref payment_hash, ref inbound_amount_msat, ref expected_outbound_amount_msat, } => {
				let mut intercept_id_nonref = Clone::clone(intercept_id);
				let mut requested_next_hop_scid_nonref = Clone::clone(requested_next_hop_scid);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut inbound_amount_msat_nonref = Clone::clone(inbound_amount_msat);
				let mut expected_outbound_amount_msat_nonref = Clone::clone(expected_outbound_amount_msat);
				Event::HTLCIntercepted {
					intercept_id: crate::c_types::ThirtyTwoBytes { data: intercept_id_nonref.0 },
					requested_next_hop_scid: requested_next_hop_scid_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					inbound_amount_msat: inbound_amount_msat_nonref,
					expected_outbound_amount_msat: expected_outbound_amount_msat_nonref,
				}
			},
			nativeEvent::SpendableOutputs {ref outputs, ref channel_id, } => {
				let mut outputs_nonref = Clone::clone(outputs);
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.drain(..) { local_outputs_nonref.push( { crate::lightning::sign::SpendableOutputDescriptor::native_into(item) }); };
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut local_channel_id_nonref = crate::lightning::ln::types::ChannelId { inner: if channel_id_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_id_nonref.unwrap())) } }, is_owned: true };
				Event::SpendableOutputs {
					outputs: local_outputs_nonref.into(),
					channel_id: local_channel_id_nonref,
				}
			},
			nativeEvent::PaymentForwarded {ref prev_channel_id, ref next_channel_id, ref prev_user_channel_id, ref next_user_channel_id, ref total_fee_earned_msat, ref skimmed_fee_msat, ref claim_from_onchain_tx, ref outbound_amount_forwarded_msat, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut local_prev_channel_id_nonref = crate::lightning::ln::types::ChannelId { inner: if prev_channel_id_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((prev_channel_id_nonref.unwrap())) } }, is_owned: true };
				let mut next_channel_id_nonref = Clone::clone(next_channel_id);
				let mut local_next_channel_id_nonref = crate::lightning::ln::types::ChannelId { inner: if next_channel_id_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((next_channel_id_nonref.unwrap())) } }, is_owned: true };
				let mut prev_user_channel_id_nonref = Clone::clone(prev_user_channel_id);
				let mut local_prev_user_channel_id_nonref = if prev_user_channel_id_nonref.is_none() { crate::c_types::derived::COption_U128Z::None } else { crate::c_types::derived::COption_U128Z::Some( { prev_user_channel_id_nonref.unwrap().into() }) };
				let mut next_user_channel_id_nonref = Clone::clone(next_user_channel_id);
				let mut local_next_user_channel_id_nonref = if next_user_channel_id_nonref.is_none() { crate::c_types::derived::COption_U128Z::None } else { crate::c_types::derived::COption_U128Z::Some( { next_user_channel_id_nonref.unwrap().into() }) };
				let mut total_fee_earned_msat_nonref = Clone::clone(total_fee_earned_msat);
				let mut local_total_fee_earned_msat_nonref = if total_fee_earned_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { total_fee_earned_msat_nonref.unwrap() }) };
				let mut skimmed_fee_msat_nonref = Clone::clone(skimmed_fee_msat);
				let mut local_skimmed_fee_msat_nonref = if skimmed_fee_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { skimmed_fee_msat_nonref.unwrap() }) };
				let mut claim_from_onchain_tx_nonref = Clone::clone(claim_from_onchain_tx);
				let mut outbound_amount_forwarded_msat_nonref = Clone::clone(outbound_amount_forwarded_msat);
				let mut local_outbound_amount_forwarded_msat_nonref = if outbound_amount_forwarded_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { outbound_amount_forwarded_msat_nonref.unwrap() }) };
				Event::PaymentForwarded {
					prev_channel_id: local_prev_channel_id_nonref,
					next_channel_id: local_next_channel_id_nonref,
					prev_user_channel_id: local_prev_user_channel_id_nonref,
					next_user_channel_id: local_next_user_channel_id_nonref,
					total_fee_earned_msat: local_total_fee_earned_msat_nonref,
					skimmed_fee_msat: local_skimmed_fee_msat_nonref,
					claim_from_onchain_tx: claim_from_onchain_tx_nonref,
					outbound_amount_forwarded_msat: local_outbound_amount_forwarded_msat_nonref,
				}
			},
			nativeEvent::ChannelPending {ref channel_id, ref user_channel_id, ref former_temporary_channel_id, ref counterparty_node_id, ref funding_txo, ref channel_type, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut former_temporary_channel_id_nonref = Clone::clone(former_temporary_channel_id);
				let mut local_former_temporary_channel_id_nonref = crate::lightning::ln::types::ChannelId { inner: if former_temporary_channel_id_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((former_temporary_channel_id_nonref.unwrap())) } }, is_owned: true };
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut funding_txo_nonref = Clone::clone(funding_txo);
				let mut channel_type_nonref = Clone::clone(channel_type);
				let mut local_channel_type_nonref = crate::lightning_types::features::ChannelTypeFeatures { inner: if channel_type_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_type_nonref.unwrap())) } }, is_owned: true };
				Event::ChannelPending {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
					user_channel_id: user_channel_id_nonref.into(),
					former_temporary_channel_id: local_former_temporary_channel_id_nonref,
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					funding_txo: crate::c_types::bitcoin_to_C_outpoint(&funding_txo_nonref),
					channel_type: local_channel_type_nonref,
				}
			},
			nativeEvent::ChannelReady {ref channel_id, ref user_channel_id, ref counterparty_node_id, ref channel_type, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_type_nonref = Clone::clone(channel_type);
				Event::ChannelReady {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
					user_channel_id: user_channel_id_nonref.into(),
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					channel_type: crate::lightning_types::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type_nonref), is_owned: true },
				}
			},
			nativeEvent::ChannelClosed {ref channel_id, ref user_channel_id, ref reason, ref counterparty_node_id, ref channel_capacity_sats, ref channel_funding_txo, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut reason_nonref = Clone::clone(reason);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut local_counterparty_node_id_nonref = if counterparty_node_id_nonref.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(counterparty_node_id_nonref.unwrap())) } };
				let mut channel_capacity_sats_nonref = Clone::clone(channel_capacity_sats);
				let mut local_channel_capacity_sats_nonref = if channel_capacity_sats_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { channel_capacity_sats_nonref.unwrap() }) };
				let mut channel_funding_txo_nonref = Clone::clone(channel_funding_txo);
				let mut local_channel_funding_txo_nonref = crate::lightning::chain::transaction::OutPoint { inner: if channel_funding_txo_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_funding_txo_nonref.unwrap())) } }, is_owned: true };
				Event::ChannelClosed {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
					user_channel_id: user_channel_id_nonref.into(),
					reason: crate::lightning::events::ClosureReason::native_into(reason_nonref),
					counterparty_node_id: local_counterparty_node_id_nonref,
					channel_capacity_sats: local_channel_capacity_sats_nonref,
					channel_funding_txo: local_channel_funding_txo_nonref,
				}
			},
			nativeEvent::DiscardFunding {ref channel_id, ref funding_info, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut funding_info_nonref = Clone::clone(funding_info);
				Event::DiscardFunding {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id_nonref), is_owned: true },
					funding_info: crate::lightning::events::FundingInfo::native_into(funding_info_nonref),
				}
			},
			nativeEvent::OpenChannelRequest {ref temporary_channel_id, ref counterparty_node_id, ref funding_satoshis, ref push_msat, ref channel_type, ref is_announced, ref params, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut funding_satoshis_nonref = Clone::clone(funding_satoshis);
				let mut push_msat_nonref = Clone::clone(push_msat);
				let mut channel_type_nonref = Clone::clone(channel_type);
				let mut is_announced_nonref = Clone::clone(is_announced);
				let mut params_nonref = Clone::clone(params);
				Event::OpenChannelRequest {
					temporary_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(temporary_channel_id_nonref), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					funding_satoshis: funding_satoshis_nonref,
					push_msat: push_msat_nonref,
					channel_type: crate::lightning_types::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type_nonref), is_owned: true },
					is_announced: is_announced_nonref,
					params: crate::lightning::ln::msgs::ChannelParameters { inner: ObjOps::heap_alloc(params_nonref), is_owned: true },
				}
			},
			nativeEvent::HTLCHandlingFailed {ref prev_channel_id, ref failed_next_destination, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut failed_next_destination_nonref = Clone::clone(failed_next_destination);
				Event::HTLCHandlingFailed {
					prev_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(prev_channel_id_nonref), is_owned: true },
					failed_next_destination: crate::lightning::events::HTLCDestination::native_into(failed_next_destination_nonref),
				}
			},
			nativeEvent::BumpTransaction (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Event::BumpTransaction (
					crate::lightning::events::bump_transaction::BumpTransactionEvent::native_into(a_nonref),
				)
			},
			nativeEvent::OnionMessageIntercepted {ref peer_node_id, ref message, } => {
				let mut peer_node_id_nonref = Clone::clone(peer_node_id);
				let mut message_nonref = Clone::clone(message);
				Event::OnionMessageIntercepted {
					peer_node_id: crate::c_types::PublicKey::from_rust(&peer_node_id_nonref),
					message: crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(message_nonref), is_owned: true },
				}
			},
			nativeEvent::OnionMessagePeerConnected {ref peer_node_id, } => {
				let mut peer_node_id_nonref = Clone::clone(peer_node_id);
				Event::OnionMessagePeerConnected {
					peer_node_id: crate::c_types::PublicKey::from_rust(&peer_node_id_nonref),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeEvent) -> Self {
		match native {
			nativeEvent::FundingGenerationReady {mut temporary_channel_id, mut counterparty_node_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				Event::FundingGenerationReady {
					temporary_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(temporary_channel_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					channel_value_satoshis: channel_value_satoshis,
					output_script: output_script.to_bytes().into(),
					user_channel_id: user_channel_id.into(),
				}
			},
			nativeEvent::FundingTxBroadcastSafe {mut channel_id, mut user_channel_id, mut funding_txo, mut counterparty_node_id, mut former_temporary_channel_id, } => {
				Event::FundingTxBroadcastSafe {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
					user_channel_id: user_channel_id.into(),
					funding_txo: crate::c_types::bitcoin_to_C_outpoint(&funding_txo),
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					former_temporary_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(former_temporary_channel_id), is_owned: true },
				}
			},
			nativeEvent::PaymentClaimable {mut receiver_node_id, mut payment_hash, mut onion_fields, mut amount_msat, mut counterparty_skimmed_fee_msat, mut purpose, mut via_channel_id, mut via_user_channel_id, mut claim_deadline, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id.unwrap())) } };
				let mut local_onion_fields = crate::lightning::ln::outbound_payment::RecipientOnionFields { inner: if onion_fields.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((onion_fields.unwrap())) } }, is_owned: true };
				let mut local_via_channel_id = crate::lightning::ln::types::ChannelId { inner: if via_channel_id.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((via_channel_id.unwrap())) } }, is_owned: true };
				let mut local_via_user_channel_id = if via_user_channel_id.is_none() { crate::c_types::derived::COption_U128Z::None } else { crate::c_types::derived::COption_U128Z::Some( { via_user_channel_id.unwrap().into() }) };
				let mut local_claim_deadline = if claim_deadline.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { claim_deadline.unwrap() }) };
				Event::PaymentClaimable {
					receiver_node_id: local_receiver_node_id,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					onion_fields: local_onion_fields,
					amount_msat: amount_msat,
					counterparty_skimmed_fee_msat: counterparty_skimmed_fee_msat,
					purpose: crate::lightning::events::PaymentPurpose::native_into(purpose),
					via_channel_id: local_via_channel_id,
					via_user_channel_id: local_via_user_channel_id,
					claim_deadline: local_claim_deadline,
				}
			},
			nativeEvent::PaymentClaimed {mut receiver_node_id, mut payment_hash, mut amount_msat, mut purpose, mut htlcs, mut sender_intended_total_msat, mut onion_fields, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id.unwrap())) } };
				let mut local_htlcs = Vec::new(); for mut item in htlcs.drain(..) { local_htlcs.push( { crate::lightning::events::ClaimedHTLC { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut local_sender_intended_total_msat = if sender_intended_total_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { sender_intended_total_msat.unwrap() }) };
				let mut local_onion_fields = crate::lightning::ln::outbound_payment::RecipientOnionFields { inner: if onion_fields.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((onion_fields.unwrap())) } }, is_owned: true };
				Event::PaymentClaimed {
					receiver_node_id: local_receiver_node_id,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					amount_msat: amount_msat,
					purpose: crate::lightning::events::PaymentPurpose::native_into(purpose),
					htlcs: local_htlcs.into(),
					sender_intended_total_msat: local_sender_intended_total_msat,
					onion_fields: local_onion_fields,
				}
			},
			nativeEvent::ConnectionNeeded {mut node_id, mut addresses, } => {
				let mut local_addresses = Vec::new(); for mut item in addresses.drain(..) { local_addresses.push( { crate::lightning::ln::msgs::SocketAddress::native_into(item) }); };
				Event::ConnectionNeeded {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					addresses: local_addresses.into(),
				}
			},
			nativeEvent::InvoiceReceived {mut payment_id, mut invoice, mut context, mut responder, } => {
				let mut local_context = if context.is_none() { crate::c_types::derived::COption_OffersContextZ::None } else { crate::c_types::derived::COption_OffersContextZ::Some( { crate::lightning::blinded_path::message::OffersContext::native_into(context.unwrap()) }) };
				let mut local_responder = crate::lightning::onion_message::messenger::Responder { inner: if responder.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((responder.unwrap())) } }, is_owned: true };
				Event::InvoiceReceived {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					invoice: crate::lightning::offers::invoice::Bolt12Invoice { inner: ObjOps::heap_alloc(invoice), is_owned: true },
					context: local_context,
					responder: local_responder,
				}
			},
			nativeEvent::PaymentSent {mut payment_id, mut payment_preimage, mut payment_hash, mut fee_paid_msat, } => {
				let mut local_payment_id = if payment_id.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_id.unwrap().0 } }) };
				let mut local_fee_paid_msat = if fee_paid_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { fee_paid_msat.unwrap() }) };
				Event::PaymentSent {
					payment_id: local_payment_id,
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					fee_paid_msat: local_fee_paid_msat,
				}
			},
			nativeEvent::PaymentFailed {mut payment_id, mut payment_hash, mut reason, } => {
				let mut local_payment_hash = if payment_hash.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_hash.unwrap().0 } }) };
				let mut local_reason = if reason.is_none() { crate::c_types::derived::COption_PaymentFailureReasonZ::None } else { crate::c_types::derived::COption_PaymentFailureReasonZ::Some( { crate::lightning::events::PaymentFailureReason::native_into(reason.unwrap()) }) };
				Event::PaymentFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: local_payment_hash,
					reason: local_reason,
				}
			},
			nativeEvent::PaymentPathSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				let mut local_payment_hash = if payment_hash.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_hash.unwrap().0 } }) };
				Event::PaymentPathSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: local_payment_hash,
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path), is_owned: true },
				}
			},
			nativeEvent::PaymentPathFailed {mut payment_id, mut payment_hash, mut payment_failed_permanently, mut failure, mut path, mut short_channel_id, } => {
				let mut local_payment_id = if payment_id.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: payment_id.unwrap().0 } }) };
				let mut local_short_channel_id = if short_channel_id.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id.unwrap() }) };
				Event::PaymentPathFailed {
					payment_id: local_payment_id,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					payment_failed_permanently: payment_failed_permanently,
					failure: crate::lightning::events::PathFailure::native_into(failure),
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path), is_owned: true },
					short_channel_id: local_short_channel_id,
				}
			},
			nativeEvent::ProbeSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				Event::ProbeSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path), is_owned: true },
				}
			},
			nativeEvent::ProbeFailed {mut payment_id, mut payment_hash, mut path, mut short_channel_id, } => {
				let mut local_short_channel_id = if short_channel_id.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id.unwrap() }) };
				Event::ProbeFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					path: crate::lightning::routing::router::Path { inner: ObjOps::heap_alloc(path), is_owned: true },
					short_channel_id: local_short_channel_id,
				}
			},
			nativeEvent::PendingHTLCsForwardable {mut time_forwardable, } => {
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable.as_secs(),
				}
			},
			nativeEvent::HTLCIntercepted {mut intercept_id, mut requested_next_hop_scid, mut payment_hash, mut inbound_amount_msat, mut expected_outbound_amount_msat, } => {
				Event::HTLCIntercepted {
					intercept_id: crate::c_types::ThirtyTwoBytes { data: intercept_id.0 },
					requested_next_hop_scid: requested_next_hop_scid,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					inbound_amount_msat: inbound_amount_msat,
					expected_outbound_amount_msat: expected_outbound_amount_msat,
				}
			},
			nativeEvent::SpendableOutputs {mut outputs, mut channel_id, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.drain(..) { local_outputs.push( { crate::lightning::sign::SpendableOutputDescriptor::native_into(item) }); };
				let mut local_channel_id = crate::lightning::ln::types::ChannelId { inner: if channel_id.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_id.unwrap())) } }, is_owned: true };
				Event::SpendableOutputs {
					outputs: local_outputs.into(),
					channel_id: local_channel_id,
				}
			},
			nativeEvent::PaymentForwarded {mut prev_channel_id, mut next_channel_id, mut prev_user_channel_id, mut next_user_channel_id, mut total_fee_earned_msat, mut skimmed_fee_msat, mut claim_from_onchain_tx, mut outbound_amount_forwarded_msat, } => {
				let mut local_prev_channel_id = crate::lightning::ln::types::ChannelId { inner: if prev_channel_id.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((prev_channel_id.unwrap())) } }, is_owned: true };
				let mut local_next_channel_id = crate::lightning::ln::types::ChannelId { inner: if next_channel_id.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((next_channel_id.unwrap())) } }, is_owned: true };
				let mut local_prev_user_channel_id = if prev_user_channel_id.is_none() { crate::c_types::derived::COption_U128Z::None } else { crate::c_types::derived::COption_U128Z::Some( { prev_user_channel_id.unwrap().into() }) };
				let mut local_next_user_channel_id = if next_user_channel_id.is_none() { crate::c_types::derived::COption_U128Z::None } else { crate::c_types::derived::COption_U128Z::Some( { next_user_channel_id.unwrap().into() }) };
				let mut local_total_fee_earned_msat = if total_fee_earned_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { total_fee_earned_msat.unwrap() }) };
				let mut local_skimmed_fee_msat = if skimmed_fee_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { skimmed_fee_msat.unwrap() }) };
				let mut local_outbound_amount_forwarded_msat = if outbound_amount_forwarded_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { outbound_amount_forwarded_msat.unwrap() }) };
				Event::PaymentForwarded {
					prev_channel_id: local_prev_channel_id,
					next_channel_id: local_next_channel_id,
					prev_user_channel_id: local_prev_user_channel_id,
					next_user_channel_id: local_next_user_channel_id,
					total_fee_earned_msat: local_total_fee_earned_msat,
					skimmed_fee_msat: local_skimmed_fee_msat,
					claim_from_onchain_tx: claim_from_onchain_tx,
					outbound_amount_forwarded_msat: local_outbound_amount_forwarded_msat,
				}
			},
			nativeEvent::ChannelPending {mut channel_id, mut user_channel_id, mut former_temporary_channel_id, mut counterparty_node_id, mut funding_txo, mut channel_type, } => {
				let mut local_former_temporary_channel_id = crate::lightning::ln::types::ChannelId { inner: if former_temporary_channel_id.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((former_temporary_channel_id.unwrap())) } }, is_owned: true };
				let mut local_channel_type = crate::lightning_types::features::ChannelTypeFeatures { inner: if channel_type.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_type.unwrap())) } }, is_owned: true };
				Event::ChannelPending {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
					user_channel_id: user_channel_id.into(),
					former_temporary_channel_id: local_former_temporary_channel_id,
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					funding_txo: crate::c_types::bitcoin_to_C_outpoint(&funding_txo),
					channel_type: local_channel_type,
				}
			},
			nativeEvent::ChannelReady {mut channel_id, mut user_channel_id, mut counterparty_node_id, mut channel_type, } => {
				Event::ChannelReady {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
					user_channel_id: user_channel_id.into(),
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					channel_type: crate::lightning_types::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type), is_owned: true },
				}
			},
			nativeEvent::ChannelClosed {mut channel_id, mut user_channel_id, mut reason, mut counterparty_node_id, mut channel_capacity_sats, mut channel_funding_txo, } => {
				let mut local_counterparty_node_id = if counterparty_node_id.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(counterparty_node_id.unwrap())) } };
				let mut local_channel_capacity_sats = if channel_capacity_sats.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { channel_capacity_sats.unwrap() }) };
				let mut local_channel_funding_txo = crate::lightning::chain::transaction::OutPoint { inner: if channel_funding_txo.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((channel_funding_txo.unwrap())) } }, is_owned: true };
				Event::ChannelClosed {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
					user_channel_id: user_channel_id.into(),
					reason: crate::lightning::events::ClosureReason::native_into(reason),
					counterparty_node_id: local_counterparty_node_id,
					channel_capacity_sats: local_channel_capacity_sats,
					channel_funding_txo: local_channel_funding_txo,
				}
			},
			nativeEvent::DiscardFunding {mut channel_id, mut funding_info, } => {
				Event::DiscardFunding {
					channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(channel_id), is_owned: true },
					funding_info: crate::lightning::events::FundingInfo::native_into(funding_info),
				}
			},
			nativeEvent::OpenChannelRequest {mut temporary_channel_id, mut counterparty_node_id, mut funding_satoshis, mut push_msat, mut channel_type, mut is_announced, mut params, } => {
				Event::OpenChannelRequest {
					temporary_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(temporary_channel_id), is_owned: true },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					funding_satoshis: funding_satoshis,
					push_msat: push_msat,
					channel_type: crate::lightning_types::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type), is_owned: true },
					is_announced: is_announced,
					params: crate::lightning::ln::msgs::ChannelParameters { inner: ObjOps::heap_alloc(params), is_owned: true },
				}
			},
			nativeEvent::HTLCHandlingFailed {mut prev_channel_id, mut failed_next_destination, } => {
				Event::HTLCHandlingFailed {
					prev_channel_id: crate::lightning::ln::types::ChannelId { inner: ObjOps::heap_alloc(prev_channel_id), is_owned: true },
					failed_next_destination: crate::lightning::events::HTLCDestination::native_into(failed_next_destination),
				}
			},
			nativeEvent::BumpTransaction (mut a, ) => {
				Event::BumpTransaction (
					crate::lightning::events::bump_transaction::BumpTransactionEvent::native_into(a),
				)
			},
			nativeEvent::OnionMessageIntercepted {mut peer_node_id, mut message, } => {
				Event::OnionMessageIntercepted {
					peer_node_id: crate::c_types::PublicKey::from_rust(&peer_node_id),
					message: crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(message), is_owned: true },
				}
			},
			nativeEvent::OnionMessagePeerConnected {mut peer_node_id, } => {
				Event::OnionMessagePeerConnected {
					peer_node_id: crate::c_types::PublicKey::from_rust(&peer_node_id),
				}
			},
		}
	}
}
/// Frees any resources used by the Event
#[no_mangle]
pub extern "C" fn Event_free(this_ptr: Event) { }
/// Creates a copy of the Event
#[no_mangle]
pub extern "C" fn Event_clone(orig: &Event) -> Event {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Event_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Event)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Event_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Event) };
}
#[no_mangle]
/// Utility method to constructs a new FundingGenerationReady-variant Event
pub extern "C" fn Event_funding_generation_ready(temporary_channel_id: crate::lightning::ln::types::ChannelId, counterparty_node_id: crate::c_types::PublicKey, channel_value_satoshis: u64, output_script: crate::c_types::derived::CVec_u8Z, user_channel_id: crate::c_types::U128) -> Event {
	Event::FundingGenerationReady {
		temporary_channel_id,
		counterparty_node_id,
		channel_value_satoshis,
		output_script,
		user_channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new FundingTxBroadcastSafe-variant Event
pub extern "C" fn Event_funding_tx_broadcast_safe(channel_id: crate::lightning::ln::types::ChannelId, user_channel_id: crate::c_types::U128, funding_txo: crate::lightning::chain::transaction::OutPoint, counterparty_node_id: crate::c_types::PublicKey, former_temporary_channel_id: crate::lightning::ln::types::ChannelId) -> Event {
	Event::FundingTxBroadcastSafe {
		channel_id,
		user_channel_id,
		funding_txo,
		counterparty_node_id,
		former_temporary_channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentClaimable-variant Event
pub extern "C" fn Event_payment_claimable(receiver_node_id: crate::c_types::PublicKey, payment_hash: crate::c_types::ThirtyTwoBytes, onion_fields: crate::lightning::ln::outbound_payment::RecipientOnionFields, amount_msat: u64, counterparty_skimmed_fee_msat: u64, purpose: crate::lightning::events::PaymentPurpose, via_channel_id: crate::lightning::ln::types::ChannelId, via_user_channel_id: crate::c_types::derived::COption_U128Z, claim_deadline: crate::c_types::derived::COption_u32Z) -> Event {
	Event::PaymentClaimable {
		receiver_node_id,
		payment_hash,
		onion_fields,
		amount_msat,
		counterparty_skimmed_fee_msat,
		purpose,
		via_channel_id,
		via_user_channel_id,
		claim_deadline,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentClaimed-variant Event
pub extern "C" fn Event_payment_claimed(receiver_node_id: crate::c_types::PublicKey, payment_hash: crate::c_types::ThirtyTwoBytes, amount_msat: u64, purpose: crate::lightning::events::PaymentPurpose, htlcs: crate::c_types::derived::CVec_ClaimedHTLCZ, sender_intended_total_msat: crate::c_types::derived::COption_u64Z, onion_fields: crate::lightning::ln::outbound_payment::RecipientOnionFields) -> Event {
	Event::PaymentClaimed {
		receiver_node_id,
		payment_hash,
		amount_msat,
		purpose,
		htlcs,
		sender_intended_total_msat,
		onion_fields,
	}
}
#[no_mangle]
/// Utility method to constructs a new ConnectionNeeded-variant Event
pub extern "C" fn Event_connection_needed(node_id: crate::c_types::PublicKey, addresses: crate::c_types::derived::CVec_SocketAddressZ) -> Event {
	Event::ConnectionNeeded {
		node_id,
		addresses,
	}
}
#[no_mangle]
/// Utility method to constructs a new InvoiceReceived-variant Event
pub extern "C" fn Event_invoice_received(payment_id: crate::c_types::ThirtyTwoBytes, invoice: crate::lightning::offers::invoice::Bolt12Invoice, context: crate::c_types::derived::COption_OffersContextZ, responder: crate::lightning::onion_message::messenger::Responder) -> Event {
	Event::InvoiceReceived {
		payment_id,
		invoice,
		context,
		responder,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentSent-variant Event
pub extern "C" fn Event_payment_sent(payment_id: crate::c_types::derived::COption_ThirtyTwoBytesZ, payment_preimage: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, fee_paid_msat: crate::c_types::derived::COption_u64Z) -> Event {
	Event::PaymentSent {
		payment_id,
		payment_preimage,
		payment_hash,
		fee_paid_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentFailed-variant Event
pub extern "C" fn Event_payment_failed(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::derived::COption_ThirtyTwoBytesZ, reason: crate::c_types::derived::COption_PaymentFailureReasonZ) -> Event {
	Event::PaymentFailed {
		payment_id,
		payment_hash,
		reason,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentPathSuccessful-variant Event
pub extern "C" fn Event_payment_path_successful(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::derived::COption_ThirtyTwoBytesZ, path: crate::lightning::routing::router::Path) -> Event {
	Event::PaymentPathSuccessful {
		payment_id,
		payment_hash,
		path,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentPathFailed-variant Event
pub extern "C" fn Event_payment_path_failed(payment_id: crate::c_types::derived::COption_ThirtyTwoBytesZ, payment_hash: crate::c_types::ThirtyTwoBytes, payment_failed_permanently: bool, failure: crate::lightning::events::PathFailure, path: crate::lightning::routing::router::Path, short_channel_id: crate::c_types::derived::COption_u64Z) -> Event {
	Event::PaymentPathFailed {
		payment_id,
		payment_hash,
		payment_failed_permanently,
		failure,
		path,
		short_channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new ProbeSuccessful-variant Event
pub extern "C" fn Event_probe_successful(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, path: crate::lightning::routing::router::Path) -> Event {
	Event::ProbeSuccessful {
		payment_id,
		payment_hash,
		path,
	}
}
#[no_mangle]
/// Utility method to constructs a new ProbeFailed-variant Event
pub extern "C" fn Event_probe_failed(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, path: crate::lightning::routing::router::Path, short_channel_id: crate::c_types::derived::COption_u64Z) -> Event {
	Event::ProbeFailed {
		payment_id,
		payment_hash,
		path,
		short_channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new PendingHTLCsForwardable-variant Event
pub extern "C" fn Event_pending_htlcs_forwardable(time_forwardable: u64) -> Event {
	Event::PendingHTLCsForwardable {
		time_forwardable,
	}
}
#[no_mangle]
/// Utility method to constructs a new HTLCIntercepted-variant Event
pub extern "C" fn Event_htlcintercepted(intercept_id: crate::c_types::ThirtyTwoBytes, requested_next_hop_scid: u64, payment_hash: crate::c_types::ThirtyTwoBytes, inbound_amount_msat: u64, expected_outbound_amount_msat: u64) -> Event {
	Event::HTLCIntercepted {
		intercept_id,
		requested_next_hop_scid,
		payment_hash,
		inbound_amount_msat,
		expected_outbound_amount_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new SpendableOutputs-variant Event
pub extern "C" fn Event_spendable_outputs(outputs: crate::c_types::derived::CVec_SpendableOutputDescriptorZ, channel_id: crate::lightning::ln::types::ChannelId) -> Event {
	Event::SpendableOutputs {
		outputs,
		channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentForwarded-variant Event
pub extern "C" fn Event_payment_forwarded(prev_channel_id: crate::lightning::ln::types::ChannelId, next_channel_id: crate::lightning::ln::types::ChannelId, prev_user_channel_id: crate::c_types::derived::COption_U128Z, next_user_channel_id: crate::c_types::derived::COption_U128Z, total_fee_earned_msat: crate::c_types::derived::COption_u64Z, skimmed_fee_msat: crate::c_types::derived::COption_u64Z, claim_from_onchain_tx: bool, outbound_amount_forwarded_msat: crate::c_types::derived::COption_u64Z) -> Event {
	Event::PaymentForwarded {
		prev_channel_id,
		next_channel_id,
		prev_user_channel_id,
		next_user_channel_id,
		total_fee_earned_msat,
		skimmed_fee_msat,
		claim_from_onchain_tx,
		outbound_amount_forwarded_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelPending-variant Event
pub extern "C" fn Event_channel_pending(channel_id: crate::lightning::ln::types::ChannelId, user_channel_id: crate::c_types::U128, former_temporary_channel_id: crate::lightning::ln::types::ChannelId, counterparty_node_id: crate::c_types::PublicKey, funding_txo: crate::lightning::chain::transaction::OutPoint, channel_type: crate::lightning_types::features::ChannelTypeFeatures) -> Event {
	Event::ChannelPending {
		channel_id,
		user_channel_id,
		former_temporary_channel_id,
		counterparty_node_id,
		funding_txo,
		channel_type,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelReady-variant Event
pub extern "C" fn Event_channel_ready(channel_id: crate::lightning::ln::types::ChannelId, user_channel_id: crate::c_types::U128, counterparty_node_id: crate::c_types::PublicKey, channel_type: crate::lightning_types::features::ChannelTypeFeatures) -> Event {
	Event::ChannelReady {
		channel_id,
		user_channel_id,
		counterparty_node_id,
		channel_type,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelClosed-variant Event
pub extern "C" fn Event_channel_closed(channel_id: crate::lightning::ln::types::ChannelId, user_channel_id: crate::c_types::U128, reason: crate::lightning::events::ClosureReason, counterparty_node_id: crate::c_types::PublicKey, channel_capacity_sats: crate::c_types::derived::COption_u64Z, channel_funding_txo: crate::lightning::chain::transaction::OutPoint) -> Event {
	Event::ChannelClosed {
		channel_id,
		user_channel_id,
		reason,
		counterparty_node_id,
		channel_capacity_sats,
		channel_funding_txo,
	}
}
#[no_mangle]
/// Utility method to constructs a new DiscardFunding-variant Event
pub extern "C" fn Event_discard_funding(channel_id: crate::lightning::ln::types::ChannelId, funding_info: crate::lightning::events::FundingInfo) -> Event {
	Event::DiscardFunding {
		channel_id,
		funding_info,
	}
}
#[no_mangle]
/// Utility method to constructs a new OpenChannelRequest-variant Event
pub extern "C" fn Event_open_channel_request(temporary_channel_id: crate::lightning::ln::types::ChannelId, counterparty_node_id: crate::c_types::PublicKey, funding_satoshis: u64, push_msat: u64, channel_type: crate::lightning_types::features::ChannelTypeFeatures, is_announced: bool, params: crate::lightning::ln::msgs::ChannelParameters) -> Event {
	Event::OpenChannelRequest {
		temporary_channel_id,
		counterparty_node_id,
		funding_satoshis,
		push_msat,
		channel_type,
		is_announced,
		params,
	}
}
#[no_mangle]
/// Utility method to constructs a new HTLCHandlingFailed-variant Event
pub extern "C" fn Event_htlchandling_failed(prev_channel_id: crate::lightning::ln::types::ChannelId, failed_next_destination: crate::lightning::events::HTLCDestination) -> Event {
	Event::HTLCHandlingFailed {
		prev_channel_id,
		failed_next_destination,
	}
}
#[no_mangle]
/// Utility method to constructs a new BumpTransaction-variant Event
pub extern "C" fn Event_bump_transaction(a: crate::lightning::events::bump_transaction::BumpTransactionEvent) -> Event {
	Event::BumpTransaction(a, )
}
#[no_mangle]
/// Utility method to constructs a new OnionMessageIntercepted-variant Event
pub extern "C" fn Event_onion_message_intercepted(peer_node_id: crate::c_types::PublicKey, message: crate::lightning::ln::msgs::OnionMessage) -> Event {
	Event::OnionMessageIntercepted {
		peer_node_id,
		message,
	}
}
#[no_mangle]
/// Utility method to constructs a new OnionMessagePeerConnected-variant Event
pub extern "C" fn Event_onion_message_peer_connected(peer_node_id: crate::c_types::PublicKey) -> Event {
	Event::OnionMessagePeerConnected {
		peer_node_id,
	}
}
/// Get a string which allows debug introspection of a Event object
pub extern "C" fn Event_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::Event }).into()}
/// Checks if two Events contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Event_eq(a: &Event, b: &Event) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the Event object into a byte array which can be read by Event_read
pub extern "C" fn Event_write(obj: &crate::lightning::events::Event) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn Event_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	Event_write(unsafe { &*(obj as *const Event) })
}
#[no_mangle]
/// Read a Event from a byte array, created by Event_write
pub extern "C" fn Event_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_EventZDecodeErrorZ {
	let res: Result<Option<lightning::events::Event>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_EventZ::None } else { crate::c_types::derived::COption_EventZ::Some( { crate::lightning::events::Event::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// An event generated by ChannelManager which indicates a message should be sent to a peer (or
/// broadcast to most peers).
/// These events are handled by PeerManager::process_events if you are using a PeerManager.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum MessageSendEvent {
	/// Used to indicate that we've accepted a channel open and should send the accept_channel
	/// message provided to the given peer.
	SendAcceptChannel {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::AcceptChannel,
	},
	/// Used to indicate that we've accepted a V2 channel open and should send the accept_channel2
	/// message provided to the given peer.
	SendAcceptChannelV2 {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::AcceptChannelV2,
	},
	/// Used to indicate that we've initiated a channel open and should send the open_channel
	/// message provided to the given peer.
	SendOpenChannel {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::OpenChannel,
	},
	/// Used to indicate that we've initiated a V2 channel open and should send the open_channel2
	/// message provided to the given peer.
	SendOpenChannelV2 {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::OpenChannelV2,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	SendFundingCreated {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::FundingCreated,
	},
	/// Used to indicate that a funding_signed message should be sent to the peer with the given node_id.
	SendFundingSigned {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::FundingSigned,
	},
	/// Used to indicate that a stfu message should be sent to the peer with the given node id.
	SendStfu {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::Stfu,
	},
	/// Used to indicate that a splice_init message should be sent to the peer with the given node id.
	SendSpliceInit {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::SpliceInit,
	},
	/// Used to indicate that a splice_ack message should be sent to the peer with the given node id.
	SendSpliceAck {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::SpliceAck,
	},
	/// Used to indicate that a splice_locked message should be sent to the peer with the given node id.
	SendSpliceLocked {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::SpliceLocked,
	},
	/// Used to indicate that a tx_add_input message should be sent to the peer with the given node_id.
	SendTxAddInput {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxAddInput,
	},
	/// Used to indicate that a tx_add_output message should be sent to the peer with the given node_id.
	SendTxAddOutput {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxAddOutput,
	},
	/// Used to indicate that a tx_remove_input message should be sent to the peer with the given node_id.
	SendTxRemoveInput {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxRemoveInput,
	},
	/// Used to indicate that a tx_remove_output message should be sent to the peer with the given node_id.
	SendTxRemoveOutput {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxRemoveOutput,
	},
	/// Used to indicate that a tx_complete message should be sent to the peer with the given node_id.
	SendTxComplete {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxComplete,
	},
	/// Used to indicate that a tx_signatures message should be sent to the peer with the given node_id.
	SendTxSignatures {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxSignatures,
	},
	/// Used to indicate that a tx_init_rbf message should be sent to the peer with the given node_id.
	SendTxInitRbf {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxInitRbf,
	},
	/// Used to indicate that a tx_ack_rbf message should be sent to the peer with the given node_id.
	SendTxAckRbf {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxAckRbf,
	},
	/// Used to indicate that a tx_abort message should be sent to the peer with the given node_id.
	SendTxAbort {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::TxAbort,
	},
	/// Used to indicate that a channel_ready message should be sent to the peer with the given node_id.
	SendChannelReady {
		/// The node_id of the node which should receive these message(s)
		node_id: crate::c_types::PublicKey,
		/// The channel_ready message which should be sent.
		msg: crate::lightning::ln::msgs::ChannelReady,
	},
	/// Used to indicate that an announcement_signatures message should be sent to the peer with the given node_id.
	SendAnnouncementSignatures {
		/// The node_id of the node which should receive these message(s)
		node_id: crate::c_types::PublicKey,
		/// The announcement_signatures message which should be sent.
		msg: crate::lightning::ln::msgs::AnnouncementSignatures,
	},
	/// Used to indicate that a series of HTLC update messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	UpdateHTLCs {
		/// The node_id of the node which should receive these message(s)
		node_id: crate::c_types::PublicKey,
		/// The update messages which should be sent. ALL messages in the struct should be sent!
		updates: crate::lightning::ln::msgs::CommitmentUpdate,
	},
	/// Used to indicate that a revoke_and_ack message should be sent to the peer with the given node_id.
	SendRevokeAndACK {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::RevokeAndACK,
	},
	/// Used to indicate that a closing_signed message should be sent to the peer with the given node_id.
	SendClosingSigned {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::ClosingSigned,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	SendShutdown {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::Shutdown,
	},
	/// Used to indicate that a channel_reestablish message should be sent to the peer with the given node_id.
	SendChannelReestablish {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::ChannelReestablish,
	},
	/// Used to send a channel_announcement and channel_update to a specific peer, likely on
	/// initial connection to ensure our peers know about our channels.
	SendChannelAnnouncement {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The channel_announcement which should be sent.
		msg: crate::lightning::ln::msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	///
	/// Note that after doing so, you very likely (unless you did so very recently) want to
	/// broadcast a node_announcement (e.g. via [`PeerManager::broadcast_node_announcement`]). This
	/// ensures that any nodes which see our channel_announcement also have a relevant
	/// node_announcement, including relevant feature flags which may be important for routing
	/// through or to us.
	///
	/// [`PeerManager::broadcast_node_announcement`]: crate::ln::peer_handler::PeerManager::broadcast_node_announcement
	BroadcastChannelAnnouncement {
		/// The channel_announcement which should be sent.
		msg: crate::lightning::ln::msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		update_msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		/// The channel_update which should be sent.
		msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a node_announcement should be broadcast to all peers.
	BroadcastNodeAnnouncement {
		/// The node_announcement which should be sent.
		msg: crate::lightning::ln::msgs::NodeAnnouncement,
	},
	/// Used to indicate that a channel_update should be sent to a single peer.
	/// In contrast to [`Self::BroadcastChannelUpdate`], this is used when the channel is a
	/// private channel and we shouldn't be informing all of our peers of channel parameters.
	SendChannelUpdate {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The channel_update which should be sent.
		msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Broadcast an error downstream to be handled
	HandleError {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The action which should be taken.
		action: crate::lightning::ln::msgs::ErrorAction,
	},
	/// Query a peer for channels with funding transaction UTXOs in a block range.
	SendChannelRangeQuery {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The query_channel_range which should be sent.
		msg: crate::lightning::ln::msgs::QueryChannelRange,
	},
	/// Request routing gossip messages from a peer for a list of channels identified by
	/// their short_channel_ids.
	SendShortIdsQuery {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The query_short_channel_ids which should be sent.
		msg: crate::lightning::ln::msgs::QueryShortChannelIds,
	},
	/// Sends a reply to a channel range query. This may be one of several SendReplyChannelRange events
	/// emitted during processing of the query.
	SendReplyChannelRange {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The reply_channel_range which should be sent.
		msg: crate::lightning::ln::msgs::ReplyChannelRange,
	},
	/// Sends a timestamp filter for inbound gossip. This should be sent on each new connection to
	/// enable receiving gossip messages from the peer.
	SendGossipTimestampFilter {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The gossip_timestamp_filter which should be sent.
		msg: crate::lightning::ln::msgs::GossipTimestampFilter,
	},
}
use lightning::events::MessageSendEvent as MessageSendEventImport;
pub(crate) type nativeMessageSendEvent = MessageSendEventImport;

impl MessageSendEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMessageSendEvent {
		match self {
			MessageSendEvent::SendAcceptChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendAcceptChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendAcceptChannelV2 {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendAcceptChannelV2 {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendOpenChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannelV2 {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendOpenChannelV2 {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendFundingCreated {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendFundingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendStfu {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendStfu {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendSpliceInit {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendSpliceInit {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendSpliceAck {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendSpliceAck {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendSpliceLocked {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendSpliceLocked {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAddInput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxAddInput {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAddOutput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxAddOutput {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxRemoveInput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxRemoveInput {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxRemoveOutput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxRemoveOutput {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxComplete {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxComplete {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxSignatures {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxInitRbf {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxInitRbf {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAckRbf {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxAckRbf {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAbort {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendTxAbort {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReady {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelReady {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendAnnouncementSignatures {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut updates_nonref = Clone::clone(updates);
				nativeMessageSendEvent::UpdateHTLCs {
					node_id: node_id_nonref.into_rust(),
					updates: *unsafe { Box::from_raw(updates_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendRevokeAndACK {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendClosingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendShutdown {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelReestablish {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelAnnouncement {ref node_id, ref msg, ref update_msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				nativeMessageSendEvent::SendChannelAnnouncement {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				let mut local_update_msg_nonref = if update_msg_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(update_msg_nonref.take_inner()) } }) };
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
					update_msg: local_update_msg_nonref,
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelUpdate {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelUpdate {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut action_nonref = Clone::clone(action);
				nativeMessageSendEvent::HandleError {
					node_id: node_id_nonref.into_rust(),
					action: action_nonref.into_native(),
				}
			},
			MessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelRangeQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendShortIdsQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendReplyChannelRange {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendReplyChannelRange {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendGossipTimestampFilter {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendGossipTimestampFilter {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeMessageSendEvent {
		match self {
			MessageSendEvent::SendAcceptChannel {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendAcceptChannel {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendAcceptChannelV2 {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendAcceptChannelV2 {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannel {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendOpenChannel {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannelV2 {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendOpenChannelV2 {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingCreated {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingCreated {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingSigned {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingSigned {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendStfu {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendStfu {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendSpliceInit {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendSpliceInit {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendSpliceAck {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendSpliceAck {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendSpliceLocked {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendSpliceLocked {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAddInput {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxAddInput {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAddOutput {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxAddOutput {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxRemoveInput {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxRemoveInput {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxRemoveOutput {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxRemoveOutput {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxComplete {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxComplete {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxSignatures {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxSignatures {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxInitRbf {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxInitRbf {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAckRbf {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxAckRbf {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendTxAbort {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendTxAbort {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReady {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelReady {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendAnnouncementSignatures {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendAnnouncementSignatures {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::UpdateHTLCs {mut node_id, mut updates, } => {
				nativeMessageSendEvent::UpdateHTLCs {
					node_id: node_id.into_rust(),
					updates: *unsafe { Box::from_raw(updates.take_inner()) },
				}
			},
			MessageSendEvent::SendRevokeAndACK {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendRevokeAndACK {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendClosingSigned {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendClosingSigned {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendShutdown {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendShutdown {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReestablish {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelReestablish {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelAnnouncement {mut node_id, mut msg, mut update_msg, } => {
				nativeMessageSendEvent::SendChannelAnnouncement {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				let mut local_update_msg = if update_msg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(update_msg.take_inner()) } }) };
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
					update_msg: local_update_msg,
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelUpdate {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelUpdate {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {mut node_id, mut action, } => {
				nativeMessageSendEvent::HandleError {
					node_id: node_id.into_rust(),
					action: action.into_native(),
				}
			},
			MessageSendEvent::SendChannelRangeQuery {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelRangeQuery {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendShortIdsQuery {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendShortIdsQuery {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendReplyChannelRange {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendReplyChannelRange {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendGossipTimestampFilter {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendGossipTimestampFilter {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &MessageSendEventImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeMessageSendEvent) };
		match native {
			nativeMessageSendEvent::SendAcceptChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendAcceptChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::AcceptChannel { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAcceptChannelV2 {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendAcceptChannelV2 {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::AcceptChannelV2 { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::OpenChannel { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannelV2 {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendOpenChannelV2 {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::OpenChannelV2 { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::FundingCreated { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::FundingSigned { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendStfu {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendStfu {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::Stfu { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendSpliceInit {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendSpliceInit {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::SpliceInit { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendSpliceAck {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendSpliceAck {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::SpliceAck { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendSpliceLocked {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendSpliceLocked {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::SpliceLocked { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAddInput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxAddInput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxAddInput { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAddOutput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxAddOutput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxAddOutput { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxRemoveInput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxRemoveInput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxRemoveInput { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxRemoveOutput {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxRemoveOutput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxRemoveOutput { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxComplete {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxComplete {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxComplete { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxSignatures { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxInitRbf {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxInitRbf {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxInitRbf { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAckRbf {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxAckRbf {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxAckRbf { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAbort {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendTxAbort {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::TxAbort { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReady {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelReady {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelReady { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::AnnouncementSignatures { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut updates_nonref = Clone::clone(updates);
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					updates: crate::lightning::ln::msgs::CommitmentUpdate { inner: ObjOps::heap_alloc(updates_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::RevokeAndACK { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ClosingSigned { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::Shutdown { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelReestablish { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelAnnouncement {ref node_id, ref msg, ref update_msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				MessageSendEvent::SendChannelAnnouncement {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
					update_msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(update_msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				let mut local_update_msg_nonref = crate::lightning::ln::msgs::ChannelUpdate { inner: if update_msg_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((update_msg_nonref.unwrap())) } }, is_owned: true };
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
					update_msg: local_update_msg_nonref,
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::lightning::ln::msgs::NodeAnnouncement { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelUpdate {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelUpdate {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut action_nonref = Clone::clone(action);
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					action: crate::lightning::ln::msgs::ErrorAction::native_into(action_nonref),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::QueryChannelRange { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::QueryShortChannelIds { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendReplyChannelRange {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendReplyChannelRange {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ReplyChannelRange { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendGossipTimestampFilter {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendGossipTimestampFilter {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::GossipTimestampFilter { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeMessageSendEvent) -> Self {
		match native {
			nativeMessageSendEvent::SendAcceptChannel {mut node_id, mut msg, } => {
				MessageSendEvent::SendAcceptChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::AcceptChannel { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAcceptChannelV2 {mut node_id, mut msg, } => {
				MessageSendEvent::SendAcceptChannelV2 {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::AcceptChannelV2 { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {mut node_id, mut msg, } => {
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::OpenChannel { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannelV2 {mut node_id, mut msg, } => {
				MessageSendEvent::SendOpenChannelV2 {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::OpenChannelV2 { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::FundingCreated { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::FundingSigned { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendStfu {mut node_id, mut msg, } => {
				MessageSendEvent::SendStfu {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::Stfu { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendSpliceInit {mut node_id, mut msg, } => {
				MessageSendEvent::SendSpliceInit {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::SpliceInit { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendSpliceAck {mut node_id, mut msg, } => {
				MessageSendEvent::SendSpliceAck {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::SpliceAck { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendSpliceLocked {mut node_id, mut msg, } => {
				MessageSendEvent::SendSpliceLocked {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::SpliceLocked { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAddInput {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxAddInput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxAddInput { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAddOutput {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxAddOutput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxAddOutput { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxRemoveInput {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxRemoveInput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxRemoveInput { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxRemoveOutput {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxRemoveOutput {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxRemoveOutput { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxComplete {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxComplete {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxComplete { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxSignatures {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxSignatures { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxInitRbf {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxInitRbf {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxInitRbf { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAckRbf {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxAckRbf {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxAckRbf { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendTxAbort {mut node_id, mut msg, } => {
				MessageSendEvent::SendTxAbort {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::TxAbort { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReady {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelReady {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelReady { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {mut node_id, mut msg, } => {
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::AnnouncementSignatures { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {mut node_id, mut updates, } => {
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					updates: crate::lightning::ln::msgs::CommitmentUpdate { inner: ObjOps::heap_alloc(updates), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {mut node_id, mut msg, } => {
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::RevokeAndACK { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ClosingSigned { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {mut node_id, mut msg, } => {
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::Shutdown { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelReestablish { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelAnnouncement {mut node_id, mut msg, mut update_msg, } => {
				MessageSendEvent::SendChannelAnnouncement {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg), is_owned: true },
					update_msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(update_msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				let mut local_update_msg = crate::lightning::ln::msgs::ChannelUpdate { inner: if update_msg.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((update_msg.unwrap())) } }, is_owned: true };
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg), is_owned: true },
					update_msg: local_update_msg,
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::lightning::ln::msgs::NodeAnnouncement { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelUpdate {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelUpdate {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {mut node_id, mut action, } => {
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					action: crate::lightning::ln::msgs::ErrorAction::native_into(action),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::QueryChannelRange { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::QueryShortChannelIds { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendReplyChannelRange {mut node_id, mut msg, } => {
				MessageSendEvent::SendReplyChannelRange {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ReplyChannelRange { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendGossipTimestampFilter {mut node_id, mut msg, } => {
				MessageSendEvent::SendGossipTimestampFilter {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::GossipTimestampFilter { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the MessageSendEvent
#[no_mangle]
pub extern "C" fn MessageSendEvent_free(this_ptr: MessageSendEvent) { }
/// Creates a copy of the MessageSendEvent
#[no_mangle]
pub extern "C" fn MessageSendEvent_clone(orig: &MessageSendEvent) -> MessageSendEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageSendEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const MessageSendEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MessageSendEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut MessageSendEvent) };
}
#[no_mangle]
/// Utility method to constructs a new SendAcceptChannel-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_accept_channel(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::AcceptChannel) -> MessageSendEvent {
	MessageSendEvent::SendAcceptChannel {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendAcceptChannelV2-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_accept_channel_v2(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::AcceptChannelV2) -> MessageSendEvent {
	MessageSendEvent::SendAcceptChannelV2 {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendOpenChannel-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_open_channel(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::OpenChannel) -> MessageSendEvent {
	MessageSendEvent::SendOpenChannel {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendOpenChannelV2-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_open_channel_v2(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::OpenChannelV2) -> MessageSendEvent {
	MessageSendEvent::SendOpenChannelV2 {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendFundingCreated-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_funding_created(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::FundingCreated) -> MessageSendEvent {
	MessageSendEvent::SendFundingCreated {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendFundingSigned-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_funding_signed(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::FundingSigned) -> MessageSendEvent {
	MessageSendEvent::SendFundingSigned {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendStfu-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_stfu(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::Stfu) -> MessageSendEvent {
	MessageSendEvent::SendStfu {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendSpliceInit-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_splice_init(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::SpliceInit) -> MessageSendEvent {
	MessageSendEvent::SendSpliceInit {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendSpliceAck-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_splice_ack(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::SpliceAck) -> MessageSendEvent {
	MessageSendEvent::SendSpliceAck {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendSpliceLocked-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_splice_locked(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::SpliceLocked) -> MessageSendEvent {
	MessageSendEvent::SendSpliceLocked {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxAddInput-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_add_input(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxAddInput) -> MessageSendEvent {
	MessageSendEvent::SendTxAddInput {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxAddOutput-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_add_output(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxAddOutput) -> MessageSendEvent {
	MessageSendEvent::SendTxAddOutput {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxRemoveInput-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_remove_input(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxRemoveInput) -> MessageSendEvent {
	MessageSendEvent::SendTxRemoveInput {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxRemoveOutput-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_remove_output(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxRemoveOutput) -> MessageSendEvent {
	MessageSendEvent::SendTxRemoveOutput {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxComplete-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_complete(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxComplete) -> MessageSendEvent {
	MessageSendEvent::SendTxComplete {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxSignatures-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_signatures(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxSignatures) -> MessageSendEvent {
	MessageSendEvent::SendTxSignatures {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxInitRbf-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_init_rbf(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxInitRbf) -> MessageSendEvent {
	MessageSendEvent::SendTxInitRbf {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxAckRbf-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_ack_rbf(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxAckRbf) -> MessageSendEvent {
	MessageSendEvent::SendTxAckRbf {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendTxAbort-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_tx_abort(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::TxAbort) -> MessageSendEvent {
	MessageSendEvent::SendTxAbort {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelReady-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_ready(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelReady) -> MessageSendEvent {
	MessageSendEvent::SendChannelReady {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendAnnouncementSignatures-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_announcement_signatures(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::AnnouncementSignatures) -> MessageSendEvent {
	MessageSendEvent::SendAnnouncementSignatures {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new UpdateHTLCs-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_update_htlcs(node_id: crate::c_types::PublicKey, updates: crate::lightning::ln::msgs::CommitmentUpdate) -> MessageSendEvent {
	MessageSendEvent::UpdateHTLCs {
		node_id,
		updates,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendRevokeAndACK-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_revoke_and_ack(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::RevokeAndACK) -> MessageSendEvent {
	MessageSendEvent::SendRevokeAndACK {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendClosingSigned-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_closing_signed(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ClosingSigned) -> MessageSendEvent {
	MessageSendEvent::SendClosingSigned {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendShutdown-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_shutdown(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::Shutdown) -> MessageSendEvent {
	MessageSendEvent::SendShutdown {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelReestablish-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_reestablish(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelReestablish) -> MessageSendEvent {
	MessageSendEvent::SendChannelReestablish {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelAnnouncement-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_announcement(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelAnnouncement, update_msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::SendChannelAnnouncement {
		node_id,
		msg,
		update_msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new BroadcastChannelAnnouncement-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_broadcast_channel_announcement(msg: crate::lightning::ln::msgs::ChannelAnnouncement, update_msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::BroadcastChannelAnnouncement {
		msg,
		update_msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new BroadcastChannelUpdate-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_broadcast_channel_update(msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::BroadcastChannelUpdate {
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new BroadcastNodeAnnouncement-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_broadcast_node_announcement(msg: crate::lightning::ln::msgs::NodeAnnouncement) -> MessageSendEvent {
	MessageSendEvent::BroadcastNodeAnnouncement {
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelUpdate-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_update(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::SendChannelUpdate {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new HandleError-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_handle_error(node_id: crate::c_types::PublicKey, action: crate::lightning::ln::msgs::ErrorAction) -> MessageSendEvent {
	MessageSendEvent::HandleError {
		node_id,
		action,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelRangeQuery-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_range_query(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::QueryChannelRange) -> MessageSendEvent {
	MessageSendEvent::SendChannelRangeQuery {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendShortIdsQuery-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_short_ids_query(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::QueryShortChannelIds) -> MessageSendEvent {
	MessageSendEvent::SendShortIdsQuery {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendReplyChannelRange-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_reply_channel_range(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ReplyChannelRange) -> MessageSendEvent {
	MessageSendEvent::SendReplyChannelRange {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendGossipTimestampFilter-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_gossip_timestamp_filter(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::GossipTimestampFilter) -> MessageSendEvent {
	MessageSendEvent::SendGossipTimestampFilter {
		node_id,
		msg,
	}
}
/// Get a string which allows debug introspection of a MessageSendEvent object
pub extern "C" fn MessageSendEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::MessageSendEvent }).into()}
/// A trait indicating an object may generate message send events
#[repr(C)]
pub struct MessageSendEventsProvider {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	pub get_and_clear_pending_msg_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for MessageSendEventsProvider {}
unsafe impl Sync for MessageSendEventsProvider {}
#[allow(unused)]
pub(crate) fn MessageSendEventsProvider_clone_fields(orig: &MessageSendEventsProvider) -> MessageSendEventsProvider {
	MessageSendEventsProvider {
		this_arg: orig.this_arg,
		get_and_clear_pending_msg_events: Clone::clone(&orig.get_and_clear_pending_msg_events),
		free: Clone::clone(&orig.free),
	}
}

use lightning::events::MessageSendEventsProvider as rustMessageSendEventsProvider;
impl rustMessageSendEventsProvider for MessageSendEventsProvider {
	fn get_and_clear_pending_msg_events(&self) -> Vec<lightning::events::MessageSendEvent> {
		let mut ret = (self.get_and_clear_pending_msg_events)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { item.into_native() }); };
		local_ret
	}
}

pub struct MessageSendEventsProviderRef(MessageSendEventsProvider);
impl rustMessageSendEventsProvider for MessageSendEventsProviderRef {
	fn get_and_clear_pending_msg_events(&self) -> Vec<lightning::events::MessageSendEvent> {
		let mut ret = (self.0.get_and_clear_pending_msg_events)(self.0.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { item.into_native() }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for MessageSendEventsProvider {
	type Target = MessageSendEventsProviderRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const MessageSendEventsProviderRef) }
	}
}
impl core::ops::DerefMut for MessageSendEventsProvider {
	fn deref_mut(&mut self) -> &mut MessageSendEventsProviderRef {
		unsafe { &mut *(self as *mut _ as *mut MessageSendEventsProviderRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn MessageSendEventsProvider_free(this_ptr: MessageSendEventsProvider) { }
impl Drop for MessageSendEventsProvider {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait indicating an object may generate events.
///
/// Events are processed by passing an [`EventHandler`] to [`process_pending_events`].
///
/// Implementations of this trait may also feature an async version of event handling, as shown with
/// [`ChannelManager::process_pending_events_async`] and
/// [`ChainMonitor::process_pending_events_async`].
///
/// # Requirements
///
/// When using this trait, [`process_pending_events`] will call [`handle_event`] for each pending
/// event since the last invocation.
///
/// In order to ensure no [`Event`]s are lost, implementors of this trait will persist [`Event`]s
/// and replay any unhandled events on startup. An [`Event`] is considered handled when
/// [`process_pending_events`] returns `Ok(())`, thus handlers MUST fully handle [`Event`]s and
/// persist any relevant changes to disk *before* returning `Ok(())`. In case of an error (e.g.,
/// persistence failure) implementors should return `Err(ReplayEvent())`, signalling to the
/// [`EventsProvider`] to replay unhandled events on the next invocation (generally immediately).
/// Note that some events might not be replayed, please refer to the documentation for
/// the individual [`Event`] variants for more detail.
///
/// Further, because an application may crash between an [`Event`] being handled and the
/// implementor of this trait being re-serialized, [`Event`] handling must be idempotent - in
/// effect, [`Event`]s may be replayed.
///
/// Note, handlers may call back into the provider and thus deadlocking must be avoided. Be sure to
/// consult the provider's documentation on the implication of processing events and how a handler
/// may safely use the provider (e.g., see [`ChannelManager::process_pending_events`] and
/// [`ChainMonitor::process_pending_events`]).
///
/// (C-not implementable) As there is likely no reason for a user to implement this trait on their
/// own type(s).
///
/// [`process_pending_events`]: Self::process_pending_events
/// [`handle_event`]: EventHandler::handle_event
/// [`ChannelManager::process_pending_events`]: crate::ln::channelmanager::ChannelManager#method.process_pending_events
/// [`ChainMonitor::process_pending_events`]: crate::chain::chainmonitor::ChainMonitor#method.process_pending_events
/// [`ChannelManager::process_pending_events_async`]: crate::ln::channelmanager::ChannelManager::process_pending_events_async
/// [`ChainMonitor::process_pending_events_async`]: crate::chain::chainmonitor::ChainMonitor::process_pending_events_async
#[repr(C)]
pub struct EventsProvider {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Processes any events generated since the last call using the given event handler.
	///
	/// See the trait-level documentation for requirements.
	pub process_pending_events: extern "C" fn (this_arg: *const c_void, handler: crate::lightning::events::EventHandler),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EventsProvider {}
unsafe impl Sync for EventsProvider {}
#[allow(unused)]
pub(crate) fn EventsProvider_clone_fields(orig: &EventsProvider) -> EventsProvider {
	EventsProvider {
		this_arg: orig.this_arg,
		process_pending_events: Clone::clone(&orig.process_pending_events),
		free: Clone::clone(&orig.free),
	}
}

use lightning::events::EventsProvider as rustEventsProvider;
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn EventsProvider_free(this_ptr: EventsProvider) { }
impl Drop for EventsProvider {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::events::ReplayEvent as nativeReplayEventImport;
pub(crate) type nativeReplayEvent = nativeReplayEventImport;

/// An error type that may be returned to LDK in order to safely abort event handling if it can't
/// currently succeed (e.g., due to a persistence failure).
///
/// Depending on the type, LDK may ensure the event is persisted and will eventually be replayed.
/// Please refer to the documentation of each [`Event`] variant for more details.
#[must_use]
#[repr(C)]
pub struct ReplayEvent {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeReplayEvent,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for ReplayEvent {
	type Target = nativeReplayEvent;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for ReplayEvent { }
unsafe impl core::marker::Sync for ReplayEvent { }
impl Drop for ReplayEvent {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeReplayEvent>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ReplayEvent, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ReplayEvent_free(this_obj: ReplayEvent) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReplayEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeReplayEvent) };
}
#[allow(unused)]
impl ReplayEvent {
	pub(crate) fn get_native_ref(&self) -> &'static nativeReplayEvent {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeReplayEvent {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeReplayEvent {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// Constructs a new ReplayEvent given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ReplayEvent_new() -> ReplayEvent {
	ReplayEvent { inner: ObjOps::heap_alloc(lightning::events::ReplayEvent (
	)), is_owned: true }
}
impl Clone for ReplayEvent {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeReplayEvent>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReplayEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeReplayEvent)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ReplayEvent
pub extern "C" fn ReplayEvent_clone(orig: &ReplayEvent) -> ReplayEvent {
	orig.clone()
}
/// Get a string which allows debug introspection of a ReplayEvent object
pub extern "C" fn ReplayEvent_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::events::ReplayEvent }).into()}
/// A trait implemented for objects handling events from [`EventsProvider`].
///
/// An async variation also exists for implementations of [`EventsProvider`] that support async
/// event handling. The async event handler should satisfy the generic bounds: `F:
/// core::future::Future<Output = Result<(), ReplayEvent>>, H: Fn(Event) -> F`.
#[repr(C)]
pub struct EventHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Handles the given [`Event`].
	///
	/// See [`EventsProvider`] for details that must be considered when implementing this method.
	pub handle_event: extern "C" fn (this_arg: *const c_void, event: crate::lightning::events::Event) -> crate::c_types::derived::CResult_NoneReplayEventZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EventHandler {}
unsafe impl Sync for EventHandler {}
#[allow(unused)]
pub(crate) fn EventHandler_clone_fields(orig: &EventHandler) -> EventHandler {
	EventHandler {
		this_arg: orig.this_arg,
		handle_event: Clone::clone(&orig.handle_event),
		free: Clone::clone(&orig.free),
	}
}

use lightning::events::EventHandler as rustEventHandler;
impl rustEventHandler for EventHandler {
	fn handle_event(&self, mut event: lightning::events::Event) -> Result<(), lightning::events::ReplayEvent> {
		let mut ret = (self.handle_event)(self.this_arg, crate::lightning::events::Event::native_into(event));
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
}

pub struct EventHandlerRef(EventHandler);
impl rustEventHandler for EventHandlerRef {
	fn handle_event(&self, mut event: lightning::events::Event) -> Result<(), lightning::events::ReplayEvent> {
		let mut ret = (self.0.handle_event)(self.0.this_arg, crate::lightning::events::Event::native_into(event));
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for EventHandler {
	type Target = EventHandlerRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const EventHandlerRef) }
	}
}
impl core::ops::DerefMut for EventHandler {
	fn deref_mut(&mut self) -> &mut EventHandlerRef {
		unsafe { &mut *(self as *mut _ as *mut EventHandlerRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn EventHandler_free(this_ptr: EventHandler) { }
impl Drop for EventHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
