// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Log traits live here, which are called throughout the library to provide useful information for
//! debugging purposes.
//!
//! Log messages should be filtered client-side by implementing check against a given [`Record`]'s
//! [`Level`] field. Each module may have its own Logger or share one.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An enum representing the available verbosity levels of the logger.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Level {
	/// Designates extremely verbose information, including gossip-induced messages
	Gossip,
	/// Designates very low priority, often extremely verbose, information
	Trace,
	/// Designates lower priority information
	Debug,
	/// Designates useful information
	Info,
	/// Designates hazardous situations
	Warn,
	/// Designates very serious errors
	Error,
}
use lightning::util::logger::Level as LevelImport;
pub(crate) type nativeLevel = LevelImport;

impl Level {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLevel {
		match self {
			Level::Gossip => nativeLevel::Gossip,
			Level::Trace => nativeLevel::Trace,
			Level::Debug => nativeLevel::Debug,
			Level::Info => nativeLevel::Info,
			Level::Warn => nativeLevel::Warn,
			Level::Error => nativeLevel::Error,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLevel {
		match self {
			Level::Gossip => nativeLevel::Gossip,
			Level::Trace => nativeLevel::Trace,
			Level::Debug => nativeLevel::Debug,
			Level::Info => nativeLevel::Info,
			Level::Warn => nativeLevel::Warn,
			Level::Error => nativeLevel::Error,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &LevelImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeLevel) };
		match native {
			nativeLevel::Gossip => Level::Gossip,
			nativeLevel::Trace => Level::Trace,
			nativeLevel::Debug => Level::Debug,
			nativeLevel::Info => Level::Info,
			nativeLevel::Warn => Level::Warn,
			nativeLevel::Error => Level::Error,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLevel) -> Self {
		match native {
			nativeLevel::Gossip => Level::Gossip,
			nativeLevel::Trace => Level::Trace,
			nativeLevel::Debug => Level::Debug,
			nativeLevel::Info => Level::Info,
			nativeLevel::Warn => Level::Warn,
			nativeLevel::Error => Level::Error,
		}
	}
}
/// Creates a copy of the Level
#[no_mangle]
pub extern "C" fn Level_clone(orig: &Level) -> Level {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Level_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Level)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Level_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Level) };
}
#[no_mangle]
/// Utility method to constructs a new Gossip-variant Level
pub extern "C" fn Level_gossip() -> Level {
	Level::Gossip}
#[no_mangle]
/// Utility method to constructs a new Trace-variant Level
pub extern "C" fn Level_trace() -> Level {
	Level::Trace}
#[no_mangle]
/// Utility method to constructs a new Debug-variant Level
pub extern "C" fn Level_debug() -> Level {
	Level::Debug}
#[no_mangle]
/// Utility method to constructs a new Info-variant Level
pub extern "C" fn Level_info() -> Level {
	Level::Info}
#[no_mangle]
/// Utility method to constructs a new Warn-variant Level
pub extern "C" fn Level_warn() -> Level {
	Level::Warn}
#[no_mangle]
/// Utility method to constructs a new Error-variant Level
pub extern "C" fn Level_error() -> Level {
	Level::Error}
/// Checks if two Levels contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Level_eq(a: &Level, b: &Level) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Get a string which allows debug introspection of a Level object
pub extern "C" fn Level_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::logger::Level }).into()}
/// Generates a non-cryptographic 64-bit hash of the Level.
#[no_mangle]
pub extern "C" fn Level_hash(o: &Level) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Get the string representation of a Level object
pub extern "C" fn Level_to_str(o: &crate::lightning::util::logger::Level) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
/// Returns the most verbose logging level.
#[must_use]
#[no_mangle]
pub extern "C" fn Level_max() -> crate::lightning::util::logger::Level {
	let mut ret = lightning::util::logger::Level::max();
	crate::lightning::util::logger::Level::native_into(ret)
}


use lightning::util::logger::Record as nativeRecordImport;
pub(crate) type nativeRecord = nativeRecordImport;

/// A Record, unit of logging output with Metadata to enable filtering
/// Module_path, file, line to inform on log's source
#[must_use]
#[repr(C)]
pub struct Record {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRecord,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl core::ops::Deref for Record {
	type Target = nativeRecord;
	fn deref(&self) -> &Self::Target { unsafe { &*ObjOps::untweak_ptr(self.inner) } }
}
unsafe impl core::marker::Send for Record { }
unsafe impl core::marker::Sync for Record { }
impl Drop for Record {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRecord>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Record, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Record_free(this_obj: Record) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Record_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRecord) };
}
#[allow(unused)]
impl Record {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRecord {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRecord {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRecord {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
	pub(crate) fn as_ref_to(&self) -> Self {
		Self { inner: self.inner, is_owned: false }
	}
}
/// The verbosity level of the message.
#[no_mangle]
pub extern "C" fn Record_get_level(this_ptr: &Record) -> crate::lightning::util::logger::Level {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().level;
	crate::lightning::util::logger::Level::from_native(inner_val)
}
/// The verbosity level of the message.
#[no_mangle]
pub extern "C" fn Record_set_level(this_ptr: &mut Record, mut val: crate::lightning::util::logger::Level) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.level = val.into_native();
}
/// The node id of the peer pertaining to the logged record.
///
/// Note that in some cases a [`Self::channel_id`] may be filled in but this may still be
/// `None`, depending on if the peer information is readily available in LDK when the log is
/// generated.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Record_get_peer_id(this_ptr: &Record) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().peer_id;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(inner_val.unwrap())) } };
	local_inner_val
}
/// The node id of the peer pertaining to the logged record.
///
/// Note that in some cases a [`Self::channel_id`] may be filled in but this may still be
/// `None`, depending on if the peer information is readily available in LDK when the log is
/// generated.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Record_set_peer_id(this_ptr: &mut Record, mut val: crate::c_types::PublicKey) {
	let mut local_val = if val.is_null() { None } else { Some( { val.into_rust() }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.peer_id = local_val;
}
/// The channel id of the channel pertaining to the logged record. May be a temporary id before
/// the channel has been funded.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Record_get_channel_id(this_ptr: &Record) -> crate::lightning::ln::types::ChannelId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_id;
	let mut local_inner_val = crate::lightning::ln::types::ChannelId { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::types::ChannelId<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The channel id of the channel pertaining to the logged record. May be a temporary id before
/// the channel has been funded.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Record_set_channel_id(this_ptr: &mut Record, mut val: crate::lightning::ln::types::ChannelId) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_id = local_val;
}
/// The message body.
#[no_mangle]
pub extern "C" fn Record_get_args(this_ptr: &Record) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().args;
	inner_val.as_str().into()
}
/// The message body.
#[no_mangle]
pub extern "C" fn Record_set_args(this_ptr: &mut Record, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.args = val.into_string();
}
/// The module path of the message.
#[no_mangle]
pub extern "C" fn Record_get_module_path(this_ptr: &Record) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().module_path;
	inner_val.into()
}
/// The module path of the message.
#[no_mangle]
pub extern "C" fn Record_set_module_path(this_ptr: &mut Record, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.module_path = val.into_str();
}
/// The source file containing the message.
#[no_mangle]
pub extern "C" fn Record_get_file(this_ptr: &Record) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().file;
	inner_val.into()
}
/// The source file containing the message.
#[no_mangle]
pub extern "C" fn Record_set_file(this_ptr: &mut Record, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.file = val.into_str();
}
/// The line containing the message.
#[no_mangle]
pub extern "C" fn Record_get_line(this_ptr: &Record) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().line;
	*inner_val
}
/// The line containing the message.
#[no_mangle]
pub extern "C" fn Record_set_line(this_ptr: &mut Record, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.line = val;
}
/// The payment hash.
///
/// Note that this is only filled in for logs pertaining to a specific payment, and will be
/// `None` for logs which are not directly related to a payment.
#[no_mangle]
pub extern "C" fn Record_get_payment_hash(this_ptr: &Record) -> crate::c_types::derived::COption_ThirtyTwoBytesZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_hash;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::ThirtyTwoBytes { data: (*inner_val.as_ref().unwrap()).clone().0 } }) };
	local_inner_val
}
/// The payment hash.
///
/// Note that this is only filled in for logs pertaining to a specific payment, and will be
/// `None` for logs which are not directly related to a payment.
#[no_mangle]
pub extern "C" fn Record_set_payment_hash(this_ptr: &mut Record, mut val: crate::c_types::derived::COption_ThirtyTwoBytesZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { ::lightning::types::payment::PaymentHash({ val_opt.take() }.data) }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_hash = local_val;
}
/// Constructs a new Record given each field
///
/// Note that peer_id_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
/// Note that channel_id_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Record_new(mut level_arg: crate::lightning::util::logger::Level, mut peer_id_arg: crate::c_types::PublicKey, mut channel_id_arg: crate::lightning::ln::types::ChannelId, mut args_arg: crate::c_types::Str, mut module_path_arg: crate::c_types::Str, mut file_arg: crate::c_types::Str, mut line_arg: u32, mut payment_hash_arg: crate::c_types::derived::COption_ThirtyTwoBytesZ) -> Record {
	let mut local_peer_id_arg = if peer_id_arg.is_null() { None } else { Some( { peer_id_arg.into_rust() }) };
	let mut local_channel_id_arg = if channel_id_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_id_arg.take_inner()) } }) };
	let mut local_payment_hash_arg = { /*payment_hash_arg*/ let payment_hash_arg_opt = payment_hash_arg; if payment_hash_arg_opt.is_none() { None } else { Some({ { ::lightning::types::payment::PaymentHash({ payment_hash_arg_opt.take() }.data) }})} };
	Record { inner: ObjOps::heap_alloc(nativeRecord {
		level: level_arg.into_native(),
		peer_id: local_peer_id_arg,
		channel_id: local_channel_id_arg,
		args: args_arg.into_string(),
		module_path: module_path_arg.into_str(),
		file: file_arg.into_str(),
		line: line_arg,
		payment_hash: local_payment_hash_arg,
	}), is_owned: true }
}
impl Clone for Record {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRecord>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Record_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRecord)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Record
pub extern "C" fn Record_clone(orig: &Record) -> Record {
	orig.clone()
}
/// Get a string which allows debug introspection of a Record object
pub extern "C" fn Record_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::util::logger::Record }).into()}
/// A trait encapsulating the operations required of a logger.
#[repr(C)]
pub struct Logger {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Logs the [`Record`].
	pub log: extern "C" fn (this_arg: *const c_void, record: crate::lightning::util::logger::Record),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}
#[allow(unused)]
pub(crate) fn Logger_clone_fields(orig: &Logger) -> Logger {
	Logger {
		this_arg: orig.this_arg,
		log: Clone::clone(&orig.log),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::logger::Logger as rustLogger;
impl rustLogger for Logger {
	fn log(&self, mut record: lightning::util::logger::Record) {
		(self.log)(self.this_arg, crate::lightning::util::logger::Record { inner: ObjOps::heap_alloc(record), is_owned: true })
	}
}

pub struct LoggerRef(Logger);
impl rustLogger for LoggerRef {
	fn log(&self, mut record: lightning::util::logger::Record) {
		(self.0.log)(self.0.this_arg, crate::lightning::util::logger::Record { inner: ObjOps::heap_alloc(record), is_owned: true })
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Logger {
	type Target = LoggerRef;
	fn deref(&self) -> &Self::Target {
		unsafe { &*(self as *const _ as *const LoggerRef) }
	}
}
impl core::ops::DerefMut for Logger {
	fn deref_mut(&mut self) -> &mut LoggerRef {
		unsafe { &mut *(self as *mut _ as *mut LoggerRef) }
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Logger_free(this_ptr: Logger) { }
impl Drop for Logger {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
