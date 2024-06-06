//! This module contains standard C-mapped types for types not in the original crate.

/// Auto-generated C-mapped types for templated containers
pub mod derived;

use bitcoin::Transaction as BitcoinTransaction;
use bitcoin::Witness as BitcoinWitness;
use bitcoin::address;
use bitcoin::address::WitnessProgram as BitcoinWitnessProgram;
use bitcoin::key::TweakedPublicKey as BitcoinTweakedPublicKey;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::secp256k1::SecretKey as SecpSecretKey;
use bitcoin::secp256k1::ecdsa::Signature as ECDSASecpSignature;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSecpSignature;
use bitcoin::secp256k1::Error as SecpError;
use bitcoin::secp256k1::ecdsa::RecoveryId;
use bitcoin::secp256k1::ecdsa::RecoverableSignature as SecpRecoverableSignature;
use bitcoin::secp256k1::Scalar as SecpScalar;
use bitcoin::bech32;

use core::convert::TryInto; // Bindings need at least rustc 1.34
use alloc::borrow::ToOwned;
use core::ffi::c_void;

#[cfg(not(feature = "no-std"))]
pub(crate) use std::io::{self, Cursor, Read};
#[cfg(feature = "no-std")]
pub(crate) use core2::io::{self, Cursor, Read};
use alloc::{boxed::Box, vec::Vec, string::String};

use core::convert::TryFrom;

#[repr(C)]
/// A dummy struct of which an instance must never exist.
/// This corresponds to the Rust type `Infallible`, or, in unstable rust, `!`
pub struct NotConstructable {
	_priv_thing: core::convert::Infallible,
}
impl From<core::convert::Infallible> for NotConstructable {
	fn from(_: core::convert::Infallible) -> Self { unreachable!(); }
}

/// Integer in the range `0..32`
#[derive(PartialEq, Eq, Copy, Clone)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct U5(u8);

impl From<bech32::u5> for U5 {
	fn from(o: bech32::u5) -> Self { Self(o.to_u8()) }
}
impl Into<bech32::u5> for U5 {
	fn into(self) -> bech32::u5 { bech32::u5::try_from_u8(self.0).expect("u5 objects must be in the range 0..32") }
}

/// Unsigned, 128-bit integer.
///
/// Because LLVM implements an incorrect ABI for 128-bit integers, a wrapper type is defined here.
/// See https://github.com/rust-lang/rust/issues/54341 for more details.
#[derive(PartialEq, Eq, Copy, Clone)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct U128 {
	/// The 128-bit integer, as 16 little-endian bytes
	pub le_bytes: [u8; 16],
}

#[no_mangle]
/// Gets the 128-bit integer, as 16 little-endian bytes
pub extern "C" fn U128_le_bytes(val: U128) -> SixteenBytes { SixteenBytes { data: val.le_bytes } }
#[no_mangle]
/// Constructs a new U128 from 16 little-endian bytes
pub extern "C" fn U128_new(le_bytes: SixteenBytes) -> U128 { U128 { le_bytes: le_bytes.data } }

impl From<u128> for U128 {
	fn from(o: u128) -> Self { Self { le_bytes: o.to_le_bytes() } }
}
impl From<&mut u128> for U128 {
	fn from(o: &mut u128) -> U128 { Self::from(*o) }
}
impl Into<u128> for U128 {
	fn into(self) -> u128 { u128::from_le_bytes(self.le_bytes) }
}

/// Integer in the range `0..=16`
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(C)]
pub struct WitnessVersion(u8);

impl From<address::WitnessVersion> for WitnessVersion {
	fn from(o: address::WitnessVersion) -> Self { Self(o.to_num()) }
}
impl Into<address::WitnessVersion> for WitnessVersion {
	fn into(self) -> address::WitnessVersion {
		address::WitnessVersion::try_from(self.0).expect("WitnessVersion objects must be in the range 0..=16")
	}
}

/// A segregated witness version byte and script bytes
#[repr(C)]
#[derive(Clone)]
pub struct WitnessProgram {
	version: WitnessVersion,
	program: derived::CVec_u8Z,
}
impl WitnessProgram {
	pub(crate) fn from_bitcoin(o: BitcoinWitnessProgram) -> Self {
		Self {
			version: o.version().into(),
			program: o.program().as_bytes().to_vec().into(),
		}
	}
	pub(crate) fn into_bitcoin(mut self) -> BitcoinWitnessProgram {
		BitcoinWitnessProgram::new(
			self.version.into(),
			self.program.into_rust(),
		).expect("Program length was previously checked")
	}
}

#[no_mangle]
/// Constructs a new WitnessProgram given a version and program bytes.
///
/// The program MUST be at least 2 bytes and no longer than 40 bytes long.
/// Further, if the version is 0, the program MUST be either exactly 20 or exactly 32 bytes long.
pub extern "C" fn WitnessProgram_new(version: WitnessVersion, program: derived::CVec_u8Z) -> WitnessProgram {
	assert!(program.datalen >= 2, "WitnessProgram program lengths must be at least 2 bytes long");
	assert!(program.datalen <= 40, "WitnessProgram program lengths must be no longer than 40 bytes");
	if version.0 == 0 {
		assert!(program.datalen == 20 || program.datalen == 32, "WitnessProgram program length must be 20 or 32 for version-0 programs");
	}
	WitnessProgram { version, program }
}
#[no_mangle]
/// Gets the `WitnessVersion` of the given `WitnessProgram`
pub extern "C" fn WitnessProgram_get_version(prog: &WitnessProgram) -> WitnessVersion {
	prog.version
}
#[no_mangle]
/// Gets the witness program bytes of the given `WitnessProgram`
pub extern "C" fn WitnessProgram_get_program(prog: &WitnessProgram) -> u8slice {
	u8slice::from_vec(&prog.program)
}
#[no_mangle]
/// Creates a new WitnessProgram which has the same data as `orig`
pub extern "C" fn WitnessProgram_clone(orig: &WitnessProgram) -> WitnessProgram { orig.clone() }
#[no_mangle]
/// Releases any memory held by the given `WitnessProgram` (which is currently none)
pub extern "C" fn WitnessProgram_free(o: WitnessProgram) { }

#[derive(Clone)]
#[repr(C)]
/// Represents a valid secp256k1 public key serialized in "compressed form" as a 33 byte array.
pub struct PublicKey {
	/// The bytes of the public key
	pub compressed_form: [u8; 33],
}
impl PublicKey {
	pub(crate) fn from_rust(pk: &SecpPublicKey) -> Self {
		Self {
			compressed_form: pk.serialize(),
		}
	}
	pub(crate) fn into_rust(&self) -> SecpPublicKey {
		SecpPublicKey::from_slice(&self.compressed_form).unwrap()
	}
	pub(crate) fn is_null(&self) -> bool { self.compressed_form[..] == [0; 33][..] }
	pub(crate) fn null() -> Self { Self { compressed_form: [0; 33] } }
}

#[derive(Clone)]
#[repr(C)]
/// Represents a tweaked X-only public key as required for BIP 340 (Taproot).
pub struct TweakedPublicKey {
	/// The bytes of the public key X coordinate
	pub x_coordinate: [u8; 32],
}
impl TweakedPublicKey {
	pub(crate) fn from_rust(pk: &BitcoinTweakedPublicKey) -> Self {
		Self {
			x_coordinate: pk.serialize(),
		}
	}
	pub(crate) fn into_rust(&self) -> BitcoinTweakedPublicKey {
		let xonly_key = XOnlyPublicKey::from_slice(&self.x_coordinate).unwrap();
		BitcoinTweakedPublicKey::dangerous_assume_tweaked(xonly_key)
	}
}

#[repr(C)]
#[derive(Clone)]
/// Represents a valid secp256k1 secret key serialized as a 32 byte array.
pub struct SecretKey {
	/// The bytes of the secret key
	pub bytes: [u8; 32],
}
impl SecretKey {
	// from_rust isn't implemented for a ref since we just return byte array refs directly
	pub(crate) fn from_rust(sk: SecpSecretKey) -> Self {
		let mut bytes = [0; 32];
		bytes.copy_from_slice(&sk[..]);
		Self { bytes }
	}
	pub(crate) fn into_rust(&self) -> SecpSecretKey {
		SecpSecretKey::from_slice(&self.bytes).unwrap()
	}
}

#[repr(C)]
#[derive(Clone)]
/// Represents a secp256k1 ECDSA signature serialized as two 32-byte numbers
pub struct ECDSASignature {
	/// The bytes of the signature in "compact" form
	pub compact_form: [u8; 64],
}
impl ECDSASignature {
	pub(crate) fn from_rust(pk: &ECDSASecpSignature) -> Self {
		Self {
			compact_form: pk.serialize_compact(),
		}
	}
	pub(crate) fn into_rust(&self) -> ECDSASecpSignature {
		ECDSASecpSignature::from_compact(&self.compact_form).unwrap()
	}
}

#[repr(C)]
#[derive(Clone)]
/// Represents a secp256k1 Schnorr signature serialized as two 32-byte numbers
pub struct SchnorrSignature {
	/// The bytes of the signature as two 32-byte numbers
	pub compact_form: [u8; 64],
}
impl SchnorrSignature {
	pub(crate) fn from_rust(pk: &SchnorrSecpSignature) -> Self {
		Self {
			compact_form: pk.as_ref().clone(),
		}
	}
	pub(crate) fn into_rust(&self) -> SchnorrSecpSignature {
		SchnorrSecpSignature::from_slice(&self.compact_form).unwrap()
	}
}

#[repr(C)]
#[derive(Clone)]
/// Represents a secp256k1 signature serialized as two 32-byte numbers as well as a tag which
/// allows recovering the exact public key which created the signature given the message.
pub struct RecoverableSignature {
	/// The bytes of the signature in "compact" form plus a "Recovery ID" which allows for
	/// recovery.
	pub serialized_form: [u8; 68],
}
impl RecoverableSignature {
	pub(crate) fn from_rust(pk: &SecpRecoverableSignature) -> Self {
		let (id, compact_form) = pk.serialize_compact();
		let mut serialized_form = [0; 68];
		serialized_form[0..64].copy_from_slice(&compact_form[..]);
		serialized_form[64..].copy_from_slice(&id.to_i32().to_le_bytes());
		Self { serialized_form }
	}
	pub(crate) fn into_rust(&self) -> SecpRecoverableSignature {
		let mut id = [0; 4];
		id.copy_from_slice(&self.serialized_form[64..]);
		SecpRecoverableSignature::from_compact(&self.serialized_form[0..64],
				RecoveryId::from_i32(i32::from_le_bytes(id)).expect("Invalid Recovery ID"))
			.unwrap()
	}
}

#[repr(C)]
#[derive(Clone)]
/// Represents a scalar value between zero and the secp256k1 curve order, in big endian.
pub struct BigEndianScalar {
	/// The bytes of the scalar value.
	pub big_endian_bytes: [u8; 32],
}
impl BigEndianScalar {
	pub(crate) fn from_rust(scalar: &SecpScalar) -> Self {
		Self { big_endian_bytes: scalar.to_be_bytes() }
	}
	pub(crate) fn into_rust(&self) -> SecpScalar {
		SecpScalar::from_be_bytes(self.big_endian_bytes).expect("Scalar greater than the curve order")
	}
}

#[no_mangle]
/// Convenience function for constructing a new BigEndianScalar
pub extern "C" fn BigEndianScalar_new(big_endian_bytes: ThirtyTwoBytes) -> BigEndianScalar {
	BigEndianScalar { big_endian_bytes: big_endian_bytes.data }
}
#[no_mangle]
/// Creates a new BigEndianScalar which has the same data as `orig`
pub extern "C" fn BigEndianScalar_clone(orig: &BigEndianScalar) -> BigEndianScalar { orig.clone() }

#[repr(C)]
#[derive(Copy, Clone)]
/// Represents an error returned from libsecp256k1 during validation of some secp256k1 data
pub enum Secp256k1Error {
	/// Signature failed verification
	IncorrectSignature,
	/// Badly sized message ("messages" are actually fixed-sized digests; see the MESSAGE_SIZE constant)
	InvalidMessage,
	/// Bad public key
	InvalidPublicKey,
	/// Bad signature
	InvalidSignature,
	/// Bad secret key
	InvalidSecretKey,
	/// Bad shared secret.
	InvalidSharedSecret,
	/// Bad recovery id
	InvalidRecoveryId,
	/// Invalid tweak for add_assign or mul_assign
	InvalidTweak,
	/// Didn't pass enough memory to context creation with preallocated memory
	NotEnoughMemory,
	/// Bad set of public keys.
	InvalidPublicKeySum,
	/// The only valid parity values are 0 or 1.
	InvalidParityValue,
}
impl Secp256k1Error {
	pub(crate) fn from_rust(err: SecpError) -> Self {
		match err {
			SecpError::IncorrectSignature => Secp256k1Error::IncorrectSignature,
			SecpError::InvalidMessage => Secp256k1Error::InvalidMessage,
			SecpError::InvalidPublicKey => Secp256k1Error::InvalidPublicKey,
			SecpError::InvalidSignature => Secp256k1Error::InvalidSignature,
			SecpError::InvalidSecretKey => Secp256k1Error::InvalidSecretKey,
			SecpError::InvalidSharedSecret => Secp256k1Error::InvalidSharedSecret,
			SecpError::InvalidRecoveryId => Secp256k1Error::InvalidRecoveryId,
			SecpError::InvalidTweak => Secp256k1Error::InvalidTweak,
			SecpError::NotEnoughMemory => Secp256k1Error::NotEnoughMemory,
			SecpError::InvalidPublicKeySum => Secp256k1Error::InvalidPublicKeySum,
			SecpError::InvalidParityValue(_) => Secp256k1Error::InvalidParityValue,
		}
	}
	pub(crate) fn into_rust(self) -> SecpError {
		let invalid_parity = secp256k1::Parity::from_i32(42).unwrap_err();
		match self {
			Secp256k1Error::IncorrectSignature => SecpError::IncorrectSignature,
			Secp256k1Error::InvalidMessage => SecpError::InvalidMessage,
			Secp256k1Error::InvalidPublicKey => SecpError::InvalidPublicKey,
			Secp256k1Error::InvalidSignature => SecpError::InvalidSignature,
			Secp256k1Error::InvalidSecretKey => SecpError::InvalidSecretKey,
			Secp256k1Error::InvalidSharedSecret => SecpError::InvalidSharedSecret,
			Secp256k1Error::InvalidRecoveryId => SecpError::InvalidRecoveryId,
			Secp256k1Error::InvalidTweak => SecpError::InvalidTweak,
			Secp256k1Error::NotEnoughMemory => SecpError::NotEnoughMemory,
			Secp256k1Error::InvalidPublicKeySum => SecpError::InvalidPublicKeySum,
			Secp256k1Error::InvalidParityValue => SecpError::InvalidParityValue(invalid_parity),
		}
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Represents an error returned from the bech32 library during validation of some bech32 data
pub enum Bech32Error {
	/// String does not contain the separator character
	MissingSeparator,
	/// The checksum does not match the rest of the data
	InvalidChecksum,
	/// The data or human-readable part is too long or too short
	InvalidLength,
	/// Some part of the string contains an invalid character
	InvalidChar(u32),
	/// Some part of the data has an invalid value
	InvalidData(u8),
	/// The bit conversion failed due to a padding issue
	InvalidPadding,
	/// The whole string must be of one case
	MixedCase,
}
impl Bech32Error {
	pub(crate) fn from_rust(err: bech32::Error) -> Self {
		match err {
			bech32::Error::MissingSeparator => Self::MissingSeparator,
			bech32::Error::InvalidChecksum => Self::InvalidChecksum,
			bech32::Error::InvalidLength => Self::InvalidLength,
			bech32::Error::InvalidChar(c) => Self::InvalidChar(c as u32),
			bech32::Error::InvalidData(d) => Self::InvalidData(d),
			bech32::Error::InvalidPadding => Self::InvalidPadding,
			bech32::Error::MixedCase => Self::MixedCase,
		}
	}
	pub(crate) fn into_rust(self) -> bech32::Error {
		match self {
			Self::MissingSeparator => bech32::Error::MissingSeparator,
			Self::InvalidChecksum => bech32::Error::InvalidChecksum,
			Self::InvalidLength => bech32::Error::InvalidLength,
			Self::InvalidChar(c) => bech32::Error::InvalidChar(core::char::from_u32(c).expect("Invalid UTF-8 character in Bech32Error::InvalidChar")),
			Self::InvalidData(d) => bech32::Error::InvalidData(d),
			Self::InvalidPadding => bech32::Error::InvalidPadding,
			Self::MixedCase => bech32::Error::MixedCase,
		}
	}
}
#[no_mangle]
/// Creates a new Bech32Error which has the same data as `orig`
pub extern "C" fn Bech32Error_clone(orig: &Bech32Error) -> Bech32Error { orig.clone() }
#[no_mangle]
/// Releases any memory held by the given `Bech32Error` (which is currently none)
pub extern "C" fn Bech32Error_free(o: Bech32Error) { }

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
/// Sub-errors which don't have specific information in them use this type.
pub struct Error {
	/// Zero-Sized_types aren't consistent across Rust/C/C++, so we add some size here
	pub _dummy: u8,
}

#[repr(C)]
#[allow(missing_docs)] // If there's no docs upstream, that's good enough for us
#[derive(Clone, Copy, PartialEq)]
/// Represents an IO Error. Note that some information is lost in the conversion from Rust.
pub enum IOError {
	NotFound,
	PermissionDenied,
	ConnectionRefused,
	ConnectionReset,
	ConnectionAborted,
	NotConnected,
	AddrInUse,
	AddrNotAvailable,
	BrokenPipe,
	AlreadyExists,
	WouldBlock,
	InvalidInput,
	InvalidData,
	TimedOut,
	WriteZero,
	Interrupted,
	Other,
	UnexpectedEof,
}
impl IOError {
	pub(crate) fn from_rust_kind(err: io::ErrorKind) -> Self {
		match err {
			io::ErrorKind::NotFound => IOError::NotFound,
			io::ErrorKind::PermissionDenied => IOError::PermissionDenied,
			io::ErrorKind::ConnectionRefused => IOError::ConnectionRefused,
			io::ErrorKind::ConnectionReset => IOError::ConnectionReset,
			io::ErrorKind::ConnectionAborted => IOError::ConnectionAborted,
			io::ErrorKind::NotConnected => IOError::NotConnected,
			io::ErrorKind::AddrInUse => IOError::AddrInUse,
			io::ErrorKind::AddrNotAvailable => IOError::AddrNotAvailable,
			io::ErrorKind::BrokenPipe => IOError::BrokenPipe,
			io::ErrorKind::AlreadyExists => IOError::AlreadyExists,
			io::ErrorKind::WouldBlock => IOError::WouldBlock,
			io::ErrorKind::InvalidInput => IOError::InvalidInput,
			io::ErrorKind::InvalidData => IOError::InvalidData,
			io::ErrorKind::TimedOut => IOError::TimedOut,
			io::ErrorKind::WriteZero => IOError::WriteZero,
			io::ErrorKind::Interrupted => IOError::Interrupted,
			io::ErrorKind::Other => IOError::Other,
			io::ErrorKind::UnexpectedEof => IOError::UnexpectedEof,
			_ => IOError::Other,
		}
	}
	pub(crate) fn from_rust(err: io::Error) -> Self {
		Self::from_rust_kind(err.kind())
	}
	pub(crate) fn to_rust_kind(&self) -> io::ErrorKind {
		match self {
			IOError::NotFound => io::ErrorKind::NotFound,
			IOError::PermissionDenied => io::ErrorKind::PermissionDenied,
			IOError::ConnectionRefused => io::ErrorKind::ConnectionRefused,
			IOError::ConnectionReset => io::ErrorKind::ConnectionReset,
			IOError::ConnectionAborted => io::ErrorKind::ConnectionAborted,
			IOError::NotConnected => io::ErrorKind::NotConnected,
			IOError::AddrInUse => io::ErrorKind::AddrInUse,
			IOError::AddrNotAvailable => io::ErrorKind::AddrNotAvailable,
			IOError::BrokenPipe => io::ErrorKind::BrokenPipe,
			IOError::AlreadyExists => io::ErrorKind::AlreadyExists,
			IOError::WouldBlock => io::ErrorKind::WouldBlock,
			IOError::InvalidInput => io::ErrorKind::InvalidInput,
			IOError::InvalidData => io::ErrorKind::InvalidData,
			IOError::TimedOut => io::ErrorKind::TimedOut,
			IOError::WriteZero => io::ErrorKind::WriteZero,
			IOError::Interrupted => io::ErrorKind::Interrupted,
			IOError::Other => io::ErrorKind::Other,
			IOError::UnexpectedEof => io::ErrorKind::UnexpectedEof,
		}
	}
	pub(crate) fn to_rust(&self) -> io::Error {
		io::Error::new(self.to_rust_kind(), "")
	}
}

#[repr(C)]
/// A serialized transaction, in (pointer, length) form.
///
/// This type optionally owns its own memory, and thus the semantics around access change based on
/// the `data_is_owned` flag. If `data_is_owned` is set, you must call `Transaction_free` to free
/// the underlying buffer before the object goes out of scope. If `data_is_owned` is not set, any
/// access to the buffer after the scope in which the object was provided to you is invalid. eg,
/// access after you return from the call in which a `!data_is_owned` `Transaction` is provided to
/// you would be invalid.
///
/// Note that, while it may change in the future, because transactions on the Rust side are stored
/// in a deserialized form, all `Transaction`s generated on the Rust side will have `data_is_owned`
/// set. Similarly, while it may change in the future, all `Transaction`s you pass to Rust may have
/// `data_is_owned` either set or unset at your discretion.
pub struct Transaction {
	/// The serialized transaction data.
	///
	/// This is non-const for your convenience, an object passed to Rust is never written to.
	pub data: *mut u8,
	/// The length of the serialized transaction
	pub datalen: usize,
	/// Whether the data pointed to by `data` should be freed or not.
	pub data_is_owned: bool,
}
impl Transaction {
	fn from_vec(vec: Vec<u8>) -> Self {
		let datalen = vec.len();
		let data = Box::into_raw(vec.into_boxed_slice());
		Self {
			data: unsafe { (*data).as_mut_ptr() },
			datalen,
			data_is_owned: true,
		}
	}
	pub(crate) fn into_bitcoin(&self) -> BitcoinTransaction {
		if self.datalen == 0 { panic!("0-length buffer can never represent a valid Transaction"); }
		::bitcoin::consensus::encode::deserialize(unsafe { core::slice::from_raw_parts(self.data, self.datalen) }).unwrap()
	}
	pub(crate) fn from_bitcoin(btc: &BitcoinTransaction) -> Self {
		let vec = ::bitcoin::consensus::encode::serialize(btc);
		Self::from_vec(vec)
	}
}
impl Drop for Transaction {
	fn drop(&mut self) {
		if self.data_is_owned && self.datalen != 0 {
			let _ = derived::CVec_u8Z { data: self.data as *mut u8, datalen: self.datalen };
		}
	}
}
impl Clone for Transaction {
	fn clone(&self) -> Self {
		let sl = unsafe { core::slice::from_raw_parts(self.data, self.datalen) };
		let mut v = Vec::new();
		v.extend_from_slice(&sl);
		Self::from_vec(v)
	}
}
#[no_mangle]
/// Frees the data buffer, if data_is_owned is set and datalen > 0.
pub extern "C" fn Transaction_free(_res: Transaction) { }

#[repr(C)]
/// A serialized witness.
pub struct Witness {
	/// The serialized transaction data.
	///
	/// This is non-const for your convenience, an object passed to Rust is never written to.
	pub data: *mut u8,
	/// The length of the serialized transaction
	pub datalen: usize,
	/// Whether the data pointed to by `data` should be freed or not.
	pub data_is_owned: bool,
}
impl Witness {
	fn from_vec(vec: Vec<u8>) -> Self {
		let datalen = vec.len();
		let data = Box::into_raw(vec.into_boxed_slice());
		Self {
			data: unsafe { (*data).as_mut_ptr() },
			datalen,
			data_is_owned: true,
		}
	}
	pub(crate) fn into_bitcoin(&self) -> BitcoinWitness {
		::bitcoin::consensus::encode::deserialize(unsafe { core::slice::from_raw_parts(self.data, self.datalen) }).unwrap()
	}
	pub(crate) fn from_bitcoin(btc: &BitcoinWitness) -> Self {
		let vec = ::bitcoin::consensus::encode::serialize(btc);
		Self::from_vec(vec)
	}
}

impl Drop for Witness {
	fn drop(&mut self) {
		if self.data_is_owned && self.datalen != 0 {
			let _ = derived::CVec_u8Z { data: self.data as *mut u8, datalen: self.datalen };
		}
	}
}
impl Clone for Witness {
	fn clone(&self) -> Self {
		let sl = unsafe { core::slice::from_raw_parts(self.data, self.datalen) };
		let mut v = Vec::new();
		v.extend_from_slice(&sl);
		Self::from_vec(v)
	}
}

#[no_mangle]
/// Creates a new Witness which has the same data as `orig` but with a new buffer.
pub extern "C" fn Witness_clone(orig: &Witness) -> Witness { orig.clone() }

#[no_mangle]
/// Frees the data pointed to by data
pub extern "C" fn Witness_free(_res: Witness) { }

pub(crate) fn bitcoin_to_C_outpoint(outpoint: &::bitcoin::blockdata::transaction::OutPoint) -> crate::lightning::chain::transaction::OutPoint {
	crate::lightning::chain::transaction::OutPoint_new(ThirtyTwoBytes { data: *outpoint.txid.as_ref() }, outpoint.vout.try_into().unwrap())
}
pub(crate) fn C_to_bitcoin_outpoint(outpoint: crate::lightning::chain::transaction::OutPoint) -> ::bitcoin::blockdata::transaction::OutPoint {
	unsafe {
		::bitcoin::blockdata::transaction::OutPoint {
			txid: (*outpoint.inner).txid, vout: (*outpoint.inner).index as u32
		}
	}
}

#[repr(C)]
#[derive(Clone)]
/// An input to a transaction.
///
/// This contains the witness, the scriptSig and the previous outpoint and represents a single
/// input to a transaction
pub struct TxIn {
	/// The witness which includes any signatures required to spend a segwit output.
	pub witness: Witness,
	/// The script_sig which includes signatures requires to spend a pre-segwit output (or a
	/// P2SH-wrapped segwit output).
	pub script_sig: derived::CVec_u8Z,
	/// The sequence number of the transaction input
	pub sequence: u32,
	/// The txid of the transaction being spent.
	pub previous_txid: ThirtyTwoBytes,
	/// The output index of the transaction being spent.
	pub previous_vout: u32,
}

impl TxIn {
	pub(crate) fn from_rust(txin: &::bitcoin::blockdata::transaction::TxIn) -> Self {
		TxIn {
			witness: Witness::from_bitcoin(&txin.witness),
			script_sig: derived::CVec_u8Z::from(txin.script_sig.clone().into_bytes()),
			sequence: txin.sequence.0,
			previous_txid: ThirtyTwoBytes { data: *txin.previous_output.txid.as_ref() },
			previous_vout: txin.previous_output.vout,
		}
	}
}
#[no_mangle]
/// Convenience function for constructing a new TxIn
pub extern "C" fn TxIn_new(witness: Witness, script_sig: derived::CVec_u8Z, sequence: u32, previous_txid: ThirtyTwoBytes, previous_vout: u32) -> TxIn {
	TxIn { witness, script_sig, sequence, previous_txid, previous_vout }
}
#[no_mangle]
/// Gets the `witness` in the given `TxIn`.
pub extern "C" fn TxIn_get_witness(txin: &TxIn) -> Witness {
	txin.witness.clone()
}
#[no_mangle]
/// Gets the `script_sig` in the given `TxIn`.
pub extern "C" fn TxIn_get_script_sig(txin: &TxIn) -> u8slice {
	u8slice::from_vec(&txin.script_sig)
}
#[no_mangle]
/// Gets the `sequence` in the given `TxIn`.
pub extern "C" fn TxIn_get_sequence(txin: &TxIn) -> u32 {
	txin.sequence
}
#[no_mangle]
/// Gets the previous outpoint txid in the given `TxIn`.
pub extern "C" fn TxIn_get_previous_txid(txin: &TxIn) -> ThirtyTwoBytes {
	txin.previous_txid
}
#[no_mangle]
/// Gets the previout outpoint index in the given `TxIn`.
pub extern "C" fn TxIn_get_previous_vout(txin: &TxIn) -> u32 {
	txin.previous_vout
}
#[no_mangle]
/// Frees the witness and script_sig in a TxIn
pub extern "C" fn TxIn_free(_res: TxIn) { }

#[repr(C)]
#[derive(Clone)]
/// A transaction output including a scriptPubKey and value.
/// This type *does* own its own memory, so must be free'd appropriately.
pub struct TxOut {
	/// The script_pubkey in this output
	pub script_pubkey: derived::CVec_u8Z,
	/// The value, in satoshis, of this output
	pub value: u64,
}

impl TxOut {
	pub(crate) fn into_rust(mut self) -> ::bitcoin::blockdata::transaction::TxOut {
		::bitcoin::blockdata::transaction::TxOut {
			script_pubkey: self.script_pubkey.into_rust().into(),
			value: self.value,
		}
	}
	pub(crate) fn from_rust(txout: &::bitcoin::blockdata::transaction::TxOut) -> Self {
		Self {
			script_pubkey: derived::CVec_u8Z::from(txout.script_pubkey.clone().into_bytes()),
			value: txout.value
		}
	}
}

#[no_mangle]
/// Convenience function for constructing a new TxOut
pub extern "C" fn TxOut_new(script_pubkey: derived::CVec_u8Z, value: u64) -> TxOut {
	TxOut { script_pubkey, value }
}
#[no_mangle]
/// Gets the `script_pubkey` in the given `TxOut`.
pub extern "C" fn TxOut_get_script_pubkey(txout: &TxOut) -> u8slice {
	u8slice::from_vec(&txout.script_pubkey)
}
#[no_mangle]
/// Gets the value in the given `TxOut`.
pub extern "C" fn TxOut_get_value(txout: &TxOut) -> u64 {
	txout.value
}
#[no_mangle]
/// Frees the data pointed to by script_pubkey.
pub extern "C" fn TxOut_free(_res: TxOut) { }
#[no_mangle]
/// Creates a new TxOut which has the same data as `orig` but with a new script buffer.
pub extern "C" fn TxOut_clone(orig: &TxOut) -> TxOut { orig.clone() }

#[repr(C)]
/// A "slice" referencing some byte array. This is simply a length-tagged pointer which does not
/// own the memory pointed to by data.
pub struct u8slice {
	/// A pointer to the byte buffer
	pub data: *const u8,
	/// The number of bytes pointed to by `data`.
	pub datalen: usize
}
impl u8slice {
	pub(crate) fn from_slice(s: &[u8]) -> Self {
		Self {
			data: s.as_ptr(),
			datalen: s.len(),
		}
	}
	pub(crate) fn to_slice(&self) -> &[u8] {
		if self.datalen == 0 { return &[]; }
		unsafe { core::slice::from_raw_parts(self.data, self.datalen) }
	}
	pub(crate) fn to_reader<'a>(&'a self) -> Cursor<&'a [u8]> {
		let sl = self.to_slice();
		Cursor::new(sl)
	}
	pub(crate) fn from_vec(v: &derived::CVec_u8Z) -> u8slice {
		Self::from_slice(v.as_slice())
	}
}
pub(crate) fn reader_to_vec<R: Read>(r: &mut R) -> derived::CVec_u8Z {
	let mut res = Vec::new();
	r.read_to_end(&mut res).unwrap();
	derived::CVec_u8Z::from(res)
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Arbitrary 32 bytes, which could represent one of a few different things. You probably want to
/// look up the corresponding function in rust-lightning's docs.
pub struct ThirtyTwoBytes {
	/// The thirty-two bytes
	pub data: [u8; 32],
}

#[derive(Clone)]
#[repr(C)]
/// A 3-byte byte array.
pub struct ThreeBytes { /** The three bytes */ pub data: [u8; 3], }
#[derive(Clone)]
#[repr(C)]
/// A 4-byte byte array.
pub struct FourBytes { /** The four bytes */ pub data: [u8; 4], }
#[derive(Clone)]
#[repr(C)]
/// A 12-byte byte array.
pub struct TwelveBytes { /** The twelve bytes */ pub data: [u8; 12], }
#[derive(Clone)]
#[repr(C)]
/// A 16-byte byte array.
pub struct SixteenBytes { /** The sixteen bytes */ pub data: [u8; 16], }
#[derive(Clone)]
#[repr(C)]
/// A 20-byte byte array.
pub struct TwentyBytes { /** The twenty bytes */ pub data: [u8; 20], }

#[derive(Clone)]
#[repr(C)]
/// 32 u16s
pub struct ThirtyTwoU16s { /** The thirty-two 16-bit integers */ pub data: [u16; 32], }

pub(crate) struct VecWriter(pub Vec<u8>);
impl lightning::util::ser::Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}
pub(crate) fn serialize_obj<I: lightning::util::ser::Writeable>(i: &I) -> derived::CVec_u8Z {
	let mut out = VecWriter(Vec::new());
	i.write(&mut out).unwrap();
	derived::CVec_u8Z::from(out.0)
}
pub(crate) fn deserialize_obj<I: lightning::util::ser::Readable>(s: u8slice) -> Result<I, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice())
}
pub(crate) fn maybe_deserialize_obj<I: lightning::util::ser::MaybeReadable>(s: u8slice) -> Result<Option<I>, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice())
}
pub(crate) fn deserialize_obj_arg<A, I: lightning::util::ser::ReadableArgs<A>>(s: u8slice, args: A) -> Result<I, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice(), args)
}

#[repr(C)]
/// A Rust str object, ie a reference to a UTF8-valid string.
/// This is *not* null-terminated so cannot be used directly as a C string!
pub struct Str {
	/// A pointer to the string's bytes, in UTF8 encoding
	pub chars: *const u8,
	/// The number of bytes (not characters!) pointed to by `chars`
	pub len: usize,
	/// Whether the data pointed to by `chars` should be freed or not.
	pub chars_is_owned: bool,
}
impl Into<Str> for &str {
	fn into(self) -> Str {
		self.to_owned().into()
	}
}
impl Into<Str> for &mut &str {
	fn into(self) -> Str {
		let us: &str = *self;
		us.into()
	}
}

impl Str {
	pub(crate) fn into_str(&self) -> &'static str {
		if self.len == 0 { return ""; }
		core::str::from_utf8(unsafe { core::slice::from_raw_parts(self.chars, self.len) }).unwrap()
	}
	pub(crate) fn into_string(mut self) -> String {
		let bytes = if self.len == 0 {
			Vec::new()
		} else if self.chars_is_owned {
			let ret = unsafe {
				Box::from_raw(core::slice::from_raw_parts_mut(unsafe { self.chars as *mut u8 }, self.len))
			}.into();
			self.chars_is_owned = false;
			ret
		} else {
			let mut ret = Vec::with_capacity(self.len);
			ret.extend_from_slice(unsafe { core::slice::from_raw_parts(self.chars, self.len) });
			ret
		};
		String::from_utf8(bytes).unwrap()
	}
	#[cfg(not(feature = "no-std"))]
	pub(crate) fn into_pathbuf(mut self) -> std::path::PathBuf {
		std::path::PathBuf::from(self.into_string())
	}
}
impl Into<Str> for String {
	fn into(self) -> Str {
		let s = Box::leak(self.into_boxed_str());
		Str { chars: s.as_ptr(), len: s.len(), chars_is_owned: true }
	}
}
#[cfg(not(feature = "no-std"))]
impl Into<Str> for std::path::PathBuf {
	fn into(self) -> Str {
		self.into_os_string().into_string().expect("We expect paths to be UTF-8 valid").into()
	}
}
impl Clone for Str {
	fn clone(&self) -> Self {
		String::from(self.into_str()).into()
	}
}

impl Drop for Str {
	fn drop(&mut self) {
		if self.chars_is_owned && self.len != 0 {
			let _ = derived::CVec_u8Z { data: self.chars as *mut u8, datalen: self.len };
		}
	}
}
#[no_mangle]
/// Frees the data buffer, if chars_is_owned is set and len > 0.
pub extern "C" fn Str_free(_res: Str) { }

// Note that the C++ headers memset(0) all the Templ types to avoid deallocation!
// Thus, they must gracefully handle being completely null in _free.

// TODO: Integer/bool primitives should avoid the pointer indirection for underlying types
// everywhere in the containers.

#[repr(C)]
pub(crate) union CResultPtr<O, E> {
	pub(crate) result: *mut O,
	pub(crate) err: *mut E,
}
#[repr(C)]
pub(crate) struct CResultTempl<O, E> {
	pub(crate) contents: CResultPtr<O, E>,
	pub(crate) result_ok: bool,
}
impl<O, E> CResultTempl<O, E> {
	pub(crate) extern "C" fn ok(o: O) -> Self {
		CResultTempl {
			contents: CResultPtr {
				result: Box::into_raw(Box::new(o)),
			},
			result_ok: true,
		}
	}
	pub(crate) extern "C" fn err(e: E) -> Self {
		CResultTempl {
			contents: CResultPtr {
				err: Box::into_raw(Box::new(e)),
			},
			result_ok: false,
		}
	}
}
impl<O, E> Drop for CResultTempl<O, E> {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !self.contents.result.is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else if unsafe { !self.contents.err.is_null() } {
			let _ = unsafe { Box::from_raw(self.contents.err) };
		}
	}
}

/// Utility to make it easy to set a pointer to null and get its original value in line.
pub(crate) trait TakePointer<T> {
	fn take_ptr(&mut self) -> T;
}
impl<T> TakePointer<*const T> for *const T {
	fn take_ptr(&mut self) -> *const T {
		let ret = *self;
		*self = core::ptr::null();
		ret
	}
}
impl<T> TakePointer<*mut T> for *mut T {
	fn take_ptr(&mut self) -> *mut T {
		let ret = *self;
		*self = core::ptr::null_mut();
		ret
	}
}


pub(crate) mod ObjOps {
	#[cfg(feature = "no-std")]
	use alloc::boxed::Box;

	#[inline]
	#[must_use = "returns new dangling pointer"]
	pub(crate) fn heap_alloc<T>(obj: T) -> *mut T {
		let ptr = Box::into_raw(Box::new(obj));
		nonnull_ptr_to_inner(ptr)
	}
	#[inline]
	pub(crate) fn nonnull_ptr_to_inner<T>(ptr: *const T) -> *mut T {
		if core::mem::size_of::<T>() == 0 {
			// We map `None::<T>` as `T { inner: null, .. }` which works great for all
			// non-Zero-Sized-Types `T`.
			// For ZSTs, we need to differentiate between null implying `None` and null implying
			// `Some` with no allocation.
			// Thus, for ZSTs, we add one (usually) page here, which should always be aligned.
			// Note that this relies on undefined behavior! A pointer to NULL may be valid, but a
			// pointer to NULL + 4096 is almost certainly not. That said, Rust's existing use of
			// `(*mut T)1` for the pointer we're adding to is also not defined, so we should be
			// fine.
			// Note that we add 4095 here as at least the Java client assumes that the low bit on
			// any heap pointer is 0, which is generally provided by malloc, but which is not true
			// for ZSTs "allocated" by `Box::new`.
			debug_assert_eq!(ptr as usize, 1);
			unsafe { (ptr as *mut T).cast::<u8>().add(4096 - 1).cast::<T>() }
		} else {
			// In order to get better test coverage, also increment non-ZST pointers with
			// --cfg=test_mod_pointers, which is set in genbindings.sh for debug builds.
			#[cfg(test_mod_pointers)]
			unsafe { (ptr as *mut T).cast::<u8>().add(4096).cast::<T>() }
			#[cfg(not(test_mod_pointers))]
			unsafe { ptr as *mut T }
		}
	}
	#[inline]
	/// Invert nonnull_ptr_to_inner
	pub(crate) fn untweak_ptr<T>(ptr: *mut T) -> *mut T {
		if core::mem::size_of::<T>() == 0 {
			unsafe { ptr.cast::<u8>().sub(4096 - 1).cast::<T>() }
		} else {
			#[cfg(test_mod_pointers)]
			unsafe { ptr.cast::<u8>().sub(4096).cast::<T>() }
			#[cfg(not(test_mod_pointers))]
			ptr
		}
	}
}

#[cfg(test_mod_pointers)]
#[no_mangle]
/// This function exists for memory safety testing purposes. It should never be used in production
/// code
pub extern "C" fn __unmangle_inner_ptr(ptr: *const c_void) -> *const c_void {
	if ptr as usize == 1 {
		core::ptr::null()
	} else {
		unsafe { ptr.cast::<u8>().sub(4096).cast::<c_void>() }
	}
}

pub(crate) struct SmartPtr<T> {
	ptr: *mut T,
}
impl<T> SmartPtr<T> {
	pub(crate) fn from_obj(o: T) -> Self {
		Self { ptr: Box::into_raw(Box::new(o)) }
	}
	pub(crate) fn null() -> Self {
		Self { ptr: core::ptr::null_mut() }
	}
}
impl<T> Drop for SmartPtr<T> {
	fn drop(&mut self) {
		if self.ptr != core::ptr::null_mut() {
			let _ = unsafe { Box::from_raw(self.ptr) };
		}
	}
}
impl<T> core::ops::Deref for SmartPtr<T> {
	type Target = *mut T;
	fn deref(&self) -> &*mut T {
		&self.ptr
	}
}
