// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//!lightning
//! Rust-Lightning, not Rusty's Lightning!
//!
//! A full-featured but also flexible lightning implementation, in library form. This allows the
//! user (you) to decide how they wish to use it instead of being a fully self-contained daemon.
//! This means there is no built-in threading/execution environment and it's up to the user to
//! figure out how best to make networking happen/timers fire/things get written to disk/keys get
//! generated/etc. This makes it a good candidate for tight integration into an existing wallet
//! instead of having a rather-separate lightning appendage to a wallet.
//!
//! `default` features are:
//!
//! * `std` - enables functionalities which require `std`, including `std::io` trait implementations and things which utilize time
//! * `grind_signatures` - enables generation of [low-r bitcoin signatures](https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding),
//! which saves 1 byte per signature in 50% of the cases (see [bitcoin PR #13666](https://github.com/bitcoin/bitcoin/pull/13666))
//!
//! Available features are:
//!
//! * `std`
//! * `grind_signatures`
//! * `no-std ` - exposes write trait implementations from the `core2` crate (at least one of `no-std` or `std` are required)
//! * Skip logging of messages at levels below the given log level:
//!     * `max_level_off`
//!     * `max_level_error`
//!     * `max_level_warn`
//!     * `max_level_info`
//!     * `max_level_debug`
//!     * `max_level_trace`

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod util;
pub mod chain;
pub mod ln;
pub mod offers;
pub mod routing;
pub mod sign;
pub mod onion_message;
pub mod blinded_path;
pub mod events;
pub mod io;
mod crypto {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod chacha20 {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod real_chacha {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
}
mod poly1305 {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod chacha20poly1305rfc {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod real_chachapoly {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
}
mod streams {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod utils {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
}
mod prelude {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod sync {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod fairrwlock {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod ext_impl {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
}
