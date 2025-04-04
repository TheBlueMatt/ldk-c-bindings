// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//!lightning_liquidity
//! The goal of this crate is to provide types and primitives to integrate a spec-compliant LSP
//! with an LDK-based node. To this end, this crate provides client-side as well as service-side
//! logic to implement the LSPS specifications.
//!
//! **Note**: Service-side support is currently considered \"beta\", i.e., not fully ready for
//! production use.
//!
//! Currently the following specifications are supported:
//! - [bLIP-50 / LSPS0] defines the transport protocol with the LSP over which the other protocols communicate.
//! - [bLIP-51 / LSPS1] defines a protocol for ordering Lightning channels from an LSP. This is useful when the client needs
//! inbound Lightning liquidity for which they are willing and able to pay in bitcoin.
//! - [bLIP-52 / LSPS2] defines a protocol for generating a special invoice for which, when paid,
//! an LSP will open a \"just-in-time\" channel. This is useful for the initial on-boarding of
//! clients as the channel opening fees are deducted from the incoming payment, i.e., no funds are
//! required client-side to initiate this flow.
//!
//! To get started, you'll want to setup a [`LiquidityManager`] and configure it to be the
//! [`CustomMessageHandler`] of your LDK node. You can then for example call
//! [`LiquidityManager::lsps1_client_handler`] / [`LiquidityManager::lsps2_client_handler`], or
//! [`LiquidityManager::lsps2_service_handler`], to access the respective client-side or
//! service-side handlers.
//!
//! [`LiquidityManager`] uses an eventing system to notify the user about important updates to the
//! protocol flow. To this end, you will need to handle events emitted via one of the event
//! handling methods provided by [`LiquidityManager`], e.g., [`LiquidityManager::next_event`].
//!
//! [bLIP-50 / LSPS0]: https://github.com/lightning/blips/blob/master/blip-0050.md
//! [bLIP-51 / LSPS1]: https://github.com/lightning/blips/blob/master/blip-0051.md
//! [bLIP-52 / LSPS2]: https://github.com/lightning/blips/blob/master/blip-0052.md
//! [`CustomMessageHandler`]: lightning::ln::peer_handler::CustomMessageHandler
//! [`LiquidityManager::next_event`]: crate::LiquidityManager::next_event

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod events;
pub mod lsps0;
pub mod lsps1;
pub mod lsps2;
pub mod message_queue;
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
mod manager {

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
