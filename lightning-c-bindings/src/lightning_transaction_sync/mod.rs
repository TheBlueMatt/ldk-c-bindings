// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Provides utilities for syncing LDK via the transaction-based [`Confirm`] interface.
//!
//! The provided synchronization clients need to be registered with a [`ChainMonitor`] via the
//! [`Filter`] interface. Then, the respective `fn sync` needs to be called with the [`Confirm`]
//! implementations to be synchronized, i.e., usually instances of [`ChannelManager`] and
//! [`ChainMonitor`].
//!
//! ## Features and Backend Support
//!
//!- `esplora-blocking` enables syncing against an Esplora backend based on a blocking client.
//!- `esplora-async` enables syncing against an Esplora backend based on an async client.
//!- `esplora-async-https` enables the async Esplora client with support for HTTPS.
//!
//! ## Version Compatibility
//!
//! Currently this crate is compatible with LDK version 0.0.114 and above using channels which were
//! created on LDK version 0.0.113 and above.
//!
//! ## Usage Example:
//!
//! ```ignore
//! let tx_sync = Arc::new(EsploraSyncClient::new(
//! \tesplora_server_url,
//! \tArc::clone(&some_logger),
//! ));
//!
//! let chain_monitor = Arc::new(ChainMonitor::new(
//! \tSome(Arc::clone(&tx_sync)),
//! \tArc::clone(&some_broadcaster),
//! \tArc::clone(&some_logger),
//! \tArc::clone(&some_fee_estimator),
//! \tArc::clone(&some_persister),
//! ));
//!
//! let channel_manager = Arc::new(ChannelManager::new(
//! \tArc::clone(&some_fee_estimator),
//! \tArc::clone(&chain_monitor),
//! \tArc::clone(&some_broadcaster),
//! \tArc::clone(&some_router),
//! \tArc::clone(&some_logger),
//! \tArc::clone(&some_entropy_source),
//! \tArc::clone(&some_node_signer),
//! \tArc::clone(&some_signer_provider),
//! \tuser_config,
//! \tchain_params,
//! ));
//!
//! let confirmables = vec![
//! \t&*channel_manager as &(dyn Confirm + Sync + Send),
//! \t&*chain_monitor as &(dyn Confirm + Sync + Send),
//! ];
//!
//! tx_sync.sync(confirmables).unwrap();
//! ```
//!
//! [`Confirm`]: lightning::chain::Confirm
//! [`Filter`]: lightning::chain::Filter
//! [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
//! [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod esplora;
pub mod electrum;
pub mod error;
mod common {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
