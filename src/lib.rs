// No need to use any unsafety in this crate
#![forbid(unsafe_code)]

// This is because ratchet trees use 32-bit indices, which means Vecs need to be able to store up
// to 2^32 - 1 many elements
#[cfg(any(target_pointer_width = "16", target_pointer_width = "8"))]
compile_error!("Molasses requires the architecture's pointer width to be at least 32 bits");

// Can't make this work using edition 2018 syntax yet
#[macro_use]
extern crate serde;

// Internal modules still need macro_use
#[macro_use]
mod utils;

#[cfg(test)]
#[macro_use]
mod test_utils;

pub mod application;
pub mod client_init_key;
mod codec;
pub mod credential;
pub mod crypto;
pub mod error;
pub mod group_ctx;
pub mod handshake;
pub mod ratchet_tree;
pub mod tls_de;
pub mod tls_ser;
mod tree_math;
pub mod upcast;
