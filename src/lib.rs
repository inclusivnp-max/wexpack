//! WexPack v2: explicit container, normalized FastCDC, BLAKE3 deduplication, reversible filters, compression engines, AEAD, Reed–Solomon recovery and bounded archive operations.
pub mod cdc;
pub mod codec;
pub mod crypto;
pub mod fec;
pub mod filters;
pub mod format;
pub mod pipeline;
