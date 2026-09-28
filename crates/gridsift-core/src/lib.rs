//! gridsift-core: bounded-memory, quote-aware access to very large CSV evidence.
//!
//! Design principles (see `survey/` and the README):
//! - the source file is immutable evidence; nothing here ever writes to it
//! - memory use must not scale with file size
//! - byte offsets into the original file are the canonical record identity
//! - a logical CSV record is the unit of navigation, never a physical line
//!
//! Module map:
//! - [`source`]  read-only, memory-mapped access to the file and its identity
//! - [`dialect`] delimiter / quote / header sniffing with evidence
//! - [`scan`]    resumable quote-aware record-boundary scanner
//! - [`record`]  field splitting for one record
//! - [`index`]   sparse checkpoint index, built in one pass with the digests
//! - [`reader`]  viewport: records by ordinal via the index
//! - [`search`]  parallel literal / regex search producing a match bitmap
//! - [`export`]  atomic, hashed export of a selection to a new file
//! - [`frequency`] parallel top-N value counts for a column
//! - [`timeline`] timestamp parsing, time-bucketed counts, time-range selection
//! - [`semantic`] semantic column typing (ip, domain, hash, timestamp, …)
//! - [`manifest`] provenance manifest written next to every export
//! - [`redact`]  export-time column redaction (drop / mask / partial / ip prefix / hmac)
//! - [`enrich`]  offline enrichment: GeoIP/ASN from imported MMDB, PSL domains, local CSV joins
//! - [`hash`]    streaming SHA-256 / BLAKE3
//! - [`sidecar`] where derived files (indexes) are stored
//! - [`synth`]   deterministic synthetic datasets for benchmarks
//! - [`sys`]     process probes and formatting helpers for reports

pub mod dialect;
pub mod enrich;
pub mod export;
pub mod frequency;
pub mod hash;
pub mod index;
pub mod manifest;
pub mod reader;
pub mod record;
pub mod redact;
pub mod scan;
pub mod search;
pub mod semantic;
pub mod sidecar;
pub mod source;
pub mod synth;
pub mod sys;
pub mod timeline;

pub use dialect::{Bom, Dialect, Sniff};
pub use hash::{Digests, HashSelection};
pub use index::{BuildOptions, Checkpoint, IndexParams, IndexStats, SparseIndex, build_index};
pub use reader::{Located, header_fields, locate_records};
pub use scan::{Control, RecordSpan, ScanConfig, Scanner};
pub use source::{Source, SourceId};
