//! Decoded rows by record ordinal, filled in windows (contiguous view) or
//! batches of scattered ordinals (filtered view).

use std::collections::HashMap;

use gridsift_core::enrich::Enrichment;
use gridsift_core::index::SparseIndex;
use gridsift_core::reader::{Located, locate_many, locate_records};
use gridsift_core::source::Source;

/// Decoded rows kept in memory before the cache is flushed.
const CACHE_CAP: usize = 20_000;

#[derive(Default)]
pub struct RowCache {
    rows: HashMap<u64, Vec<String>>,
}

impl RowCache {
    pub fn get(&self, record: u64) -> Option<&[String]> {
        self.rows.get(&record).map(Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn clear(&mut self) {
        self.rows.clear();
    }

    fn make_room(&mut self) {
        if self.rows.len() > CACHE_CAP {
            self.rows.clear();
        }
    }

    /// Decode rows to strings; derived (enrichment) values are appended
    /// after the source fields.
    fn decode(
        source: &Source,
        index: &SparseIndex,
        recs: &[Located],
        enrichment: Option<&Enrichment>,
    ) -> Vec<(u64, Vec<String>)> {
        let mut fields = Vec::new();
        let mut derived = Vec::new();
        recs.iter()
            .map(|r| {
                r.fields(source, index, &mut fields);
                let mut row: Vec<String> = fields
                    .iter()
                    .map(|f| String::from_utf8_lossy(f).into_owned())
                    .collect();
                if let Some(e) = enrichment {
                    e.compute(r.raw(source), &mut derived);
                    row.extend(
                        derived
                            .iter()
                            .map(|v| String::from_utf8_lossy(v).into_owned()),
                    );
                }
                (r.record, row)
            })
            .collect()
    }

    /// Fetch `first .. first + count`; returns how many rows were found.
    pub fn fill_window(
        &mut self,
        source: &Source,
        index: &SparseIndex,
        enrichment: Option<&Enrichment>,
        first: u64,
        count: usize,
    ) -> usize {
        self.make_room();
        let recs = locate_records(source, index, first, count);
        let n = recs.len();
        self.rows
            .extend(Self::decode(source, index, &recs, enrichment));
        n
    }

    /// Fetch scattered ordinals (sorted, de-duplicated).
    pub fn fill_many(
        &mut self,
        source: &Source,
        index: &SparseIndex,
        enrichment: Option<&Enrichment>,
        ordinals: &[u64],
    ) {
        self.make_room();
        let recs = locate_many(source, index, ordinals);
        self.rows
            .extend(Self::decode(source, index, &recs, enrichment));
    }
}
