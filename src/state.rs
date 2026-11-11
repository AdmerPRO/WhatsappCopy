use sqlx::PgPool;

use std::sync::{Arc, RwLock};

use crate::utils::BloomFilter;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub bloom: Arc<RwLock<BloomFilter>>,
}

impl AppState {
    pub fn new(db: sqlx::PgPool) -> Self {
        let bloom = BloomFilter::load().expect("Failed to load Bloom Filter");

        Self {
            db,
            bloom: Arc::new(RwLock::new(bloom)),
        }
    }
}
