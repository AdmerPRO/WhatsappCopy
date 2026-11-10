use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub uuid: Uuid,
    pub email: String,
    pub username: String,
    pub password: String,
}

pub async fn connect() -> Result<PgPool, sqlx::Error> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL missing!");

    PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
}
