use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

pub async fn connect() -> Result<PgPool, sqlx::Error> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL missing!");

    PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
}
