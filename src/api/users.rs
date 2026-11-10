use crate::database::User;
use crate::state::AppState;

use axum::{Router, routing::post};
use sqlx::PgPool;
use uuid::Uuid;

async fn get_user_by_uuid(db: &PgPool, uuid: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE uuid = $1")
        .bind(uuid)
        .fetch_optional(db)
        .await
}

async fn create_user() -> &'static str {
    "create"
}

async fn login_user() -> &'static str {
    "login"
}

async fn get_data_from_user() -> &'static str {
    "data"
}

pub fn users_router() -> Router<AppState> {
    Router::new()
        .route("/create_user", post(create_user))
        .route("/login_user", post(login_user))
        .route("/get_data_from_user", post(get_data_from_user))
}
