use axum::{Router, routing::post};

pub fn users_router() -> Router {
    Router::new()
        .route("/create_user", post(create_user))
        .route("/login_user", post(login_user))
        .route("/get_data_from_user", post(get_data_from_user))
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
