pub mod chats;
pub mod users;

use chats::load_chat;
use users::users_router;

use crate::state::AppState;

use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::Serialize;

#[derive(Serialize)]
struct ApiRootOutput {
    status: String,
    ping: String,
}

impl ApiRootOutput {
    pub fn generate_status_success() -> ApiRootOutput {
        ApiRootOutput {
            status: String::from("ok"),
            ping: String::from("pong"),
        }
    }
}

async fn api_root() -> Json<ApiRootOutput> {
    let data = ApiRootOutput::generate_status_success();

    Json(data)
}

pub fn api_router() -> Router<AppState> {
    Router::new()
        .route("/", get(api_root))
        .nest("/users", users_router())
        .route("/chats/{id}", post(load_chat))
}
