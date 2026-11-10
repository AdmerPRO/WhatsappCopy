pub mod chats;
pub mod users;

use chats::load_chat;
use users::{create_user, get_data_from_user, login_user};

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

pub fn api_router() -> Router {
    Router::new()
        .route("/", get(api_root))
        .route("/users/create_user", post(create_user))
        .route("/users/login_user", post(login_user))
        .route("/users/get_data_from_user", post(get_data_from_user))
        .route("/chats/{id}", post(load_chat))
}
