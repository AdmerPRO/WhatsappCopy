pub mod users;

use users::{create_user, login_user};
use serde::Serialize;

use axum::{routing::{get, post}, Router, Json};

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
}