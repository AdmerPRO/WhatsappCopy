mod api;
mod database;
mod state;

use api::api_router;
use state::AppState;

use axum::{Router, routing::get};
use std::env;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // Database

    let db = database::connect()
        .await
        .expect("Database connection failed!");

    // State

    let state = AppState { db };

    // Networking

    let address = env::var("ADDRESS").unwrap_or("0.0.0.0".to_string());
    let port: u16 = env::var("PORT")
        .unwrap_or("3000".to_string())
        .parse()
        .expect("Invalid PORT");

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .nest("/api", api_router())
        .with_state(state);

    let bind_address = format!("{address}:{port}");

    let listener = tokio::net::TcpListener::bind(&bind_address).await.unwrap();

    println!("Listening on http://{}", bind_address);
    axum::serve(listener, app).await.unwrap();
}
