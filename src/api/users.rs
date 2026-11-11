use crate::state::AppState;
use crate::utils::hash_password;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct CreateUserInput {
    username: String,
    password: String,
    email: String,
}

// Check if username is valid
fn is_username_valid(input: &str) -> bool {
    let length = input.chars().count();

    (3..=16).contains(&length) && input.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// Check if password is valid
fn is_password_valid(input: &str) -> bool {
    let length = input.chars().count();

    (8..=128).contains(&length) && input.chars().all(|c| !c.is_control())
}

// Check if email is vaild
fn is_email_valid(input: &str) -> bool {
    let length = input.len();

    (5..=254).contains(&length)
        && input.contains('@')
        && input.contains('.')
        && input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
}

// Check if username is taken in bloom or database
async fn is_username_taken(state: &AppState, name: &str) -> bool {
    let possibly_taken = {
        let bloom = state.bloom.read().unwrap();
        bloom.is_taken(name)
    };

    // Bloom Filter says definitely free
    if !possibly_taken {
        return false;
    }

    // Bloom Filter says possibly taken, check database
    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
            .bind(name)
            .fetch_one(&state.db)
            .await
            .unwrap();

    exists
}

// Check if username is available
async fn check_username(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<bool>, (StatusCode, Json<bool>)> {
    if !is_username_valid(&name) {
        return Err((StatusCode::BAD_REQUEST, Json(false)));
    }

    let taken = is_username_taken(&state, &name).await;

    Ok(Json(taken))
}

// Creates a user
async fn create_user(
    State(state): State<AppState>,
    Json(user): Json<CreateUserInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let username = user.username;
    let password = user.password;
    let email = user.email;

    // Validate username
    if !is_username_valid(&username) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INVALID_USERNAME",
                "message": "Username contains invalid characters"
            })),
        ));
    }

    // Validate password
    if !is_password_valid(&password) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INVALID_PASSWORD",
                "message": "Password contains invalid characters"
            })),
        ));
    }

    // Validate email
    if !is_email_valid(&email) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INVALID_EMAIL",
                "message": "Email contains invalid characters"
            })),
        ));
    }

    // Check Bloom Filter
    let taken = is_username_taken(&state, &username).await;

    if taken {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "USERNAME_TAKEN",
                "message": "This username is already taken"
            })),
        ));
    }

    // TODO: release password variable somehow
    let hashed_password = hash_password(&password);

    let result = sqlx::query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)")
        .bind(&username)
        .bind(email)
        .bind(hashed_password)
        .execute(&state.db)
        .await;

    if let Err(error) = result {
        eprintln!("Database error: {error}");

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": "DATABASE_ERROR"
            })),
        ));
    }

    // Update Bloom Filter only after successful INSERT
    let mut bloom = state.bloom.write().map_err(|error| {
        eprintln!("Failed to lock Bloom Filter: {error}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": "BLOOM_FILTER_ERROR"
            })),
        )
    })?;

    bloom.insert(&username);

    if let Err(error) = bloom.save() {
        eprintln!("Failed to save Bloom Filter: {error}");

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": "BLOOM_FILTER_ERROR"
            })),
        ));
    }

    Ok(Json(json!({
        "success": true,
        "message": "User created"
    })))
}

// Logs in the user
async fn login_user() -> &'static str {
    "login"
}

// Gets data from database about user
async fn get_data_from_user() -> &'static str {
    "data"
}

// Router for users endpoints
pub fn users_router() -> Router<AppState> {
    Router::new()
        .route("/create_user", post(create_user))
        .route("/login_user", post(login_user))
        .route("/get_data_from_user", post(get_data_from_user))
        .route("/check_username/{name}", get(check_username))
}
