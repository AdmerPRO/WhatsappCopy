use crate::state::AppState;
use crate::utils::{generate_token, hash_password, verify_password, verify_token, generate_session_id, hash_session_id};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use chrono::Utc;

// Create user

#[derive(Deserialize)]
struct CreateUserInput {
    username: String,
    password: String,
    email: String,
}

// Login user with username

#[derive(Deserialize)]
struct LoginUserInput {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginUserOutput {
    username: String,
    token: String,
    expires_at: usize,
}

#[derive(Debug, sqlx::FromRow)]
struct UserLoginData {
    password: String,
    uuid: Uuid,
}

// Login user with token

#[derive(Deserialize)]
struct LoginTokenInput {
    username: String,
    token: String,
}

#[derive(Serialize)]
struct LoginTokenOutput {
    username: String,
    session: String,
    expires_at: u64,
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
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
        .bind(name)
        .fetch_one(&state.db)
        .await
        .unwrap()
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

    // Check if username is taken
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
    drop(password);

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
        eprintln!("Failed to save Bloom Filter: {error} , Username: {username}");

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": "BLOOM_FILTER_ERROR"
            })),
        ));
    }

    drop(username);

    Ok(Json(json!({
        "success": true,
        "message": "User created"
    })))
}

// Logs in the user
async fn login_user_with_username(
    State(state): State<AppState>,
    Json(user): Json<LoginUserInput>,
) -> Result<Json<LoginUserOutput>, (StatusCode, Json<Value>)> {
    let username = user.username;
    let password = user.password;

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

    let user_db =
        sqlx::query_as::<_, UserLoginData>("SELECT password, uuid FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&state.db)
            .await;

    let (password_db, uuid_db) = match user_db {
        Ok(Some(user)) => (user.password, user.uuid),

        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "INVALID_CREDENTIALS",
                    "message": "Invalid username or password."
                })),
            ));
        }

        Err(error) => {
            eprintln!("Database error: {error}");

            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "DATABASE_ERROR"
                })),
            ));
        }
    };

    let valid_password = verify_password(&password, &password_db);

    drop(password);
    drop(password_db);

    if !valid_password {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "INVALID_CREDENTIALS",
                "message": "Invalid username or password."
            })),
        ));
    }

    let token = generate_token(username.clone(), uuid_db).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "TOKEN_GENERATION_FAILED"
            })),
        )
    })?;

    let token_as_struct = verify_token(&token).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "TOKEN_VERIFICATION_FAILED"
            })),
        )
    })?;

    let expires_at = token_as_struct.exp;

    Ok(Json(LoginUserOutput {
        username,
        token,
        expires_at,
    }))
}

async fn login_user_with_token(
    State(state): State<AppState>,
    Json(user): Json<LoginTokenInput>,
) -> Result<Json<LoginTokenOutput>, (StatusCode, Json<Value>)> {

    let username = user.username;
    let token = user.token;

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

    let token_as_struct = verify_token(&token).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "TOKEN_VERIFICATION_FAILED"
            })),
        )
    })?;

    let now = Utc::now().timestamp() as usize;
    let expires_at = token_as_struct.exp;

    if expires_at >= now {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "TOKEN_INACTIVE",
                "message": "Token is inactive"
            }))
        ));
    }

    let session = generate_session_id();
    let session_hash = hash_session_id(&session);
    let expires_at = chrono::Utc::now().timestamp() + 15 * 60;

    let result = sqlx::query("INSERT INTO sessions (username, session_hash, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(&username)
        .bind(session_hash)
        .bind("0.0.0.0") // Todo: Add real user ip
        .bind("Mozilla") // Todo: Add real user agent
        .bind(&expires_at)
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

    Ok(Json(LoginTokenOutput {
        username: username,
        session: session,
        expires_at: expires_at as u64,
    }))
}

// Todo: login_user_with_email

// Gets data from database about user
async fn get_data_from_user() -> &'static str {
    "data"
}

// Router for users endpoints
pub fn users_router() -> Router<AppState> {
    Router::new()
        .route("/create_user", post(create_user))
        .route("/login_user_username", post(login_user_with_username))
        .route("/login_user_token", post(login_user_with_token))
        .route("/get_data_from_user", post(get_data_from_user))
        .route("/check_username/{name}", get(check_username))
}
