use axum::{
    extract::Path,
};

pub async fn load_chat( Path(chat_id): Path<String> ) -> String {
    format!("load chat {}", chat_id)
}