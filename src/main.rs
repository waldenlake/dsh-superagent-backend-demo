mod auth;

use axum::{Router, routing::post};
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

pub async fn init_state() -> AppState {
    // Single connection: each new connection to `sqlite::memory:` gets its own empty DB.
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("open in-memory sqlite");
    sqlx::query(
        "CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )",
    )
    .execute(&db)
    .await
    .expect("create users table");
    AppState { db }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/register", post(auth::register))
        .route("/api/login", post(auth::login))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let state = init_state().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind 127.0.0.1:8080");
    axum::serve(listener, app(state)).await.expect("serve");
}
