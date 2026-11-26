use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    name: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct UserView {
    pub name: String,
    pub email: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserView,
}

pub struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }
    fn unauthorized(message: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message,
        }
    }
    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
        }
    }
    fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
        }
    }
    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "服务器内部错误",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

/// Same rule as the frontend: `^[^\s@]+@[^\s@]+\.[^\s@]+$`.
fn is_valid_email(email: &str) -> bool {
    let bad = |c: char| c.is_whitespace() || c == '@';
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.chars().any(bad) || domain.chars().any(bad) {
        return false;
    }
    match domain.rsplit_once('.') {
        Some((host, tld)) => !host.is_empty() && !tld.is_empty(),
        None => false,
    }
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rand_core::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::internal())
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    match PasswordHash::new(hash) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let name = req.name.trim().to_string();
    let email = req.email.trim().to_lowercase();

    if name.chars().count() < 2 {
        return Err(ApiError::bad_request("昵称至少需要 2 个字符"));
    }
    if !is_valid_email(&email) {
        return Err(ApiError::bad_request("请输入有效的邮箱地址"));
    }
    if req.password.chars().count() < 8 {
        return Err(ApiError::bad_request("密码至少需要 8 位"));
    }

    let taken: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE email = ? OR name = ?")
        .bind(&email)
        .bind(&name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ApiError::internal())?;
    if taken.is_some() {
        return Err(ApiError::conflict("该邮箱或昵称已被注册，请直接登录"));
    }

    let hash = hash_password(&req.password)?;
    sqlx::query("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)")
        .bind(&name)
        .bind(&email)
        .bind(&hash)
        .execute(&state.db)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user: UserView { name, email },
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let email = req.email.trim().to_lowercase();

    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, password_hash FROM users WHERE email = ?")
            .bind(&email)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| ApiError::internal())?;
    let Some((name, hash)) = row else {
        return Err(ApiError::not_found("账号不存在，请先注册"));
    };
    if !verify_password(&req.password, &hash) {
        return Err(ApiError::unauthorized("密码不正确，请重试"));
    }

    Ok(Json(AuthResponse {
        user: UserView { name, email },
    }))
}

#[cfg(test)]
mod tests {
    use crate::{app, init_state};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    async fn post(app: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
        let res = app
            .clone()
            .oneshot(
                Request::post(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn register_then_login_succeeds() {
        let app = app(init_state().await);
        let (s, b) = post(
            &app,
            "/api/register",
            json!({"name":"Alex","email":"A@Example.com ","password":"secret123"}),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(b["user"]["email"], "a@example.com");
        let (s, b) = post(
            &app,
            "/api/login",
            json!({"email":"a@example.com","password":"secret123"}),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["user"]["name"], "Alex");
    }

    #[tokio::test]
    async fn register_rejects_invalid_input() {
        let app = app(init_state().await);
        let (s, b) = post(
            &app,
            "/api/register",
            json!({"name":"A","email":"a@b.co","password":"secret123"}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"], "昵称至少需要 2 个字符");
        let (s, b) = post(
            &app,
            "/api/register",
            json!({"name":"Al","email":"bad","password":"secret123"}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"], "请输入有效的邮箱地址");
        let (s, b) = post(
            &app,
            "/api/register",
            json!({"name":"Al","email":"a@b.co","password":"short"}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"], "密码至少需要 8 位");
    }

    #[tokio::test]
    async fn register_rejects_duplicate_email_or_name() {
        let app = app(init_state().await);
        post(
            &app,
            "/api/register",
            json!({"name":"Alex","email":"a@b.co","password":"secret123"}),
        )
        .await;
        let (s, _) = post(
            &app,
            "/api/register",
            json!({"name":"Other","email":"A@b.co","password":"secret123"}),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, _) = post(
            &app,
            "/api/register",
            json!({"name":"Alex","email":"x@b.co","password":"secret123"}),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn login_errors() {
        let app = app(init_state().await);
        post(
            &app,
            "/api/register",
            json!({"name":"Alex","email":"a@b.co","password":"secret123"}),
        )
        .await;
        let (s, b) = post(
            &app,
            "/api/login",
            json!({"email":"zz@b.co","password":"secret123"}),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(b["error"], "账号不存在，请先注册");
        let (s, b) = post(
            &app,
            "/api/login",
            json!({"email":"a@b.co","password":"wrongpass"}),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(b["error"], "密码不正确，请重试");
    }
}
