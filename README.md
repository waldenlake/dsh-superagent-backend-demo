# dsh-superagent-backend-demo

Login and registration backend for the Nebula frontend (`waldenlake/dsh-superagent-demo`). Built with axum and sqlx on in-memory SQLite. Data resets on restart.

## Run

```sh
cargo run   # listens on 127.0.0.1:8080
cargo test
```

## API

- `POST /api/register` with `{"name","email","password"}` returns `201` and `{"user":{"name","email"}}`.
- `POST /api/login` with `{"email","password"}` returns `200` and `{"user":{"name","email"}}`.
- Errors return `{"error": "<message>"}`: `400` for validation, `409` for a duplicate email or name, `404` for an unknown account, `401` for a wrong password.

Validation rules and messages match the frontend. Emails are trimmed and lowercased. Passwords are hashed with argon2.
