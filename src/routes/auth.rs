use std::env;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};
use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Extension, Json, Router,
};
use diesel::{
    prelude::*,
    result::{DatabaseErrorKind, Error::DatabaseError},
    SelectableHelper,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{self, Claims},
    errors::InternalErrExt,
    models::{User, UserInfo},
    utils::random_hash,
    AppState,
};

pub fn router<S>(state: AppState) -> Router<S> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route(
            "/me",
            get(me).route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth::middleware,
            )),
        )
        .with_state(state)
}

async fn register(
    State(state): State<AppState>,
    Json(mut user): Json<UserInfo>,
) -> Result<Json<User>, StatusCode> {
    use crate::schema::users;

    let mut conn = state.pool.get().map_internal_err()?;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(user.password.as_bytes(), &salt)
        .map_internal_err()?
        .to_string();

    user.password = password_hash;

    let created_user = diesel::insert_into(users::table)
        .values(&user)
        .returning(User::as_returning())
        .get_result(&mut conn)
        .map_err(|e| {
            if let DatabaseError(DatabaseErrorKind::UniqueViolation, _) = e {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    Ok(Json(created_user))
}

#[derive(Debug, Deserialize)]
struct LoginCredentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
struct Token {
    pub token: String,
}

async fn login(
    State(state): State<AppState>,
    Json(credentials): Json<LoginCredentials>,
) -> Result<Json<Token>, StatusCode> {
    use crate::schema::users::dsl::{email, users};

    let mut conn = state.pool.get().map_internal_err()?;

    let target_user = users
        .filter(email.eq(credentials.email))
        .select(User::as_select())
        .first(&mut conn)
        .optional()
        .map_internal_err()?;

    let Some(target_user) = target_user else {
        random_hash()?;
        return Err(StatusCode::UNAUTHORIZED);
    };

    let password_hash = PasswordHash::new(&target_user.password).map_internal_err()?;

    let matching_passwords = Argon2::default()
        .verify_password(credentials.password.as_bytes(), &password_hash)
        .is_ok();

    if !matching_passwords {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let claims = Claims {
        user_id: target_user.id,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()),
    )
    .map_internal_err()?;

    Ok(Json(Token { token }))
}

pub async fn me(
    State(_state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<User>, StatusCode> {
    Ok(Json(user))
}
