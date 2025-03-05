mod errors;
mod models;
mod schema;

use self::models::*;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, Pool},
    result::{DatabaseErrorKind, Error::DatabaseError},
};
use dotenvy::dotenv;
use errors::InternalErrExt;
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub fn get_connection_pool() -> Pool<ConnectionManager<PgConnection>> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::builder()
        .test_on_check_out(true)
        .build(manager)
        .expect("Could not build connection pool")
}

#[derive(Clone)]
struct AppState {
    pool: Pool<ConnectionManager<PgConnection>>,
}

async fn register_user(
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

fn random_hash() -> Result<(), StatusCode> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2.hash_password(b"fakepassword", &salt).map_internal_err()?;

    Ok(())
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    dotenv().ok();

    let state = AppState {
        pool: get_connection_pool(),
    };

    let app = Router::new()
        .route("/register", post(register_user))
        .route("/login", post(login))
        .with_state(state);

    let addr = env::var("ADDR")
        .ok()
        .map(|s| s.parse::<IpAddr>().expect("invalid address"));
    let port = env::var("PORT")
        .ok()
        .map(|s| s.parse::<u16>().expect("invalid port"));

    let sockaddr = SocketAddr::from((
        addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        port.unwrap_or(3000),
    ));
    tracing::info!("Listening on http://{sockaddr}");

    let listener = tokio::net::TcpListener::bind(&sockaddr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
