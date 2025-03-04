mod errors;
mod models;
mod schema;

use self::models::*;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, Pool},
    result::DatabaseErrorKind,
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
    Json(payload): Json<UserInfo>,
) -> Result<Json<User>, StatusCode> {
    use crate::schema::users;

    let mut conn = state.pool.get().map_internal_err()?;

    let created_user = diesel::insert_into(users::table)
        .values(&payload)
        .returning(User::as_returning())
        .get_result(&mut conn)
        .map_err(|e| {
            if let diesel::result::Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) = e {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    Ok(Json(created_user))
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
