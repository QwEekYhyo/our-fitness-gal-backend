use std::env;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use diesel::{prelude::*, SelectableHelper};
use serde::{Deserialize, Serialize};

use crate::{errors::InternalErrExt, models, AppState};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i32,
}

pub async fn middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header| auth_header.to_str().ok())
        .and_then(|auth_value| auth_value.strip_prefix("Bearer "));

    let token = token.ok_or(StatusCode::UNAUTHORIZED)?;

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let mut validation = jsonwebtoken::Validation::default();
    validation.set_required_spec_claims(&["user_id"]);

    let claims = jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_ref()),
        &validation,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;

    use crate::schema::users::dsl::users;

    let mut conn = state.pool.get().map_internal_err()?;

    let logged_user = users
        .select(models::User::as_select())
        .find(claims.user_id)
        .first(&mut conn)
        .optional()
        .map_internal_err()?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    req.extensions_mut().insert(logged_user);

    Ok(next.run(req).await)
}
