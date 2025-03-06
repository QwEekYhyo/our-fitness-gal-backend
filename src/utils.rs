use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::http::StatusCode;

use crate::errors::InternalErrExt;

pub fn random_hash() -> Result<(), StatusCode> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(b"fakepassword", &salt)
        .map_internal_err()?;

    Ok(())
}
