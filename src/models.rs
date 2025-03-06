use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::users;

#[derive(Clone, Debug, Identifiable, Queryable, Selectable, Serialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    #[serde(skip)]
    pub password: String,
}

#[derive(Debug, Deserialize, Insertable)]
#[diesel(table_name = users)]
pub struct UserInfo {
    pub username: String,
    pub email: String,
    pub password: String,
}
