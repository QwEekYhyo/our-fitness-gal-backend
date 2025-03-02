use diesel::prelude::*;

use crate::schema::users;

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct UserInfo<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub password: &'a str,
}
