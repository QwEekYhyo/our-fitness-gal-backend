mod models;
mod schema;

use diesel::prelude::*;
use dotenvy::dotenv;
use self::models::*;
use std::env;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn create_user(conn: &mut PgConnection, username: &str, email: &str, password: &str) -> User {
    use crate::schema::users;

    let new_user = UserInfo { username, email, password };

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result(conn)
        .expect("Error registering new user")
}

fn main() {
    use self::schema::users::dsl::*;

    let connection = &mut establish_connection();

    create_user(connection, "QwEekYhyo", "bite@gmail.com", "password");

    let results = users
        .select(User::as_select())
        .load(connection)
        .expect("Error loading users");

    println!("Displaying {} users", results.len());
    for user in results {
        println!("{}", user.username);
        println!("{}", user.email);
    }
}
