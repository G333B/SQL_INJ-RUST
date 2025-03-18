use actix_web::{web, App, HttpResponse, HttpServer, Responder, http::header::ContentType};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::Insertable;
use serde::Deserialize;
use dotenvy::dotenv;
use std::env;

mod schema; 

use crate::schema::users::dsl::*; // ✅ Utilisation correcte de `crate::schema`

#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)] // ✅ Correction Diesel
struct NewUser<'a> {
    username: &'a str,
    password: &'a str,
}

fn establish_connection() -> SqliteConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect("Error connecting to database")
}

fn create_user(conn: &mut SqliteConnection, new_user: &NewUser) -> QueryResult<usize> {
    diesel::insert_into(users::table) // ✅ `users::table`
        .values(new_user)
        .execute(conn)
}

#[derive(Deserialize)]
struct AuthData {
    username: String,
    password: String,
}

async fn register_process(form: web::Form<AuthData>) -> impl Responder {
    let conn = &mut establish_connection();
    let new_user = NewUser {
        username: &form.username,
        password: &form.password, // ⚠️ Toujours stocké en clair
    };

    let _ = diesel::insert_into(users::table) // ✅ Correction Diesel
        .values(&new_user)
        .execute(conn);

    HttpResponse::Ok().body(format!("User {} registered!", form.username))
}

async fn login_process(form: web::Form<AuthData>) -> impl Responder {
    let conn = &mut establish_connection();

    let user_exists = diesel::sql_query(format!(
        "SELECT * FROM users WHERE username = '{}' AND password = '{}'",
        form.username, form.password // ⚠️ Requête SQL non préparée (potentiellement vulnérable)
    ))
    .execute(conn)
    .is_ok();

    if user_exists {
        HttpResponse::Ok().body("Login successful!")
    } else {
        HttpResponse::Unauthorized().body("Invalid credentials.")
    }
}

async fn login_page() -> impl Responder {
    HttpResponse::Ok()
        .insert_header(ContentType::html())
        .body(r#"
        <html><body>
            <h2>Login</h2>
            <form action="/login" method="post">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </body></html>
        "#)
}

async fn register_page() -> impl Responder {
    HttpResponse::Ok()
        .insert_header(ContentType::html())
        .body(r#"
        <html><body>
            <h2>Register</h2>
            <form action="/register" method="post">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Register</button>
            </form>
        </body></html>
        "#)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login_process))
            .route("/register", web::get().to(register_page))
            .route("/register", web::post().to(register_process))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
