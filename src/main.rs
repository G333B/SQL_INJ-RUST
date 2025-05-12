use actix_web::{web, App, HttpResponse, HttpServer, Responder, http::header::ContentType};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::RunQueryDsl;
use diesel::Insertable;
use serde::Deserialize;
use dotenvy::dotenv;
use std::env;

mod schema;

use crate::schema::{users, statuses};


#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)] 
struct NewUser<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::statuses)]
struct NewStatus<'a> {
    user_id: i32,
    content: &'a str,
}

#[derive(diesel::QueryableByName)]
struct UserIdRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
}

#[derive(diesel::QueryableByName)]
struct StatusRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    username: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    content: String,
}

#[derive(diesel::QueryableByName)]
struct UserIdResult {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
}



fn establish_connection() -> SqliteConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect("Error connecting to database")
}

fn create_user(conn: &mut SqliteConnection, new_user: &NewUser) -> QueryResult<usize> {
    diesel::insert_into(users::table)
        .values(new_user)
        .execute(conn)
}

#[derive(Deserialize)]
struct AuthData {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct StatusData {
    content: String,
}

#[derive(Deserialize)]
struct DeleteData {
    status_id: i32,
}
#[derive(Deserialize)]
struct ProfileQuery {
    user_id: i32,
}
use diesel::sql_types::{Text};


#[derive(QueryableByName)]
struct UsernameResult  {

    #[diesel(sql_type = Text)]
    username: String,
}

#[derive(Deserialize)]
struct UserIdQuery {
    user_id: i32,
}


async fn register_process(form: web::Form<AuthData>) -> impl Responder {
    let conn = &mut establish_connection();
    let new_user = NewUser {
        username: &form.username,
        password: &form.password, // ⚠️ Stocké en clair
    };

    match create_user(conn, &new_user) {
        Ok(_) => HttpResponse::Ok().body(format!("User {} registered!", form.username)),
        Err(_) => HttpResponse::InternalServerError().body("Failed to register user."),
    }
}

async fn login_process(form: web::Form<AuthData>) -> impl Responder {
    let conn = &mut establish_connection();

    let user = diesel::sql_query(format!(
        "SELECT id FROM users WHERE username = '{}' AND password = '{}'",
        form.username, form.password
    ))
    .load::<UserIdRow>(conn)
    .ok()
    .and_then(|mut users| users.pop());

    if let Some(user) = user {
        HttpResponse::SeeOther()
            .append_header(("Location", format!("/profile?user_id={}", user.id)))
            .finish()
    } else {
        HttpResponse::Unauthorized().body("Invalid credentials.")
    }
}

async fn show_login_form() -> impl Responder {
    HttpResponse::Ok().body(r#"
        <h1>Login</h1>
        <form action="/login" method="post">
            <input name="username" placeholder="Username">
            <input name="password" type="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
        <a href="/register">Register</a>
    "#)
}

async fn show_register_form() -> impl Responder {
    HttpResponse::Ok().body(r#"
        <h1>Register</h1>
        <form action="/register" method="post">
            <input name="username" placeholder="Username">
            <input name="password" type="password" placeholder="Password">
            <button type="submit">Register</button>
        </form>
        <a href="/login">Login</a>
    "#)
}


async fn profile_page(query: web::Query<ProfileQuery>) -> impl Responder {
    let conn = &mut establish_connection();

    // Trouve le nom d'utilisateur pour afficher "Welcome, XXX"
    let username = diesel::sql_query(format!(
        "SELECT username FROM users WHERE id = {}",
        query.user_id
    ))
    .load::<UsernameResult>(conn)
    .ok()
    .and_then(|mut r| r.pop())
    .map(|res| res.username)
    .unwrap_or("Unknown".into());

    let statuses: Vec<StatusRow> = diesel::sql_query(
        "SELECT statuses.id, users.username, statuses.content 
         FROM statuses JOIN users ON statuses.user_id = users.id"
    )
    .load(conn)
    .unwrap_or_default();

    let status_list = statuses.iter()
    .map(|status| {
        let delete_button = if status.username == username {
            format!(
                "<form action='/delete_status' method='post' style='display:inline'>
                    <input type='hidden' name='status_id' value='{}'>
                    <button type='submit'>❌</button>
                </form>",
                status.id
            )
        } else {
            String::new()
        };

        format!("<p><b>{}:</b> {} {}</p>", status.username, status.content, delete_button)
    })
    .collect::<String>();

    let html = format!(r#"
        <html>
        <body>
            <h2>Welcome, {}</h2>
            <h3>Post a status:</h3>
            <form action="/post_status?user_id={}" method="post">
                <textarea name="content" placeholder="Write something..." required></textarea>
                <button type="submit">Post</button>
            </form>
            <h3>All Statuses:</h3>
            {}
        </body>
        </html>
    "#, username, query.user_id, status_list);

    HttpResponse::Ok().insert_header(ContentType::html()).body(html)
}



async fn post_status(form: web::Form<StatusData>, query: web::Query<UserIdQuery>) -> impl Responder {
    println!("post_status() triggered with content: {}", form.content); // <-- Confirm it runs

    let conn = &mut establish_connection();
    let user_id = query.user_id;

    let new_status = NewStatus {
        user_id,
        content: &form.content,
    };

    let insert_result = diesel::insert_into(statuses::table)
        .values(&new_status)
        .execute(conn);

    match insert_result {
        Ok(_) => println!("Status inserted successfully."),
        Err(e) => println!("Error inserting status: {}", e),
    }

    HttpResponse::SeeOther()
        .append_header(("Location", format!("/profile?user_id={}", user_id)))
        .finish()
}


async fn delete_status(form: web::Form<DeleteData>, query: web::Query<AuthData>) -> impl Responder {
    let conn = &mut establish_connection();

    diesel::sql_query(format!(
        "DELETE FROM statuses WHERE id = {} AND user_id = (SELECT id FROM users WHERE username = '{}')",
        form.status_id, query.username
    ))
    .execute(conn)
    .ok();

    let user_id = diesel::sql_query(format!(
        "SELECT id FROM users WHERE username = '{}'",
        query.username
    ))
    .load::<UserIdResult>(conn)
    .ok()
    .and_then(|mut r| r.pop())
    .map(|res| res.id);
    
    if let Some(user_id) = user_id {
        HttpResponse::SeeOther()
            .append_header(("Location", format!("/profile?user_id={}", user_id)))
            .finish()
    } else {
        HttpResponse::InternalServerError().body("User not found")
    }
    

}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/login", web::get().to(show_login_form))
            .route("/register", web::get().to(show_register_form))
            .route("/login", web::post().to(login_process))
            .route("/register", web::post().to(register_process))
            .route("/profile", web::get().to(profile_page))
            .route("/post_status", web::post().to(post_status))
            .route("/delete_status", web::post().to(delete_status))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
