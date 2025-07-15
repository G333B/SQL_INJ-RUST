use actix_web::{web, App, HttpResponse, HttpServer, Responder, http::header::ContentType, http::header};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::RunQueryDsl;
use diesel::Insertable;
//use serde::{Deserialize, Serialize};
use dotenvy::dotenv;
use std::env;


mod schema;

use crate::schema::{users, statuses, infos};



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
#[allow(dead_code)]
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

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct AuthData {
    username: String,
    password: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct StatusData {
    content: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DeleteData {
    status_id: i32,
}
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProfileQuery {
    user_id: i32,
    deleted: Option<i32>,
}
use diesel::sql_types::{Text};


#[derive(QueryableByName)]
struct UsernameResult  {

    #[diesel(sql_type = Text)]
    username: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct UserIdQuery {
    user_id: i32,
}



use diesel::QueryableByName;

#[derive(Queryable, Selectable, QueryableByName)]
#[diesel(table_name = crate::schema::infos)]
pub struct Info {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub user_id: i32,

    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub full_name: Option<String>,

    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub address: Option<String>,

    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
    pub age: Option<i32>,

    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub country: Option<String>,

    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub dog_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct InfoForm {
    full_name: Option<String>,
    address: Option<String>,
    age: Option<i32>,
    country: Option<String>,
    dog_name: Option<String>,
}

#[derive(Insertable)]
#[diesel(table_name = infos)]
pub struct NewInfo<'a> {
    pub user_id: i32,
    pub full_name: Option<&'a str>,
    pub address: Option<&'a str>,
    pub age: Option<i32>,
    pub country: Option<&'a str>,
    pub dog_name: Option<&'a str>,
}


#[derive(AsChangeset)]
#[diesel(table_name = crate::schema::infos)]
pub struct InfoChangeset {
    pub full_name: Option<String>,
    pub address: Option<String>,
    pub age: Option<i32>,
    pub country: Option<String>,
    pub dog_name: Option<String>,
}


async fn register_process(form: web::Form<AuthData>) -> impl Responder {
    let conn = &mut establish_connection();
    let new_user = NewUser {
        username: &form.username,
        password: &form.password, // pas hashé exprès
    };

    match create_user(conn, &new_user) {
        Ok(_) => {
            HttpResponse::SeeOther()
                .insert_header((header::LOCATION, "/login"))
                .finish()
        },
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
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f0f2f5;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .form-container {
                background: white;
                padding: 2rem;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                width: 320px;
                text-align: center;
            }
            input {
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 1rem;
            }
            button {
                width: 100%;
                padding: 10px;
                background: #007bff;
                border: none;
                color: white;
                font-size: 1rem;
                border-radius: 4px;
                cursor: pointer;
                margin-top: 10px;
            }
            button:hover {
                background: #0056b3;
            }
            a {
                display: block;
                margin-top: 15px;
                color: #007bff;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
            h1 {
                margin-bottom: 20px;
            }
        </style>
        <div class="form-container">
            <h1>Login</h1>
            <form action="/login" method="post">
                <input name="username" placeholder="Username" required>
                <input name="password" type="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <a href="/register">Register</a>
        </div>
    "#)
}

async fn show_register_form() -> impl Responder {
    HttpResponse::Ok().body(r#"
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f0f2f5;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .form-container {
                background: white;
                padding: 2rem;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                width: 320px;
                text-align: center;
            }
            input {
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 1rem;
            }
            button {
                width: 100%;
                padding: 10px;
                background: #28a745;
                border: none;
                color: white;
                font-size: 1rem;
                border-radius: 4px;
                cursor: pointer;
                margin-top: 10px;
            }
            button:hover {
                background: #1e7e34;
            }
            a {
                display: block;
                margin-top: 15px;
                color: #007bff;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
            h1 {
                margin-bottom: 20px;
            }
        </style>
        <div class="form-container">
            <h1>Register</h1>
            <form action="/register" method="post">
                <input name="username" placeholder="Username" required>
                <input name="password" type="password" placeholder="Password" required>
                <button type="submit">Register</button>
            </form>
            <a href="/login">Login</a>
        </div>
    "#)
}



async fn profile_page(query: web::Query<ProfileQuery>) -> impl Responder {
    let conn = &mut establish_connection();
// afficher nom utilisateur 

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

    let deletion_message = if query.deleted == Some(1) {
    "<p style='color:green;'>✅ Statut supprimé avec succès.</p>".to_string()
    } else {
        "".to_string()
    };
    let my_infos_link = format!(
    "<a href=\"/my_infos?user_id={}\">📋 Mes infos perso</a><br><br>",
    query.user_id
)   ;


    let status_list = statuses.iter()
    .map(|status| {
        let delete_button = if status.username == username {
        format!(
            "<form action='/delete_status?user_id={}' method='post' style='display:inline'>
                <input type='hidden' name='status_id' value='{}'>
                <button type='submit'>Supprimer mon poste ❌</button>
            </form>",
            query.user_id, status.id
        )

        } else {
            String::new()
        };

        format!("<p><b>{}:</b> {} {}</p>", status.username, status.content, delete_button)
    })
    .collect::<String>();

let html = format!(r#"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Mon Réseau Social Rust</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 700px;
            margin: 30px auto;
            padding: 20px;
            background-color: #f9f9f9;
            color: #333;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h2, h3 {{
            color:rgb(96, 91, 236);
        }}
        form {{
            margin-bottom: 20px;
        }}
        textarea {{
            width: 100%;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ccc;
            resize: vertical;
        }}
        button {{
            background-color:rgb(96, 91, 236);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
        }}
        button:hover {{
            background-color:rgb(69, 78, 160);
        }}
        .status {{
            background-color: #fff;
            padding: 10px 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid rgb(69, 78, 160);
        }}
        }}
        .delete-form {{
            display: inline;
        }}
        .message {{
            color: green;
            background: #e6ffe6;
            padding: 8px;
            border: 1px solid #b3ffb3;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <h2>Bienvenue, {} !</h2>
    {}
    {}
    <h3>Poste un truc:</h3>
    <form action="/post_status?user_id={}" method="post">
        <textarea name="content" placeholder="Tu peux écrire ici..." required></textarea><br>
        <button type="submit">Poster</button>
    </form>
   
    <h3>Statuts des utilisateurs:</h3>
    {}

    <form action="/logout" method="get">
        <button type="submit">Déconnexion</button>
    </form>

</body>
</html>
"#, username, my_infos_link, deletion_message, query.user_id, status_list);


    HttpResponse::Ok().insert_header(ContentType::html()).body(html)
}



async fn post_status(form: web::Form<StatusData>, query: web::Query<UserIdQuery>) -> impl Responder {
    println!("post_status() triggered with content: {}", form.content); 

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


async fn delete_status(form: web::Form<DeleteData>, query: web::Query<UserIdQuery>) -> impl Responder {
    let conn = &mut establish_connection();

    let _ = diesel::sql_query(format!(
        "DELETE FROM statuses WHERE id = {} AND user_id = {}",
        form.status_id, query.user_id
    ))
    .execute(conn)
    .unwrap_or(0);

    HttpResponse::SeeOther()
        .append_header(("Location", format!("/profile?user_id={}&deleted=1", query.user_id)))
        .finish()
}


async fn show_info_page(query: web::Query<UserIdQuery>) -> impl Responder {
    let conn = &mut establish_connection();
    let user_id_v = query.user_id;

    let existing_info: Option<Info> = diesel::sql_query(format!(
        "SELECT * FROM infos WHERE user_id = {}",
        user_id_v 
    ))
    .load::<Info>(conn)
    .ok()
    .and_then(|mut r| r.pop());

    let html = format!(
        r#"
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background: #f0f2f5;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                .form-container {{
                    background: white;
                    padding: 2rem;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    width: 360px;
                    box-sizing: border-box;
                }}
                label {{
                    display: block;
                    margin-bottom: 6px;
                    font-weight: bold;
                    color: #333;
                }}
                input {{
                    width: 100%;
                    padding: 8px;
                    margin-bottom: 15px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    font-size: 1rem;
                }}
                input[type="number"] {{
                    -moz-appearance: textfield; /* remove spinner in Firefox */
                }}
                button {{
                    width: 100%;
                    padding: 10px;
                    background: #007bff;
                    border: none;
                    color: white;
                    font-size: 1.1rem;
                    border-radius: 4px;
                    cursor: pointer;
                }}
                button:hover {{
                    background: #0056b3;
                }}
                a {{
                    display: block;
                    margin-top: 15px;
                    text-align: center;
                    color: #007bff;
                    text-decoration: none;
                    font-weight: 600;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
                h2 {{
                    text-align: center;
                    color: #222;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="form-container">
                <h2>Mes infos perso</h2>
                <form action="/submit_infos?user_id={user_id}" method="post">
                    <label>Nom complet:</label>
                    <input name="full_name" value="{full_name}" placeholder="Votre nom complet">

                    <label>Adresse:</label>
                    <input name="address" value="{address}" placeholder="Votre adresse">

                    <label>Âge:</label>
                    <input name="age" type="number" value="{age}" placeholder="Votre âge">

                    <label>Pays:</label>
                    <input name="country" value="{country}" placeholder="Votre pays">

                    <label>Nom de mon chien:</label>
                    <input name="dog_name" value="{dog_name}" placeholder="Nom de votre chien">

                    <button type="submit">Enregistrer</button>
                </form>
                <a href="/profile?user_id={user_id}">⬅ Retour au profil</a>
            </div>
        </body>
        </html>
        "#,
        user_id = user_id_v,
        full_name = existing_info.as_ref().and_then(|i| i.full_name.clone()).unwrap_or_default(),
        address = existing_info.as_ref().and_then(|i| i.address.clone()).unwrap_or_default(),
        age = existing_info
            .as_ref()
            .and_then(|i| i.age.map(|n| n.to_string()))
            .unwrap_or_default(),
        country = existing_info.as_ref().and_then(|i| i.country.clone()).unwrap_or_default(),
        dog_name = existing_info.as_ref().and_then(|i| i.dog_name.clone()).unwrap_or_default(),
    );

    HttpResponse::Ok().insert_header(ContentType::html()).body(html)
}

async fn submit_info(
    query: web::Query<UserIdQuery>,
    form: web::Form<InfoForm>,
) -> impl Responder {
    let conn = &mut establish_connection();
    let user_id_val = query.user_id;

    use crate::schema::infos::dsl::*;

    let _existing_info: Option<Info> = infos
        .filter(user_id.eq(user_id_val))
        .first::<Info>(conn)
        .optional()
        .expect("Error loading info");

    let new_info = NewInfo {
        user_id: user_id_val,
        full_name: form.full_name.as_deref(),
        address: form.address.as_deref(),
        age: form.age,
        country: form.country.as_deref(),
        dog_name: form.dog_name.as_deref(),
    };

    let existing = diesel::sql_query(format!("SELECT * FROM infos WHERE user_id = {}", user_id_val))
        .load::<Info>(conn)
        .ok()
        .and_then(|mut r| r.pop());

    let changeset = InfoChangeset {
        full_name: new_info.full_name.map(|s| s.to_string()),
        address: new_info.address.map(|s| s.to_string()),
        age: new_info.age,
        country: new_info.country.map(|s| s.to_string()),
        dog_name: new_info.dog_name.map(|s| s.to_string()),
    };

    if existing.is_some() {
        // Update
        diesel::update(crate::schema::infos::table.find(user_id_val))
            .set(changeset)
            .execute(conn)
            .ok();
    } else {
        // Insert
        diesel::insert_into(crate::schema::infos::table)
            .values(&new_info)
            .execute(conn)
            .ok();
    }

    HttpResponse::SeeOther()
        .append_header(("Location", format!("/my_infos?user_id={}", user_id_val)))
        .finish()
}


async fn logout() -> impl Responder {
    HttpResponse::SeeOther()
        .append_header(("Location", "/login"))
        .finish()
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
            .route("/my_infos", web::get().to(show_info_page))
            .route("/submit_infos", web::post().to(submit_info))
            .route("/logout", web::get().to(logout))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

// TESTS UNITAIRES

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::connection::SimpleConnection;
    // La ligne suivante peut être commentée ou supprimée car MigrationConnection n'est pas utilisée directement
    // use diesel::migration::MigrationConnection;
    use diesel::RunQueryDsl;
    use diesel::sql_query;
    use crate::schema::{users, statuses};

    use actix_web::{test, web, App};
    use actix_web::http::header;
    use actix_web::http::StatusCode; // Gardé car utilisé dans les tests restants

    // Une fonction utilitaire pour établir une connexion de test en mémoire
    fn establish_test_connection() -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:")
            .expect("Error connecting to in-memory database");

        // Appliquez le schéma à la base de données en mémoire.
        conn.batch_execute(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
            CREATE TABLE statuses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE infos (
                user_id INTEGER PRIMARY KEY,
                full_name TEXT,
                address TEXT,
                age INTEGER,
                country TEXT,
                dog_name TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            "
        ).unwrap();
        conn
    }

    // Un wrap pour la fonction create_user qui utilise la connexion de test
    fn create_test_user(conn: &mut SqliteConnection, username: &str, password: &str) -> QueryResult<usize> {
        let new_user = NewUser { username, password };
        create_user(conn, &new_user)
    }

    #[actix_web::test]
    async fn test_main_connection_successful() {
        // Ce test vérifiera votre connexion normale (via .env)
        let result = std::panic::catch_unwind(|| {
            establish_connection();
        });
        assert!(result.is_ok(), "Failed to establish connection to database, check your DATABASE_URL in .env");
    }

    #[actix_web::test]
    async fn test_create_user_successful() {
        let mut conn = establish_test_connection();
        let result = create_test_user(&mut conn, "testuser", "testpassword");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // 1 ligne insérée

        let user_count: i64 = users::table
            .count()
            .get_result(&mut conn)
            .expect("Error loading user count");
        assert_eq!(user_count, 1);
    }

    #[actix_web::test]
    async fn test_create_user_duplicate_fails() {
        let mut conn = establish_test_connection();
        create_test_user(&mut conn, "testuser", "testpassword").unwrap();

        let result = create_test_user(&mut conn, "testuser", "anotherpassword");
        assert!(result.is_err()); 
    }





    #[actix_web::test]
    async fn test_login_process_failure_invalid_credentials() {
        // Crée une instance de l'application pour le test
        let app = test::init_service(App::new().route("/login", web::post().to(login_process))).await;

        let req = test::TestRequest::post()
            .uri("/login")
            .set_form(&AuthData {
                username: "nonexistent".to_string(),
                password: "wrongpassword".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED); // Code 401
    }

    #[actix_web::test]
    async fn test_delete_status_success() {
        let mut conn = establish_test_connection();
        create_test_user(&mut conn, "deleteuser", "deletepassword").unwrap();
        let user_id_row: UserIdRow = sql_query("SELECT id FROM users WHERE username = 'deleteuser'")
            .load::<UserIdRow>(&mut conn)
            .unwrap()
            .pop()
            .unwrap();
        let user_id = user_id_row.id;

        // Insérer un statut à supprimer (sans .to_string() car content est &str)
        let new_status = NewStatus {
            user_id,
            content: "This status will be deleted.",
        };
        diesel::insert_into(statuses::table)
            .values(&new_status)
            .execute(&mut conn)
            .unwrap();

        let status_id_row: UserIdRow = sql_query(format!("SELECT id FROM statuses WHERE user_id = {}", user_id))
            .load::<UserIdRow>(&mut conn)
            .unwrap()
            .pop()
            .unwrap();
        let status_id = status_id_row.id;

        // Crée une instance de l'application pour le test
        let app = test::init_service(App::new().route("/delete_status", web::post().to(delete_status))).await;

        let req = test::TestRequest::post()
            .uri(format!("/delete_status?user_id={}", user_id).as_str())
            .set_form(&DeleteData { status_id })
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER); // Code 303
        let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, format!("/profile?user_id={}&deleted=1", user_id));

        // Vérifiez que le statut a été supprimé
        let mut check_conn = establish_test_connection();
        let status_count: i64 = statuses::table
            .count()
            .get_result(&mut check_conn)
            .expect("Error loading status count");
        assert_eq!(status_count, 0);
    }

    #[actix_web::test]
    async fn test_logout_redirects() {
        // Crée une instance de l'application pour le test
        let app = test::init_service(App::new().route("/logout", web::get().to(logout))).await;
        let req = test::TestRequest::get().uri("/logout").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER); // Code 303
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/login");
    }
}