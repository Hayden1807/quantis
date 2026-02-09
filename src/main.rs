use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use sqlx::{
    postgres::PgPoolOptions, 
    PgPool,
    types::Uuid
};
use std::env;

use serde::{Deserialize, Serialize};

// Hasher
use argon2::{
    password_hash::{PasswordHasher, SaltString, PasswordHash, PasswordVerifier},
    Argon2,
};
use rand::rngs::OsRng;

// Routes
// Basic routes
#[get ("/health")]
async fn health(db: web::Data<PgPool>) -> impl Responder {
    // Ping DB
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(db.get_ref())
        .await
    {
        Ok(_) => HttpResponse::Ok().body("db_state : operational"),
        Err(_) => HttpResponse::ServiceUnavailable().body("db : Down"),
    }
}
#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}
#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}
#[get("/hey")]
async fn hey() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}
// ===== Sign up =====
#[post("/signup")]
async fn signup(db: web::Data<PgPool>, body: web::Json<SignupReq>) -> impl Responder {
    let email = normalize_email(&body.email);
    
    // 1. Check email validity
    if !basic_email_valid(&email) {
        return HttpResponse::BadRequest().body("Enter correct email");
    }
    if body.password.len() < 10 {
        return HttpResponse::BadRequest().body("Too short password (min 10)");
    }

    // 2. Hash password
    let salt = SaltString::generate(&mut OsRng); // salt for better security
    let argon2 = Argon2::default();
    let hash = match argon2.hash_password(body.password.as_bytes(), &salt) {
        Ok(ph) => ph.to_string(),
        Err(_) => return HttpResponse::InternalServerError().body("error while hashing password"),
    };

    // 3. Insert user in sql
    let res: Result<(Uuid, String), sqlx::Error> = sqlx::query_as(
r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email // avoid SELECT
        "#,
    )
    .bind(&email)
    .bind(&hash)
    .fetch_one(db.get_ref())
    .await;

    match res {
       Ok((id, email)) => HttpResponse::Created().json(SignupResp {id, email }),
       Err(sqlx::Error::Database(db_err)) => {
           // check if email already used
           let is_unique = db_err.code().as_deref() == Some("23505") // code
               || db_err.constraint() == Some("users_email_key"); // constraint

           if is_unique {
               HttpResponse::Conflict().body("email already exists")
           } else {
               HttpResponse::InternalServerError().body("db error")
           }
       }
       Err(e) => {
           eprintln!("Signup error {e:?}");
           HttpResponse::InternalServerError().body("db error")
       }

    }

}
// sign up struct
#[derive(Deserialize)]
struct SignupReq {
    email: String,
    password: String,
}
#[derive(Serialize)]
struct SignupResp {
    id: Uuid,
    email: String,
}

// ===== login =====
#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
}
#[derive(Serialize)]
struct LoginResp {
    id: Uuid,
    email: String,
}
#[post("/login")]
async fn login(db: web::Data<PgPool>, body: web::Json<LoginReq>) -> impl Responder {
    let email = normalize_email(&body.email);

    let user: Result<(Uuid, String, String), sqlx::Error> = sqlx::query_as(
        r#"
        SELECT id, email, password_hash
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(&email) // $1
    .fetch_one(db.get_ref())
    .await;

    // Check if email exists
    let (id, email, password_hash) = match user {
        Ok(v) => v,
        Err(sqlx::Error::RowNotFound) => return HttpResponse::Unauthorized().body("invalid credentials"),
        Err(e) => {
            eprintln!("LOGIN DB ERROR: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }    
    };
    // Parse password for argon2
    let parsed = match PasswordHash::new(&password_hash) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("LOGIN HASH PARSE ERROR: {e:?}");
            return HttpResponse::InternalServerError().body("hash error");
        }
    };
    // Check password
    // Vuln : Timing attack
    let argon2 = Argon2::default();
    if argon2
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    HttpResponse::Ok().json(LoginResp {id, email})
}


fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
fn basic_email_valid(email: &str) -> bool {
    let e = email.trim();
    e.contains('@') && e.contains('.') && e.len() <= 254
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // get env variables
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL missing");


    // build pool
    let pool = PgPoolOptions::new()
    .max_connections(10)
    .connect(&database_url)
    .await
    .expect("failed to connect to database");

    // Migration
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("failed to connect to database");

    let pool_data = web::Data::new(pool);

    HttpServer::new(move || {

        App::new()
            .app_data(pool_data.clone())
            .service(hello)
            .service(echo)
            .service(hey)
            .service(health)
            .service(signup)
            .service(login)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

