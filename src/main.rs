use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use sqlx::{
    postgres::PgPoolOptions,
    PgPool,
    types::Uuid,
};
use std::env;

use serde::{Deserialize, Serialize};

// Hasher
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;

// Token generator
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use time::{Duration, OffsetDateTime};

// Cookies
use actix_web::cookie::{Cookie, SameSite};
use actix_web::cookie::time::Duration as CookieDuration;
use time::Duration as TimeDuration; // as to avoid conflict

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

// === login ===
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

// === token ===
#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_encoding: EncodingKey,
    jwt_decoding: DecodingKey,
    auth_cookie_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // User ID
    email: String,
    exp: usize, // expiration
}

#[derive(Serialize)]
struct AuthResp {
    token: String,
    id: Uuid,
    email: String,
}

#[derive(Deserialize)]
struct CreatePlaceReq {
    name: String,
}

#[derive(Serialize)]
struct PlaceResp {
    id: Uuid,
    name: String,
}

#[derive(Deserialize)]
struct AddDataReq {
    place_id: Uuid,
    value: f64,
    unit: Option<String>,
    recorded_at: Option<String>,
}

#[derive(Serialize)]
struct ConsumptionResp {
    id: Uuid,
    place_id: Uuid,
    value: f64,
    unit: String,
    recorded_at: String,
}

// == functions ==
fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
fn basic_email_valid(email: &str) -> bool {
    let e = email.trim();
    e.contains('@') && e.contains('.') && e.len() <= 254
}

fn make_jwt(state: &AppState, user_id: Uuid, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = (OffsetDateTime::now_utc() + TimeDuration::days(7)).unix_timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        exp,
    };
    encode(&Header::default(), &claims, &state.jwt_encoding)
}

// Helper Auth
fn require_auth(req: &HttpRequest, state: &AppState) -> Result<Claims, HttpResponse> {
    let token_opt = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    let token = if let Some(t) = token_opt {
        t.to_string()
    } else if let Some(c) = req.cookie(&state.auth_cookie_name) {
        c.value().to_string()
    } else {
        return Err(HttpResponse::Unauthorized().body("Missing token"));
    };

    let data = decode::<Claims>(&token, &state.jwt_decoding, &Validation::default())
        .map_err(|_| HttpResponse::Unauthorized().body("Invalid token"))?;

    Ok(data.claims)
}

// Store Token
fn is_request_secure(req: &HttpRequest) -> bool {
    matches!(
        req.headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok()),
        Some("HttpServer")
    )
}
fn build_auth_cookie(state: &AppState, token: &str, secure: bool) -> Cookie<'static> {
    Cookie::build(state.auth_cookie_name.clone(), token.to_string())
        .path("/api")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(secure)
        .max_age(CookieDuration::days(7))
        .finish()
} 

// Routes
// Basic routes
#[get("/health")]
async fn health(state: web::Data<AppState>) -> impl Responder {
    // Ping DB
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
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
async fn signup(req: HttpRequest, state: web::Data<AppState>, body: web::Json<SignupReq>) -> impl Responder {
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
        RETURNING id, email
        "#,
    )
    .bind(&email)
    .bind(&hash)
    .fetch_one(&state.db)
    .await;

    match res {
        Ok((id, email_db)) => {
            // token (maintenant on a id + email_db)
            let token = match make_jwt(state.get_ref(), id, &email_db) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("JWT ERROR: {e:?}");
                    return HttpResponse::InternalServerError().body("jwt error");
                }
            };

            let cookie = build_auth_cookie(state.get_ref(), &token, false);
            HttpResponse::Created()
                .cookie(cookie)
                .json(AuthResp { token, id, email: email_db })
        }
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

#[post("/login")]
async fn login(req: HttpRequest, state: web::Data<AppState>, body: web::Json<LoginReq>) -> impl Responder {
    let email = normalize_email(&body.email);

    let user: Result<(Uuid, String, String), sqlx::Error> = sqlx::query_as(
        r#"
        SELECT id, email, password_hash
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(&email) // $1
    .fetch_one(&state.db)
    .await;

    // Check if email exists
    let (id, email_db, password_hash) = match user {
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
    // Vuln : Timing attack (on pourra améliorer après)
    let argon2 = Argon2::default();
    if argon2
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    // token
    let token = match make_jwt(state.get_ref(), id, &email_db) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("JWT ERROR: {e:?}");
            return HttpResponse::InternalServerError().body("jwt error");
        }
    };
    
    let cookie = build_auth_cookie(state.get_ref(), &token, false);
    HttpResponse::Ok()
        .cookie(cookie)
        .json(AuthResp { token, id, email: email_db })
}

// dashboard
#[get("/me")]
async fn me(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    match require_auth(&req, state.get_ref()) {
        Ok(claims) => HttpResponse::Ok().json(claims),
        Err(resp) => resp,
    }
}
#[post("/places")]
async fn create_place(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CreatePlaceReq>) -> impl Responder {
    // get cookie
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(e) => return e,
    };
    
    // get userID
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token"),
    };

    // Check name validity
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 80 {
        return HttpResponse::BadRequest().body("invalid name");
    }

    // Insert into db
    let res: Result<(Uuid, String), sqlx::Error> = sqlx::query_as(
        r#"
        INSERT INTO places (user_id, name)
        VALUES ($1, $2)
        RETURNING id, name
        "#
    )
    .bind(user_id)
    .bind(&name)
    .fetch_one(&state.db)
    .await;

    // DB response
    match res {
        Ok((id, name)) => HttpResponse::Created().json(PlaceResp {id, name}),
        Err(sqlx::Error::Database(db_err)) => {
            let is_unique = db_err.code().as_deref() == Some("23505");
            if is_unique {
                HttpResponse::Conflict().body("place name already exists")
            } else {
                eprintln!("Database Error when creating place : {db_err:?}");
                HttpResponse::InternalServerError().body("db error")
            }
        }
        Err(e) => {
            eprintln!("Database Error when creating place: {e:?} ");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}


// destroy cookie
#[post("/logout")]
async fn logout(req:HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let mut c = Cookie::build(state.auth_cookie_name.clone(), "")
        .path("/api")
        .http_only(true)
        .same_site(SameSite::Strict)
        //.secure(is_request_secure(&req)) false for a prototype
        .secure(false)
        .finish();

    c.make_removal();
    HttpResponse::Ok().cookie(c).body("ok")
}

#[post("/add-data")]
async fn add_data(req: HttpRequest, state: web::Data<AppState>, body: web::Json<AddDataReq>) -> impl Responder {
    // get cookie
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token"),
    };

    // Check that selected place is owned by connected user
    let owns_place = sqlx::query_scalar::<_, i32>(
        r#"SELECT 1 FROM places WHERE id = $1 AND user_id = $2"#,
    )
    .bind(body.place_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await;

    match owns_place {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("ADD-DATA owns_place error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    }

    // Check values validity
    if !body.value.is_finite() {
        return HttpResponse::BadRequest().body("invalid value");
    }
    let unit = body.unit.clone().unwrap_or_else(|| "kwh".to_string());
    let unit = unit.trim().to_lowercase();
    if unit.is_empty() || unit.len() > 16 {
        return HttpResponse::BadRequest().body("invalid unit");
    }

    // Insert into Database
    let res: Result<(Uuid, Uuid, f64, String, String), sqlx::Error> = sqlx::query_as(
        r#"
        INSERT INTO consumptions (place_id, recorded_at, value, unit)
        VALUES ($1, COALESCE($2::timestamptz, now()), $3, $4)
        RETURNING id, place_id, value, unit, recorded_at::text
        "#,
    )
    .bind(body.place_id)
    .bind(body.recorded_at.as_deref())
    .bind(body.value)
    .bind(&unit)
    .fetch_one(&state.db)
    .await;

    // get db result
    match res {
        Ok((id, place_id, value, unit, recorded_at)) => HttpResponse::Created().json(ConsumptionResp { id, place_id, value, unit, recorded_at }),
        Err(e) => {
            eprintln!("ADD-DATA insert error: {e:?}");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // get env variables
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL missing");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET missing");

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
        .expect("failed to run migrations");

    // AppState (DB + JWT keys)
    let state = AppState {
        db: pool,
        jwt_encoding: EncodingKey::from_secret(jwt_secret.as_bytes()),
        jwt_decoding: DecodingKey::from_secret(jwt_secret.as_bytes()),
        auth_cookie_name: "access_token".to_string(),
    };
    let state_data = web::Data::new(state);

    HttpServer::new(move || {
        App::new()
            .app_data(state_data.clone())
            .service(hello)
            .service(echo)
            .service(hey)
            .service(health)
            .service(signup)
            .service(login)
            .service(me)
            .service(logout)
            .service(create_place)
            .service(add_data)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

