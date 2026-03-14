use actix_web::{delete, get, post, put, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
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
use time::OffsetDateTime;

// Cookies
use actix_web::cookie::{Cookie, SameSite};
use actix_web::cookie::time::Duration as CookieDuration;
use time::Duration as TimeDuration; // as to avoid conflict
use time::format_description::well_known::Rfc3339;

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
    energy: String,
}

#[derive(Serialize)]
struct ConsumptionResp {
    id: Uuid,
    place_id: Uuid,
    value: f64,
    unit: String,
    energy: String,
    recorded_at: String,
}

// Goal configuration
#[derive(Deserialize)]
struct SetGoalReq {
    energy: String,
    weekly_kwh: f64,
    monthly_kwh: f64,
}

#[derive(Serialize, sqlx::FromRow)]
struct GoalRow {
    energy: String,
    weekly_target_kwh: f64,
    monthly_target_kwh: f64,
}

#[derive(Deserialize)]
struct PlacePath {
    place_id: Uuid,
}

#[derive(Serialize, sqlx::FromRow)]
struct PlaceRow {
    id: Uuid,
    name: String,
}

#[derive(Deserialize)]
struct SummaryQuery {
    place_id: Uuid,
    period: String, // week || mounth
}

#[derive(Serialize, sqlx::FromRow)]
struct EnergySummary {
    energy: String,
    total_kwh: f64,
    goal_kwh: f64,
    delta_kwh: f64,
    last_recorded_at: Option<String>,
}

#[derive(Serialize)]
struct SummaryResp {
    period: String,
    items: Vec<EnergySummary>,
}

#[derive(Deserialize)]
struct SeriesQuery {
    place_id: Uuid,
    energy: String,
    period: String,
}
#[derive(Serialize)]
struct SeriesResp {
    labels: Vec<String>,
    values: Vec<f64>,
}

#[derive(Deserialize)]
struct RecentQuery {
    place_id: Uuid,
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
struct RecentRow {
    recorded_at: String,
    energy: String,
    value: f64,
    unit: String,
    status: String,
}
#[derive(Serialize)]
struct RecentResp {
    items: Vec<RecentRow>,
}

#[derive(Deserialize)]
struct AlertsQuery {
    place_id: Uuid,
    period: String,
}

#[derive(sqlx::FromRow)]
struct AlertMetricsRow {
    energy: String,
    current_month_total_kwh: f64,
    goal_kwh: f64,
}

#[derive(Serialize)]
struct AlertItem {
    id: String,
    severity: String,
    kind: String,
    title: String,
    message: String,
    energy: Option<String>,
    period: String,
    value_kwh: Option<f64>,
    goal_kwh: Option<f64>,
    action_label: Option<String>,
    action_href: Option<String>,
}

#[derive(Serialize)]
struct AlertsResp {
    items: Vec<AlertItem>,
}

// === History ===
#[derive(Deserialize)]
struct HistoryQuery {
    place_id: Uuid,
    from: Option<String>,
    to: Option<String>,
    energy: Option<String>,
    status: Option<String>,
    page: Option<i64>,
    limit: Option<i64>,
    sort: Option<String>,
}
#[derive(Serialize, sqlx::FromRow)]
struct HistoryRow {
    day: String,        // YYYY-MM-DD
    energy: String,
    total_kwh: f64,
    goal_kwh: f64,
    status: String,     // ok / watch / alert
}
#[derive(Serialize)]
struct HistoryResp {
    page: i64,
    limit: i64,
    total: i64,
    items: Vec<HistoryRow>,
}

// == functions ==
fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
fn basic_email_valid(email: &str) -> bool {
    let e = email.trim();
    e.contains('@') && e.contains('.') && e.len() <= 254
}

fn green_tip_for_energy(energy: &str, seed: u8) -> &'static str {
    let elec_tips = [
        "gardez le même rythme sur les appareils les plus utilisés",
        "pensez à couper les appareils en veille",
        "gardez vos habitudes actuelles aux heures de forte utilisation",
    ];
    let gas_tips = [
        "gardez vos réglages actuels pour le chauffage et l'eau chaude",
        "évitez les chauffes inutiles pendant les périodes creuses",
        "gardez vos réglages actuels si le confort vous convient",
    ];

    let tips = if energy == "gas" { &gas_tips } else { &elec_tips };
    let idx = (seed as usize) % tips.len();
    tips[idx]
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
        .path("/")
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

#[get("/places")]
async fn list_places(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // authentification
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token"),
    };

    let rows: Result<Vec<PlaceRow>, sqlx::Error> = sqlx::query_as("SELECT id, name FROM places WHERE user_id=$1 ORDER BY created_at DESC")
        .bind(user_id)
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(v) => HttpResponse::Ok().json(v),
        Err(e) => {
            eprintln!("LIST PLACES ERROR: {e:?}");
            HttpResponse::InternalServerError().body("db_error")
        }
    }
}

#[put("/places/{place_id}")]
async fn update_place(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<PlacePath>,
    body: web::Json<CreatePlaceReq>,
) -> impl Responder {
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token"),
    };

    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 80 {
        return HttpResponse::BadRequest().body("invalid name");
    }

    let res: Result<(Uuid, String), sqlx::Error> = sqlx::query_as(
        r#"
        UPDATE places
        SET name = $3
        WHERE id = $1 AND user_id = $2
        RETURNING id, name
        "#,
    )
    .bind(path.place_id)
    .bind(user_id)
    .bind(&name)
    .fetch_one(&state.db)
    .await;

    match res {
        Ok((id, name)) => HttpResponse::Ok().json(PlaceResp { id, name }),
        Err(sqlx::Error::RowNotFound) => HttpResponse::NotFound().body("place not found"),
        Err(sqlx::Error::Database(db_err)) => {
            let is_unique = db_err.code().as_deref() == Some("23505");
            if is_unique {
                HttpResponse::Conflict().body("place name already exists")
            } else {
                eprintln!("UPDATE PLACE error: {db_err:?}");
                HttpResponse::InternalServerError().body("db error")
            }
        }
        Err(e) => {
            eprintln!("UPDATE PLACE error: {e:?}");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}

#[delete("/places/{place_id}")]
async fn delete_place(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<PlacePath>,
) -> impl Responder {
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token"),
    };

    let deleted = sqlx::query(
        r#"
        DELETE FROM places
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(path.place_id)
    .bind(user_id)
    .execute(&state.db)
    .await;

    match deleted {
        Ok(result) if result.rows_affected() > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("DELETE PLACE error: {e:?}");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}

// destroy cookie
#[post("/logout")]
async fn logout(req:HttpRequest, state: web::Data<AppState>) -> impl Responder {
    let mut c = Cookie::build(state.auth_cookie_name.clone(), "")
        .path("/")
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

    // Check energy kind and validity
    let energy = body.energy.trim().to_lowercase();
    if !matches!(energy.as_str(), "electricity" | "gas") {
        return HttpResponse::BadRequest().body("invalid energy type");
    }

    let now = OffsetDateTime::now_utc();
    let recorded_at = if let Some(s) = body.recorded_at.as_deref() {
        let parsed = match OffsetDateTime::parse(s, &Rfc3339) {
            Ok(v) => v,
            Err(_) => return HttpResponse::BadRequest().body("invalid recorded_at (use RFC3339)"),
        };
        if parsed > now {
            return HttpResponse::BadRequest().body("future date not allowed");
        }
        parsed
    } else {
        now
    };

    // Insert into Database
    let res: Result<(Uuid, Uuid, f64, String, String, String), sqlx::Error> = sqlx::query_as(
        r#"
        INSERT INTO consumptions (place_id, recorded_at, day, value, unit, energy)
        VALUES ($1, $2, ($2)::date, $3, $4, $5::energy_type)
        ON CONFLICT (place_id, energy, day)
        DO UPDATE SET
            recorded_at = EXCLUDED.recorded_at,
            value = EXCLUDED.value,
            unit = EXCLUDED.unit
        RETURNING id, place_id, value, unit, energy::text,recorded_at::text
        "#,
    )
    .bind(body.place_id)
    .bind(recorded_at)
    .bind(body.value)
    .bind(&unit)
    .bind(&energy)
    .fetch_one(&state.db)
    .await;

    // get db result
    match res {
        Ok((id, place_id, value, unit, energy,recorded_at)) => HttpResponse::Created().json(ConsumptionResp { id, place_id, value, unit, energy, recorded_at }),
        Err(e) => {
            eprintln!("ADD-DATA insert error: {e:?}");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}

#[get("places/{place_id}/goals")]
async fn get_goals(req:HttpRequest, state: web::Data<AppState>, path: web::Path<PlacePath>,) -> impl Responder {
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };

    let owns = sqlx::query_scalar::<_, i32>("SELECT 1 FROM places WHERE id=$1 AND user_id=$2")
        .bind(path.place_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match owns {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("GET GOALS owns error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    }

    let rows: Result<Vec<GoalRow>, sqlx::Error> = sqlx::query_as(
        r#"
        SELECT energy::text as energy, weekly_target_kwh, monthly_target_kwh
        FROM place_goals
        WHERE place_id = $1
        ORDER BY energy
        "#
    )
    .bind(path.place_id)
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(v) => HttpResponse::Ok().json(v),
        Err(e) => {
            eprintln!("GET GOALS error: {e:?}");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}

#[put("/places/{place_id}/goals")]
async fn set_goal(req: HttpRequest, state: web::Data<AppState>, path: web::Path<PlacePath>, body: web::Json<SetGoalReq>,) -> impl Responder {
    
    // authentification
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token subject"),
    };

    // owns place
    let owns = sqlx::query_scalar::<_, i32>("SELECT 1 FROM places WHERE id=$1 AND user_id=$2")
        .bind(path.place_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match owns {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("SET GOAL owns error: {e:?}");
            return HttpResponse::InternalServerError().body("db_error")
        }
    }

    // check goal and unit validity
    let energy = body.energy.trim().to_lowercase();
    if !matches!(energy.as_str(), "electricity" | "gas") {
        return HttpResponse:: BadRequest().body("invalid energy (electricity | gas)");
    }
    if !body.weekly_kwh.is_finite() || body.weekly_kwh < 0.0 || !body.monthly_kwh.is_finite() || body.monthly_kwh < 0.0 { //why not weekly is finit
        return HttpResponse::BadRequest().body("invalid goal values");    
    }

    // Insert into database
    let row: Result<GoalRow, sqlx::Error> = sqlx::query_as(
        r#"
        INSERT INTO place_goals (place_id, energy, weekly_target_kwh, monthly_target_kwh, updated_at)
        VALUES ($1, $2::energy_type, $3, $4, now())
        ON CONFLICT (place_id, energy)
        DO UPDATE SET
            weekly_target_kwh = EXCLUDED.weekly_target_kwh,
            monthly_target_kwh = EXCLUDED.monthly_target_kwh,
            updated_at = now()
        RETURNING energy::text as energy, weekly_target_kwh, monthly_target_kwh
        "#
    )
    .bind(path.place_id)
    .bind(&energy)
    .bind(body.weekly_kwh)
    .bind(body.monthly_kwh)
    .fetch_one(&state.db)
    .await;

    match row {
        Ok(g) => HttpResponse::Ok().json(g),
        Err(e) => {
            eprintln!("SET GOAL error: {e:?}");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}

// === Dashboard ===
#[get("/dashboard/summary")]
async fn dashboard_summary(req: HttpRequest, state: web::Data<AppState>, q: web::Query<SummaryQuery>) -> impl Responder {
    // authentification
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token"),
    };

    // owns
    let owns = sqlx::query_scalar::<_, i32>("SELECT 1 FROM places WHERE id=$1 AND user_id=$2")
        .bind(q.place_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match owns {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("SUMMARY owns error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    }

    let period = q.period.trim().to_lowercase();
    if !matches!(period.as_str(), "week" | "month") {
        return HttpResponse::BadRequest().body("period must be week or month");
    }

    // interval + goal
    let (interval_sql, goal_col) = if period == "week" {
        ("interval '7 days'", "weekly_target_kwh")
    } else {
        ("interval '30 days'", "monthly_target_kwh")
    };

    let sql = format!(r#"
      WITH totals AS (
        SELECT
          c.energy::text AS energy,
          COALESCE(SUM(c.value),0)::float8 AS total_kwh,
          MAX(c.recorded_at)::text AS last_recorded_at
        FROM consumptions c
        WHERE c.place_id = $1
          AND c.recorded_at >= (now() - {interval_sql})
        GROUP BY c.energy
      ),
      goals AS (
        SELECT
          g.energy::text AS energy,
          COALESCE(g.{goal_col},0)::float8 AS goal_kwh
        FROM place_goals g
        WHERE g.place_id = $1
      )
      SELECT
        e.energy::text AS energy,
        COALESCE(t.total_kwh,0)::float8 AS total_kwh,
        COALESCE(go.goal_kwh,0)::float8 AS goal_kwh,
        (COALESCE(t.total_kwh,0) - COALESCE(go.goal_kwh,0))::float8 AS delta_kwh,
        t.last_recorded_at
      FROM (VALUES ('electricity'::energy_type), ('gas'::energy_type)) e(energy)
      LEFT JOIN totals t ON t.energy = e.energy::text
      LEFT JOIN goals go ON go.energy = e.energy::text
      ORDER BY e.energy::text
    "#);

    let rows: Result<Vec<EnergySummary>, sqlx::Error> = sqlx::query_as(&sql)
        .bind(q.place_id)
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(items) => HttpResponse::Ok().json(SummaryResp { period, items }),
        Err(e) => { eprintln!("SUMMARY ERROR: {e:?}"); HttpResponse::InternalServerError().body("db error") }
    }
}

#[get("/dashboard/alerts")]
async fn dashboard_alerts(
    req: HttpRequest,
    state: web::Data<AppState>,
    q: web::Query<AlertsQuery>,
) -> impl Responder {
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token"),
    };

    let owns = sqlx::query_scalar::<_, i32>("SELECT 1 FROM places WHERE id=$1 AND user_id=$2")
        .bind(q.place_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match owns {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("ALERTS owns error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    }

    let period = q.period.trim().to_lowercase();
    if !matches!(period.as_str(), "week" | "month") {
        return HttpResponse::BadRequest().body("period must be week|month");
    }

    let (current_from_sql, current_to_sql, goal_col, period_label) =
        if period == "week" {
            (
                "now() - interval '7 days'",
                "now()",
                "weekly_target_kwh",
                "hebdomadaire",
            )
        } else {
            (
                "date_trunc('month', now())",
                "date_trunc('month', now()) + interval '1 month'",
                "monthly_target_kwh",
                "mensuel",
            )
        };

    let rows: Result<Vec<AlertMetricsRow>, sqlx::Error> = sqlx::query_as(
        &format!(
        r#"
        WITH current_month AS (
          SELECT
            c.energy::text AS energy,
            COALESCE(SUM(c.value), 0)::float8 AS total_kwh
          FROM consumptions c
          WHERE c.place_id = $1
            AND c.recorded_at >= ({current_from_sql})
            AND c.recorded_at < ({current_to_sql})
          GROUP BY c.energy
        ),
        goals AS (
          SELECT
            g.energy::text AS energy,
            COALESCE(g.{goal_col}, 0)::float8 AS goal_kwh
          FROM place_goals g
          WHERE g.place_id = $1
        )
        SELECT
          e.energy::text AS energy,
          COALESCE(cm.total_kwh, 0)::float8 AS current_month_total_kwh,
          COALESCE(go.goal_kwh, 0)::float8 AS goal_kwh
        FROM (VALUES ('electricity'::energy_type), ('gas'::energy_type)) e(energy)
        LEFT JOIN current_month cm ON cm.energy = e.energy::text
        LEFT JOIN goals go ON go.energy = e.energy::text
        ORDER BY e.energy::text
        "#
        )
    )
    .bind(q.place_id)
    .fetch_all(&state.db)
    .await;

    let rows = match rows {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ALERTS ERROR: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    };

    let now = OffsetDateTime::now_utc();
    let tip_seed = now.day();

    let mut items: Vec<(i32, AlertItem)> = Vec::new();

    for row in rows {
        if row.current_month_total_kwh <= 0.0 {
            continue;
        }

        let energy_objective = if row.energy == "gas" {
            "pour le gaz"
        } else {
            "pour l'électricité"
        };

        if row.goal_kwh > 0.0 {
            let pct = (row.current_month_total_kwh / row.goal_kwh) * 100.0;
            if row.current_month_total_kwh > row.goal_kwh {
                items.push((
                    300,
                    AlertItem {
                        id: format!("{}-month-alert", row.energy),
                        severity: "alert".to_string(),
                        kind: "alert".to_string(),
                        title: format!("Objectif {} dépassé", period_label),
                        message: format!("Vous avez dépassé votre objectif {} {}.", period_label, energy_objective),
                        energy: Some(row.energy.clone()),
                        period: period.clone(),
                        value_kwh: Some(row.current_month_total_kwh),
                        goal_kwh: Some(row.goal_kwh),
                        action_label: Some("Voir l'historique".to_string()),
                        action_href: Some("/hist.html".to_string()),
                    },
                ));
            } else if pct >= 80.0 {
                items.push((
                    220,
                    AlertItem {
                        id: format!("{}-month-watch", row.energy),
                        severity: "watch".to_string(),
                        kind: "alert".to_string(),
                        title: "Objectif presque atteint".to_string(),
                        message: format!(
                            "Vous avez atteint {:.0} % de votre objectif {} {}.",
                            pct, period_label, energy_objective
                        ),
                        energy: Some(row.energy.clone()),
                        period: period.clone(),
                        value_kwh: Some(row.current_month_total_kwh),
                        goal_kwh: Some(row.goal_kwh),
                        action_label: Some("Voir l'historique".to_string()),
                        action_href: Some("/hist.html".to_string()),
                    },
                ));
            } else {
                let tip = green_tip_for_energy(
                    &row.energy,
                    tip_seed + if row.energy == "gas" { 1 } else { 0 },
                );
                items.push((
                    90,
                    AlertItem {
                        id: format!("{}-month-ok", row.energy),
                        severity: "info".to_string(),
                        kind: "advice".to_string(),
                        title: "Objectif bien maîtrisé".to_string(),
                        message: format!(
                            "Vous avez atteint {:.0} % de votre objectif {} {}. Conseil : {}.",
                            pct, period_label, energy_objective, tip
                        ),
                        energy: Some(row.energy.clone()),
                        period: period.clone(),
                        value_kwh: Some(row.current_month_total_kwh),
                        goal_kwh: Some(row.goal_kwh),
                        action_label: Some("Voir l'historique".to_string()),
                        action_href: Some("/hist.html".to_string()),
                    },
                ));
            }
        }
    }

    items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
    items.truncate(2);

    let items = items.into_iter().map(|(_, item)| item).collect();
    HttpResponse::Ok().json(AlertsResp { items })
}
#[get("/dashboard/series")]
async fn dashboard_series(req: HttpRequest, state: web::Data<AppState>, q: web::Query<SeriesQuery>,) -> impl Responder {
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token subject"),
    };

    // owns place
    let owns = sqlx::query_scalar::<_, i32>("SELECT 1 FROM places WHERE id=$1 AND user_id=$2")
        .bind(q.place_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match owns {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => { eprintln!("SERIES owns error: {e:?}"); return HttpResponse::InternalServerError().body("db error"); }
    }

    let energy = q.energy.trim().to_lowercase();
    if !matches!(energy.as_str(), "electricity" | "gas") {
        return HttpResponse::BadRequest().body("energy must be electricity|gas");
    }
    let period = q.period.trim().to_lowercase();
    if !matches!(period.as_str(), "week" | "month") {
        return HttpResponse::BadRequest().body("period must be week|month");
    }

       // 7 points pour week, 30 points pour month (proto)
    let days: i64 = if period == "week" { 6 } else { 29 };

    let rows: Result<Vec<(String, f64)>, sqlx::Error> = sqlx::query_as(
        r#"
        WITH days AS (
          SELECT generate_series(
            date_trunc('day', now()) - ($3::int * interval '1 day'),
            date_trunc('day', now()),
            interval '1 day'
          ) AS d
        ),
        agg AS (
          SELECT
            date_trunc('day', c.recorded_at) AS d,
            SUM(c.value)::float8 AS v
          FROM consumptions c
          WHERE c.place_id = $1
            AND c.energy = $2::energy_type
            AND c.recorded_at >= (date_trunc('day', now()) - ($3::int * interval '1 day'))
          GROUP BY 1
        )
        SELECT
          to_char(days.d, 'YYYY-MM-DD') AS label,
          COALESCE(agg.v, 0)::float8 AS value
        FROM days
        LEFT JOIN agg ON agg.d = days.d
        ORDER BY days.d
        "#
    )
    .bind(q.place_id)
    .bind(&energy)
    .bind(days)
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(v) => {
            let (labels, values): (Vec<_>, Vec<_>) = v.into_iter().unzip();
            HttpResponse::Ok().json(SeriesResp { labels, values })
        }
        Err(e) => { eprintln!("SERIES ERROR: {e:?}"); HttpResponse::InternalServerError().body("db error") }
    }
}
#[get("/dashboard/recent")]
async fn dashboard_recent(
    req: HttpRequest,
    state: web::Data<AppState>,
    q: web::Query<RecentQuery>,
) -> impl Responder {
    // auth
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token subject"),
    };

    // owns place
    let owns = sqlx::query_scalar::<_, i32>("SELECT 1 FROM places WHERE id=$1 AND user_id=$2")
        .bind(q.place_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match owns {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("RECENT owns error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    }

    // limit clamp (proto safe)
    let mut limit = q.limit.unwrap_or(10);
    if limit < 1 { limit = 1; }
    if limit > 50 { limit = 50; }

    let rows: Result<Vec<RecentRow>, sqlx::Error> = sqlx::query_as(
        r#"
        WITH recent AS (
          SELECT
            c.id,
            c.recorded_at,
            c.energy,
            c.value,
            c.unit,
            to_char(date_trunc('day', c.recorded_at), 'YYYY-MM-DD') AS day,
            to_char(date_trunc('month', c.recorded_at), 'YYYY-MM') AS month_key
          FROM consumptions c
          WHERE c.place_id = $1
          ORDER BY c.recorded_at DESC
          LIMIT $2
        ),
        monthly AS (
          SELECT
            to_char(date_trunc('month', c.recorded_at), 'YYYY-MM') AS month_key,
            c.energy::text AS energy,
            SUM(c.value)::float8 AS total_kwh
          FROM consumptions c
          INNER JOIN recent r
            ON r.month_key = to_char(date_trunc('month', c.recorded_at), 'YYYY-MM')
           AND r.energy = c.energy
          WHERE c.place_id = $1
          GROUP BY 1, 2
        ),
        goals AS (
          SELECT
            g.energy::text AS energy,
            COALESCE(g.monthly_target_kwh, 0.0)::float8 AS goal_kwh
          FROM place_goals g
          WHERE g.place_id = $1
        )
        SELECT
          r.recorded_at::text AS recorded_at,
          r.energy::text      AS energy,
          r.value             AS value,
          r.unit              AS unit,
          CASE
            WHEN COALESCE(go.goal_kwh, 0.0) <= 0.0 THEN 'ok'
            WHEN m.total_kwh < (go.goal_kwh * 0.8) THEN 'ok'
            WHEN m.total_kwh <= go.goal_kwh THEN 'watch'
            ELSE 'alert'
          END AS status
        FROM recent r
        LEFT JOIN monthly m
          ON m.month_key = r.month_key
         AND m.energy = r.energy::text
        LEFT JOIN goals go
          ON go.energy = r.energy::text
        ORDER BY r.recorded_at DESC
        LIMIT $2
        "#
    )
    .bind(q.place_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(items) => HttpResponse::Ok().json(RecentResp { items }),
        Err(e) => {
            eprintln!("RECENT ERROR: {e:?}");
            HttpResponse::InternalServerError().body("db error")
        }
    }
}


#[get("/history")]
async fn history(
    req: HttpRequest,
    state: web::Data<AppState>,
    q: web::Query<HistoryQuery>,
) -> impl Responder {
    // auth
    let claims = match require_auth(&req, state.get_ref()) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("invalid token subject"),
    };

    // owns place
    let owns = sqlx::query_scalar::<_, i32>("SELECT 1 FROM places WHERE id=$1 AND user_id=$2")
        .bind(q.place_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match owns {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("place not found"),
        Err(e) => {
            eprintln!("HISTORY owns error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    }

    // pagination
    let mut page = q.page.unwrap_or(1);
    if page < 1 { page = 1; }
    let mut limit = q.limit.unwrap_or(50);
    if limit < 1 { limit = 1; }
    if limit > 200 { limit = 200; }
    let offset = (page - 1) * limit;

    // from/to defaults (last 30 days) handled in SQL when empty string
    let from = q.from.clone().unwrap_or_else(|| "".to_string());
    let to = q.to.clone().unwrap_or_else(|| "".to_string());

    // energy filter -> Option (NULL means no filter)
    let energy = q.energy.as_deref().unwrap_or("all").to_lowercase();
    if !matches!(energy.as_str(), "all" | "electricity" | "gas") {
        return HttpResponse::BadRequest().body("energy must be all|electricity|gas");
    }
    let energy_param: Option<String> = if energy == "all" { None } else { Some(energy) };

    // status filter -> Option (NULL means no filter)
    let status = q.status.as_deref().unwrap_or("all").to_lowercase();
    if !matches!(status.as_str(), "all" | "ok" | "watch" | "alert") {
        return HttpResponse::BadRequest().body("status must be all|ok|watch|alert");
    }
    let status_param: Option<String> = if status == "all" { None } else { Some(status) };

    // sort (safe whitelist)
    let sort = q.sort.as_deref().unwrap_or("desc").to_lowercase();
    let sort_sql = if sort == "asc" { "ASC" } else { "DESC" };

    // COUNT query (fixed params: $1..$5, $6/$7 not used here but we still bind them for uniformity)
    // We keep only $1..$5 in SQL and bind only those 5 for count to avoid useless binds.
    let count_sql = r#"
      WITH bounds AS (
        SELECT
          CASE WHEN $2 = '' THEN (date_trunc('day', now()) - interval '29 days')::date ELSE $2::date END AS d_from,
          CASE WHEN $3 = '' THEN (date_trunc('day', now()))::date ELSE $3::date END AS d_to
      ),
      daily AS (
        SELECT
          to_char(date_trunc('day', c.recorded_at), 'YYYY-MM-DD') AS day,
          to_char(date_trunc('month', c.recorded_at), 'YYYY-MM') AS month_key,
          c.energy::text AS energy,
          SUM(c.value)::float8 AS total_kwh
        FROM consumptions c, bounds b
        WHERE c.place_id = $1
          AND c.recorded_at >= b.d_from
          AND c.recorded_at < (b.d_to + 1)
          AND ($4::text IS NULL OR c.energy = $4::energy_type)
        GROUP BY 1, 2, 3
      ),
      goals AS (
        SELECT
          g.energy::text AS energy,
          COALESCE(g.monthly_target_kwh, 0.0)::float8 AS goal_kwh
        FROM place_goals g
        WHERE g.place_id = $1
      ),
      monthly AS (
        SELECT
          to_char(date_trunc('month', c.recorded_at), 'YYYY-MM') AS month_key,
          c.energy::text AS energy,
          SUM(c.value)::float8 AS total_kwh
        FROM consumptions c, bounds b
        WHERE c.place_id = $1
          AND c.recorded_at >= date_trunc('month', b.d_from)
          AND c.recorded_at < (date_trunc('month', b.d_to) + interval '1 month')
          AND ($4::text IS NULL OR c.energy = $4::energy_type)
        GROUP BY 1, 2
      ),
      enriched AS (
        SELECT
          d.day, d.energy, d.total_kwh,
          COALESCE(go.goal_kwh, 0.0)::float8 AS goal_kwh,
          CASE
            WHEN COALESCE(go.goal_kwh, 0.0) <= 0.0 THEN 'ok'
            WHEN m.total_kwh < (go.goal_kwh * 0.8) THEN 'ok'
            WHEN m.total_kwh <= go.goal_kwh THEN 'watch'
            ELSE 'alert'
          END AS status
        FROM daily d
        LEFT JOIN monthly m ON m.month_key = d.month_key AND m.energy = d.energy
        LEFT JOIN goals go ON go.energy = d.energy
      )
      SELECT COUNT(*)::bigint
      FROM enriched
      WHERE ($5::text IS NULL OR status = $5)
    "#;

    let total: i64 = match sqlx::query_scalar(count_sql)
        .bind(q.place_id)
        .bind(&from)
        .bind(&to)
        .bind(energy_param.as_deref()) // Option<&str> -> NULL if None
        .bind(status_param.as_deref()) // Option<&str>
        .fetch_one(&state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HISTORY count error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    };

    // DATA query (fixed params $1..$7)
    let data_sql = format!(r#"
      WITH bounds AS (
        SELECT
          CASE WHEN $2 = '' THEN (date_trunc('day', now()) - interval '29 days')::date ELSE $2::date END AS d_from,
          CASE WHEN $3 = '' THEN (date_trunc('day', now()))::date ELSE $3::date END AS d_to
      ),
      daily AS (
        SELECT
          to_char(date_trunc('day', c.recorded_at), 'YYYY-MM-DD') AS day,
          to_char(date_trunc('month', c.recorded_at), 'YYYY-MM') AS month_key,
          c.energy::text AS energy,
          SUM(c.value)::float8 AS total_kwh
        FROM consumptions c, bounds b
        WHERE c.place_id = $1
          AND c.recorded_at >= b.d_from
          AND c.recorded_at < (b.d_to + 1)
          AND ($4::text IS NULL OR c.energy = $4::energy_type)
        GROUP BY 1, 2, 3
      ),
      goals AS (
        SELECT
          g.energy::text AS energy,
          COALESCE(g.monthly_target_kwh, 0.0)::float8 AS goal_kwh
        FROM place_goals g
        WHERE g.place_id = $1
      ),
      monthly AS (
        SELECT
          to_char(date_trunc('month', c.recorded_at), 'YYYY-MM') AS month_key,
          c.energy::text AS energy,
          SUM(c.value)::float8 AS total_kwh
        FROM consumptions c, bounds b
        WHERE c.place_id = $1
          AND c.recorded_at >= date_trunc('month', b.d_from)
          AND c.recorded_at < (date_trunc('month', b.d_to) + interval '1 month')
          AND ($4::text IS NULL OR c.energy = $4::energy_type)
        GROUP BY 1, 2
      ),
      enriched AS (
        SELECT
          d.day, d.energy, d.total_kwh,
          COALESCE(go.goal_kwh, 0.0)::float8 AS goal_kwh,
          CASE
            WHEN COALESCE(go.goal_kwh, 0.0) <= 0.0 THEN 'ok'
            WHEN m.total_kwh < (go.goal_kwh * 0.8) THEN 'ok'
            WHEN m.total_kwh <= go.goal_kwh THEN 'watch'
            ELSE 'alert'
          END AS status
        FROM daily d
        LEFT JOIN monthly m ON m.month_key = d.month_key AND m.energy = d.energy
        LEFT JOIN goals go ON go.energy = d.energy
      )
      SELECT day, energy, total_kwh, goal_kwh, status
      FROM enriched
      WHERE ($5::text IS NULL OR status = $5)
      ORDER BY day {sort_sql}, energy ASC
      LIMIT $6 OFFSET $7
    "#);

    let items: Vec<HistoryRow> = match sqlx::query_as(&data_sql)
        .bind(q.place_id)
        .bind(&from)
        .bind(&to)
        .bind(energy_param.as_deref())
        .bind(status_param.as_deref())
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HISTORY data error: {e:?}");
            return HttpResponse::InternalServerError().body("db error");
        }
    };

    HttpResponse::Ok().json(HistoryResp {
        page,
        limit,
        total,
        items,
    })
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
            .service(update_place)
            .service(delete_place)
            .service(add_data)
            .service(set_goal)
            .service(get_goals)
            .service(list_places)
            .service(dashboard_summary)
            .service(dashboard_alerts)
            .service(dashboard_series)
            .service(dashboard_recent)
            .service(history)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
