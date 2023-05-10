use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        // `GET /ping` goes to the `ping` function
        .route("/ping", get(ping))
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// A basic route handler that returns a static 
// string, "pong"
async fn ping() -> &'static str {
    "pong"
}

// TODO: Add a route handler for the `/users` route
async fn create_user(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<CreateUser>,
) -> impl IntoResponse {
    // if this was a real world program,
    // you might insert into a database here
    // and return the newly created user
    // with their id
    //
    // The sqlx crate is a good choice for
    // interacting with databases in Rust
    // via staticly typed sql queries
    let user = User {
        id: 1337,
        username: payload.username,
    };

    // this will be converted into a JSON response
    // with a status code of `201 Created`
    (StatusCode::CREATED, Json(user))
}

// the input to our `create_user` handler
#[derive(Deserialize)]
struct CreateUser {
    username: String,
}

// the output to our `create_user` handler
#[derive(Serialize)]
struct User {
    id: u64,
    username: String,
}


// TODO: Add a route handler for the `/hello/:name` route
// that returns a string of "hello {name}"
