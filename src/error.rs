//use serde_json::error::Error as SerdeError;
use axum::{
    body::{self},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    LoginError,
    Forbidden,
    Unauthorized,
    NotFound,
    UnkError,
    ReqwestError(reqwest::Error),
}

impl std::error::Error for VaultError {}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VaultError::LoginError => f.write_str("Error logging in to vault"),
            VaultError::Forbidden => f.write_str("Forbidden to read secret"),
            VaultError::Unauthorized => f.write_str("Unauthorized to read secret"),
            VaultError::NotFound => f.write_str("Secret not found"),
            VaultError::UnkError => f.write_str("Returned bad status code"),
            VaultError::ReqwestError(ref e) => write!(f, "Reqwest error: {}", e),
        }
    }
}

impl IntoResponse for VaultError {
    fn into_response(self) -> Response {
        let payload = self.to_string();
        let body = body::boxed(body::Full::from(payload));

        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(body)
            .unwrap()
    }
}

impl From<reqwest::Error> for VaultError {
    fn from(err: reqwest::Error) -> VaultError {
        VaultError::ReqwestError(err)
    }
}
