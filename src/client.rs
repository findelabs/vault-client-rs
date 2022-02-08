use std::error::Error;
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, HeaderName, CONTENT_TYPE};
use chrono::offset::Utc;
use chrono::NaiveDateTime;
use chrono::DateTime;
use serde_json::{Value, Map};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::*;

type BoxResult<T> = Result<T,Box<dyn Error + Send + Sync>>;

#[derive(Debug, Clone, Default)]
pub struct Client {
    client: reqwest::Client,
    config: Arc<RwLock<Config>>
}

#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    config: Config
}

#[derive(Debug, Clone, Default)]
pub struct Config {
	url: String,
	kubernetes_role: Option<String>,
    mount: String,
    login_path: String,
	jwt_path: Option<String>,
    role_id: Option<String>,
    secret_id: Option<String>,
    token: String,
    token_expires: i64,
	insecure: bool
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Metadata{
    created_time: String,
    #[serde(default)]
    custom_metadata: Value,
    deletion_time: String,
    destroyed: bool,
    version: u64
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct SecretData {
    data: Map<String, Value>,
    metadata: Metadata
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Secret {
    request_id: String,
    lease_id: String,
    renewable: bool,
    lease_duration: u32,
    wrap_info: Value,
    warnings: Value,
    auth: Value,
    data: SecretData,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct List {
    lease_id: String,
    lease_duration: u32,
    auth: Value,
    data: ListData,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct ListData {
    keys: Vec<Value>
}

impl List {
    pub async fn keys(self) -> Vec<Value> {
        self.data.keys
    }
}

impl Secret {
    pub async fn data(self) -> Map<String, Value> {
        self.data.data
    }

    pub async fn metadata(self) -> Metadata {
        self.data.metadata
    }
}

impl ClientBuilder {
    pub fn with_kubernetes_role(mut self, arg: Option<&str>) -> Self {
        let f: Option<String> = arg.map(String::from);
        self.config.kubernetes_role = f;
        self
    }
    
    pub fn with_url(mut self, arg: &str) -> Self {
        self.config.url = arg.to_string();
        self
    }
    
    pub fn with_mount(mut self, arg: &str) -> Self {
        self.config.mount = arg.to_string();
        self
    }
    
    pub fn with_login_path(mut self, arg: &str) -> Self {
        self.config.login_path = arg.to_string();
        self
    }

    pub fn with_role_id(mut self, arg: Option<&str>) -> Self {
        let f: Option<String> = arg.map(String::from);
        self.config.role_id = f;
        self
    }
    
    pub fn with_secret_id(mut self, arg: Option<&str>) -> Self {
        let f: Option<String> = arg.map(String::from);
        self.config.secret_id = f;
        self
    }

    pub fn with_jwt_path(mut self, arg: Option<&str>) -> Self {
        let f: Option<String> = arg.map(String::from);
        self.config.jwt_path = f;
        self
    }
    
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.config.insecure = insecure;
        self
    }

    pub fn new() -> Self {
        let config = Config::default();
        Self { config }

    }

    pub fn build(&mut self) -> BoxResult<Client> {

        // Ensure role_id and secret_id both exist together
        if self.config.role_id.is_some() && self.config.secret_id.is_none() {
            panic!("Missing secret_id");
        } else if self.config.secret_id.is_some() && self.config.role_id.is_none() {
            panic!("Missing role_id");
        };

        if self.config.role_id.is_some() && self.config.kubernetes_role.is_some() {
            panic!("Cannot use both approle and kubernetes jwt login");
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::new(60, 0))
            .danger_accept_invalid_certs(self.config.insecure)
            .build()
            .expect("Failed to build client");

        Ok(Client{ client, config: Arc::new(RwLock::new(self.config.clone())) })
    }
}

impl Client {
    pub async fn get(&mut self, path: &str) -> Result<Secret, VaultError> {
        self.renew().await?;
        let uri = format!("{}/v1/{}/data/{}", self.url().await, self.mount().await, path);
        log::debug!("Attempting to get {}", &uri);

        let response = self.client
            .get(uri)
            .headers(self.headers().await?)
            .send()
            .await?;

        match response.status().as_u16() {
            404 => Err(VaultError::NotFound),
            403 => Err(VaultError::Forbidden),
            401 => Err(VaultError::Unauthorized),
            200 => {
                Ok(response.json().await?)
            },
            _ => Err(VaultError::UnkError)
        }
    }

    pub async fn list(&mut self, path: &str) -> Result<List, VaultError> {
        self.renew().await?;
        let uri = format!("{}/v1/{}/metadata/{}", self.url().await, self.mount().await, path);
        log::debug!("Attempting to list {}", &uri);

        let response = self.client
            .get(uri)
            .headers(self.headers().await?)
            .query(&[("list", "true")])
            .send()
            .await?;

        match response.status().as_u16() {
            404 => Err(VaultError::NotFound),
            403 => Err(VaultError::Forbidden),
            401 => Err(VaultError::Unauthorized),
            200 => {
                Ok(response.json().await?)
            },
            _ => Err(VaultError::UnkError)
        }
    }

    pub async fn list_secrets(&mut self, path: &str) -> BoxResult<Vec<Secret>> {
        let list = self.list(path).await?;
        let keys = list.data.keys;

        let mut vec = Vec::new();
        for key in keys {
            let secret_path = format!("{}{}", path, key.as_str().expect("Could not extract string"));
            log::debug!("Attempting to get {}", secret_path);
            let secret = self.get(&secret_path).await?;
            vec.push(secret)
        }
        Ok(vec)
    }

    pub async fn headers(&self) -> Result<HeaderMap, VaultError> {
        let config = self.config.read().await;

        // Create HeaderMap
        let mut headers = HeaderMap::new();

        log::debug!("Using X-Vault-Token of {}", config.token);

        // Add all headers
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/json").unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-vault-token"),
            HeaderValue::from_str(&config.token).unwrap(),
        );

        // Return headers
        Ok(headers)
    }

    pub async fn login(&mut self) -> Result<(), VaultError> {
        // Check out config
        let mut config = self.config.write().await;

        let data = if config.kubernetes_role.is_some() {
		    let jwt_token = std::fs::read_to_string(&config.jwt_path.as_ref().unwrap()).expect("Unable to read jwt token");
            let data = format!("{{\"role\": \"{}\", \"jwt\": \"{}\"}}", config.kubernetes_role.as_ref().unwrap(), jwt_token);
            data
        } else if config.role_id.is_some() {
            let data = format!("{{\"role_id\": \"{}\", \"secret_id\": \"{}\"}}", config.role_id.as_ref().unwrap(), config.secret_id.as_ref().unwrap());
            data
        } else {
            panic!("Unknown auth backend")
        };

        let uri = format!("{}/v1/{}/login", config.url, config.login_path);

        log::debug!("Using body: {}", data);

        let response = self.client
            .clone()
            .post(uri)
            .body(data)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => log::info!("Successfully logged in to {}", config.url),
            _ => {
                log::error!("Error logging in to controller: {}", response.status());
                return Err(VaultError::LoginError)
            }
        };

        let body: Value = response.json().await?;

        let token_expires = Utc::now().timestamp() + body["auth"]["lease_duration"].as_i64().unwrap_or(0);
        let token = body["auth"]["client_token"].as_str().unwrap_or("error").to_string();

        match token == config.token {
            true => log::info!("client_token is the same as before..."),
            false => { 
                log::debug!("Registered token: {}", &token);
                config.token = token;
            }
        };

        // Update max_age for new token
        config.token_expires = token_expires;

        Ok(())
    }

    // Return back the time in UTC that the cookie will expire
    pub async fn expires(&self) -> BoxResult<String> {
        let config = self.config.read().await;
        let naive = NaiveDateTime::from_timestamp(config.token_expires, 0);
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        let newdate = datetime.format("%Y-%m-%d %H:%M:%S");
        Ok(newdate.to_string())
    }

    async fn token_expires(&self) -> i64 {
        let config = self.config.read().await;
        config.token_expires.clone()
    }

    async fn url(&self) -> String {
        let config = self.config.read().await;
        config.url.clone()
    }

    async fn mount(&self) -> String {
        let config = self.config.read().await;
        config.mount.clone()
    }

    async fn renew(&mut self) -> Result<(), VaultError> {
        if self.token_expires().await - Utc::now().timestamp() <= 0 {
            log::info!("token has expired, kicking off re-login function");
            self.login().await?;
        } else {
            log::debug!("Session and token are current");
        }
        Ok(())
    }
}
