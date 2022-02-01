use std::error::Error;
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, HeaderName, CONTENT_TYPE};
use chrono::offset::Utc;
use chrono::NaiveDateTime;
use chrono::DateTime;
use serde_json::Value;
use std::sync::{Arc, RwLock};

type BoxResult<T> = Result<T,Box<dyn Error + Send + Sync>>;

const VAULT_AUTH: &'static str = "auth/kubernetes/login";

#[derive(Debug, Clone, Default)]
pub struct Client {
    client: reqwest::Client,
    config: Arc<RwLock<Config>>
}

#[derive(Debug, Clone, Default)]
pub struct Config{
	vault_role: String,
	vault_url: String,
	jwt_path: String,
    jwt_token: String,
    token: String,
    token_expires: i64,
	insecure: bool
}

impl Client {

	pub async fn with_vault_role(&mut self, vault_role: &str) -> &mut Self {
        let mut config = self.config.write().expect("Failed getting write access to config");
		config.vault_role = vault_role.to_string();
		drop(config);
		self
	}

	pub async fn with_vault_url(&mut self, vault_url: &str) -> &mut Self {
        let mut config = self.config.write().expect("Failed getting write access to config");
		config.vault_url = vault_url.to_string();
		drop(config);
		self
	}

	pub async fn with_jwt_path(&mut self, jwt_path: &str) -> &mut Self {
        let mut config = self.config.write().expect("Failed getting write access to config");
		config.jwt_path = jwt_path.to_string();
		drop(config);
		self
	}

	pub async fn insecure(&mut self, insecure: bool) -> &mut Self {
        let mut config = self.config.write().expect("Failed getting write access to config");
		config.insecure= insecure;
		drop(config);
		self
	}

    pub async fn new(&self) -> BoxResult<Self> {
        let config = self.config.read().expect("Failed getting write access to config");

        let client = reqwest::Client::builder()
            .timeout(Duration::new(60, 0))
            .danger_accept_invalid_certs(config.insecure)
            .build()
            .expect("Failed to build client");

		let config = Config::default();

        Ok(Self { client, config: Arc::new(RwLock::new(config)) })

    }

    pub async fn get(&mut self, path: &str) -> BoxResult<Value> {
        self.renew().await?;
        let uri = format!("{}{}", self.vault_url().await, path);
        log::debug!("Getting json output from {}", &uri);
        let response = self.client
            .get(uri)
            .headers(self.headers().await?)
            .send()
            .await?;

        match response.json().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn headers(&self) -> BoxResult<HeaderMap> {
        let config = self.config.read().expect("Failed reading config");

        // Create HeaderMap
        let mut headers = HeaderMap::new();

        log::debug!("Using X-Vault-Token of {}", config.token);

        // Add all headers
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/json").unwrap(),
        );
        headers.insert(
            HeaderName::from_static("X-Vault-Token"),
            HeaderValue::from_str(&config.token).unwrap(),
        );

        // Return headers
        Ok(headers)
	}

    pub async fn login(&mut self) -> BoxResult<String> {
        // Check out config
        let mut config = self.config.write().expect("Failed getting write access to config");

		let jwt_token = std::fs::read_to_string(&config.jwt_path).expect("Unable to read jwt token");

        let data = format!("{{\"role\": \"{}\", \"jwt\": \"{}\"}}", config.vault_role, jwt_token);
        let uri = format!("{}/{}", config.vault_url.clone(), VAULT_AUTH);

        let response = self.client
            .post(uri)
            .body(data)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => log::info!("Successfully logged in to {}", config.vault_url),
            _ => {
                log::error!("Error logging in to controller: {}", response.status());
                return Ok("Error logging in to controller".to_owned());
            }
        };

		let body: Value = response.json().await?;

        let token_expires = Utc::now().timestamp() + body["lease_duration"].as_i64().unwrap_or(0);
        let token = body["client_token"].as_str().unwrap_or("error").to_string();

        match token == config.token {
            true => log::info!("client_token is the same as before..."),
            false => { 
                log::debug!("Registered token: {}", &token);
                config.token = token;
            }
        };

        // Update max_age for new token
        config.token_expires = token_expires;
		config.jwt_token = jwt_token;

        Ok(config.token_expires.to_string())
    }

    // Return back the time in UTC that the cookie will expire
    pub fn expires(&self) -> BoxResult<String> {
        let config = self.config.read().expect("Failed reading config");
        let naive = NaiveDateTime::from_timestamp(config.token_expires, 0);
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        let newdate = datetime.format("%Y-%m-%d %H:%M:%S");
        Ok(newdate.to_string())
    }

    async fn token_expires(&self) -> BoxResult<i64> {
        let config = self.config.read().expect("Failed reading config");
        Ok(config.token_expires)
    }

    async fn vault_url(&self) -> String {
        let config = self.config.read().expect("Failed reading config");
        config.vault_url.clone()
    }

    async fn renew(&mut self) -> BoxResult<()> {
        if self.token_expires().await? - Utc::now().timestamp() <= 0 {
            log::info!("token has expired, kicking off re-login function");
            self.login().await?;
        } else {
            log::debug!("Session and token are current");
        }
        Ok(())
    }
}
