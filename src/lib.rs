pub mod client;

#[cfg(test)]
mod client_tests {
	use crate::client::Client;

	#[tokio::test]
    async fn setup() {

		let vault_role = "my_role";
		let vault_url = "https://vault.server.com";
		let jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";

		let mut _client = Client::new()
			.with_vault_role(&vault_role)
			.with_vault_url(&vault_url)
			.with_jwt_path(&jwt_path)
			.build().unwrap();
    }
}
