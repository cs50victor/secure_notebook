// `cp /System/Library/Sandbox/Profiles/* sb_references``

pub mod templates;

use anyhow::Result;
use std::path::PathBuf;

pub const DEFAULT_SANDBOX_PROFILE: &str = include_str!("notebook_defaults.sb");

/// Permissions struct to hold allowed and denied permissions.
#[derive(Debug, Default, Clone)]
pub struct Permissions {
    pub allow_read: Vec<String>,
    pub deny_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_write: Vec<String>,
    pub allow_net: bool,
    // pub deny_net: bool,
    pub allow_run: Vec<String>,
    pub deny_run: Vec<String>,
}

impl Permissions {
    /// Create a new Permissions instance with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow read access to specified paths (supports glob patterns).
    pub fn allow_read(&mut self, paths: Vec<PathBuf>) -> Result<()> {
        self.allow_read = validate_paths(paths)?;
        Ok(())
    }

    /// Deny read access to specified paths (supports glob patterns).
    pub fn deny_read(&mut self, paths: Vec<PathBuf>) -> Result<()> {
        self.deny_read = validate_paths(paths)?;
        Ok(())
    }

    /// Allow write access to specified paths (supports glob patterns).
    pub fn allow_write(&mut self, paths: Vec<PathBuf>) -> Result<()> {
        self.allow_write = validate_paths(paths)?;
        Ok(())
    }

    /// Deny write access to specified paths (supports glob patterns).
    pub fn deny_write(&mut self, paths: Vec<PathBuf>) -> Result<()> {
        self.deny_write = validate_paths(paths)?;
        Ok(())
    }

    /// Allow network access.
    fn allow_net(&mut self) {
        self.allow_net = true;
    }

    /// Allow execution of specified programs (supports glob patterns).
    fn allow_run(&mut self, programs: Vec<String>) {
        self.allow_run = programs;
    }

    /// Deny execution of specified programs (supports glob patterns).
    fn deny_run(&mut self, programs: Vec<String>) {
        self.deny_run = programs;
    }
}

fn validate_paths(paths: Vec<PathBuf>) -> Result<Vec<String>, std::io::Error> {
    paths
        .into_iter()
        .map(|path| {
            if path.exists() {
                Ok(path.to_string_lossy().to_string())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Path does not exist: {}", path.display()),
                ))
            }
        })
        .collect()
}

/// Function to generate the sandbox profile based on permissions.
pub fn generate_profile(template: &str, permissions: &Permissions) -> Result<String> {
    let mut profile = String::from(template);

    // Generate file read permissions
    profile.push_str(&generate_file_permissions(
        "file-read*",
        &permissions.allow_read,
        &permissions.deny_read,
    ));

    // Generate file write permissions
    profile.push_str(&generate_file_permissions(
        "file-write*",
        &permissions.allow_write,
        &permissions.deny_write,
    ));

    // Generate network permissions
    profile.push_str(&generate_network_permissions(
        permissions.allow_net,
        // permissions.deny_net,
    ));

    // Generate process execution permissions
    profile.push_str(&generate_run_permissions(
        &permissions.allow_run,
        &permissions.deny_run,
    ));

    Ok(profile)
}

/// Helper function to generate file permissions.
pub fn generate_file_permissions(
    access_type: &str,
    allow_paths: &[String],
    deny_paths: &[String],
) -> String {
    let mut statement = String::new();

    for path in deny_paths {
        statement.push_str(&format!("(deny {} (subpath \"{}\"))\n", access_type, path));
    }

    if !allow_paths.is_empty() {
        statement.push_str(&format!("(allow {})\n", access_type));
        for path in allow_paths {
            statement.push_str(&format!("    (subpath \"{}\")\n", path));
        }
        statement.push_str(")\n");
    }

    statement
}

/// Helper function to generate network permissions.
fn generate_network_permissions(allow_net: bool) -> String {
    let mut statement = String::new();

    if allow_net {
        statement.push_str("(allow network*)\n");
    }
    // else if deny_net {
    //     statement.push_str("(deny network*)\n");
    // }

    statement
}

/// Helper function to generate process execution permissions.
fn generate_run_permissions(allow_progs: &[String], deny_progs: &[String]) -> String {
    let mut statement = String::new();

    for prog in deny_progs {
        statement.push_str(&format!("(deny process-exec (literal \"{}\"))\n", prog));
    }

    if !allow_progs.is_empty() {
        statement.push_str("(allow process-exec\n");
        for prog in allow_progs {
            statement.push_str(&format!("    (literal \"{}\")\n", prog));
        }
        statement.push_str(")\n");
    }

    statement
}

/// Function to minify the sandbox profile.
pub fn minify_profile(profile: &str) -> String {
    profile
        .lines()
        .filter_map(|line| {
            // Remove comments (lines starting with ';')
            let line = if let Some(index) = line.find(';') {
                &line[..index]
            } else {
                line
            };
            let line = line.trim();
            if line.is_empty() {
                None
            } else {
                Some(line)
            }
        })
        .collect::<Vec<&str>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jupyter_client::Client;
    use std::collections::HashMap;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio;

    #[test]
    fn test_minify_profile() {
        let profile = "
            ; Comment line
            (version 1)

            (deny default)
            ; Another comment
            (allow file-read*)
        ";
        let minified = minify_profile(profile);
        assert_eq!(minified, "(version 1) (deny default) (allow file-read*)");
    }

    #[test]
    fn test_nonexistent_path() {
        let result =
            Permissions::new().allow_read(vec![PathBuf::from("/path/that/does/not/exist")]);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_permissions_generation() {
        let allow_paths = vec!["/tmp/allowed".to_string()];
        let deny_paths = vec!["/tmp/denied".to_string()];
        let permissions = generate_file_permissions("file-read*", &allow_paths, &deny_paths);

        assert!(permissions.contains("(deny file-read* (subpath \"/tmp/denied\"))"));
        assert!(permissions.contains("(allow file-read*)"));
        assert!(permissions.contains("(subpath \"/tmp/allowed\")"));
    }

    #[test]
    fn test_network_permissions_generation() {
        let allow_net_permissions = generate_network_permissions(true);
        assert_eq!(allow_net_permissions, "(allow network*)\n");

        let deny_net_permissions = generate_network_permissions(false);
        assert_eq!(deny_net_permissions, "");
    }

    #[test]
    fn test_run_permissions_generation() {
        let allow_progs = vec!["jupyter".to_string(), "python".to_string()];
        let deny_progs = vec!["bash".to_string()];
        let permissions = generate_run_permissions(&allow_progs, &deny_progs);

        assert!(permissions.contains("(deny process-exec (literal \"bash\"))"));
        assert!(permissions.contains("(allow process-exec"));
        assert!(permissions.contains("(literal \"jupyter\")"));
        assert!(permissions.contains("(literal \"python\")"));
    }

    #[test]
    fn test_generate_profile() -> Result<()> {
        let temp_dir = tempdir()?;
        let allowed_path = temp_dir.path().join("allowed");
        let denied_path = temp_dir.path().join("denied");
        std::fs::create_dir_all(&allowed_path)?;
        std::fs::create_dir_all(&denied_path)?;

        let mut permissions = Permissions::new();
        permissions.allow_read(vec![allowed_path.clone()])?;
        permissions.deny_read(vec![denied_path.clone()])?;
        permissions.allow_write(vec![allowed_path])?;
        permissions.deny_write(vec![denied_path])?;
        permissions.allow_net();
        permissions.allow_run(vec!["jupyter".to_string()]);

        let template = "(version 1)\n(deny default)\n";
        let profile = generate_profile(template, &permissions)?;

        assert!(profile.contains("(allow file-read*)"));
        assert!(profile.contains("(deny file-read* (subpath"));
        assert!(profile.contains("(allow file-write*)"));
        assert!(profile.contains("(deny file-write* (subpath"));
        assert!(profile.contains("(allow network*)"));
        assert!(profile.contains("(allow process-exec"));

        Ok(())
    }

    // end to end test -ish section
    // testing the sandbox with a real kernel

    async fn setup_jupyter_server(profile: &str) -> Client {
        // Start the Jupyter server (this assumes jupyter-server is in PATH)

        if let Err(e) = tokio::process::Command::new("sandbox-exec")
            .arg("-p")
            .arg(format!("'{profile}'"))
            .arg("jupyter-server")
            .arg("--no-browser")
            .arg("--IdentityProvider.token")
            .arg("''")
            .spawn()
        {
            println!("Failed to start Jupyter server: {:?}", e);
        };

        // Give the server some time to start up
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Connect to the server
        Client::existing().expect("Failed to connect to Jupyter server")
    }

    async fn run_code(client: &Client, code: &str) -> Result<()> {
        println!("Running code: {code}");
        let command = jupyter_client::commands::Command::Execute {
            code: code.to_string(),
            silent: false,
            store_history: true,
            user_expressions: HashMap::new(),
            allow_stdin: true,
            stop_on_error: false,
        };

        let response = client
            .send_shell_command(command)
            .map_err(|e| anyhow::anyhow!(e))?;

        // Check for errors in the response
        if let jupyter_client::responses::Response::Shell(
            jupyter_client::responses::ShellResponse::Execute { content, .. },
        ) = response
        {
            if content.status == jupyter_client::responses::Status::Error {
                return Err(anyhow::anyhow!("Execution error: {:?}", content.evalue));
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_jupyter_permissions() -> Result<(), anyhow::Error> {
        let temp_dir = tempdir()?;
        let allowed_path = temp_dir.path().join("allowed");
        let denied_path = temp_dir.path().join("denied");
        std::fs::create_dir_all(&allowed_path)?;
        std::fs::create_dir_all(&denied_path)?;

        let mut permissions = Permissions::new();
        permissions.allow_read(vec![allowed_path.clone()])?;
        permissions.deny_read(vec![denied_path.clone()])?;
        permissions.allow_write(vec![allowed_path.clone()])?;
        permissions.deny_write(vec![denied_path.clone()])?;
        permissions.allow_net();
        permissions.allow_run(vec!["python".to_string()]);

        let template = "(version 1)\n(deny default)\n";
        let profile = generate_profile(template, &permissions)?;
        let minified_profile = minify_profile(&profile);

        let jupyter_client = setup_jupyter_server(&minified_profile).await;

        // Test allowed read
        let allowed_read_code = format!(
            "
                with open('{}', 'r') as f:
                    print(f.read())
            ",
            allowed_path.join("test.txt").to_str().unwrap()
        );
        run_code(&jupyter_client, &allowed_read_code).await?;

        // Test denied read
        let denied_read_code = format!(
            "
                with open('{}', 'r') as f:
                    print(f.read())
            ",
            denied_path.join("test.txt").to_str().unwrap()
        );
        assert!(run_code(&jupyter_client, &denied_read_code).await.is_err());

        // Test allowed write
        let allowed_write_code = format!(
            "
                with open('{}', 'w') as f:
                    f.write('test')
            ",
            allowed_path.join("test.txt").to_str().unwrap()
        );
        run_code(&jupyter_client, &allowed_write_code).await?;

        // Test denied write
        let denied_write_code = format!(
            "
                with open('{}', 'w') as f:
                    f.write('test')
            ",
            denied_path.join("test.txt").to_str().unwrap()
        );
        assert!(run_code(&jupyter_client, &denied_write_code).await.is_err());

        // Test allowed network access
        let network_code = "
                import requests
                response = requests.get('https://api.github.com')
                print(response.status_code)
            ";
        run_code(&jupyter_client, network_code).await?;

        // Test allowed program execution
        let python_exec_code = "
                import sys
                print(sys.executable)
            ";
        run_code(&jupyter_client, python_exec_code).await?;

        Ok(())
    }
}
