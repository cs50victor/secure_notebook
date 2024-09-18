use std::path::PathBuf;
use anyhow::Result;

/// Permissions struct to hold allowed and denied permissions.
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
        Permissions {
            allow_read: Vec::new(),
            deny_read: Vec::new(),
            allow_write: Vec::new(),
            deny_write: Vec::new(),
            allow_net: false,
            // deny_net: false,
            allow_run: Vec::new(),
            deny_run: Vec::new(),
        }
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
    pub fn allow_net(&mut self) {
        self.allow_net = true;
    }

    /// Deny network access. 
    // pub fn deny_net(&mut self) -> Self {
    //     self.deny_net = true;
    //     self
    // }

    /// Allow execution of specified programs (supports glob patterns).
    pub fn allow_run(&mut self, programs: Vec<String>) {
        self.allow_run = programs;
    }

    /// Deny execution of specified programs (supports glob patterns).
    pub fn deny_run(&mut self, programs: Vec<String>) {
        self.deny_run = programs;
    }
}

fn validate_paths(paths: Vec<PathBuf>) -> Result<Vec<String>, std::io::Error> {
    paths.into_iter().map(|path| {
        if path.exists() {
            Ok(path.to_string_lossy().to_string())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Path does not exist: {}", path.display()),
            ))
        }
    }).collect()
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
fn generate_file_permissions(
    access_type: &str,
    allow_paths: &[String],
    deny_paths: &[String],
) -> String {
    let mut statement = String::new();

    for path in deny_paths {
        statement.push_str(&format!(
            "(deny {} (subpath \"{}\"))\n",
            access_type,
            path
        ));
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
        statement.push_str(&format!(
            "(deny process-exec (literal \"{}\"))\n",
            prog
        ));
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
    use std::io::Write;
    use std::fs::File;
    use tempfile::tempdir;


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
        let result = Permissions::new().allow_read(vec![PathBuf::from("/path/that/does/not/exist")]);
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



}

