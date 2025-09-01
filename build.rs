fn main() {
    // Get git commit hash - prioritize environment variable, then fallback to .git files
    let git_hash = std::env::var("GIT_COMMIT_HASH").unwrap_or_else(|_| get_git_commit_from_files());

    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", git_hash);

    // Watch for git file changes to trigger rebuilds
    if std::path::Path::new(".git").exists() {
        println!("cargo:rerun-if-changed=.git/HEAD");

        // Also watch the current branch ref if it exists
        if let Ok(head_content) = std::fs::read_to_string(".git/HEAD") {
            if let Some(ref_path) = head_content.strip_prefix("ref: ").map(|s| s.trim()) {
                println!("cargo:rerun-if-changed=.git/{}", ref_path);
            }
        }
    }
}

fn get_git_commit_from_files() -> String {
    match std::fs::read_to_string(".git/HEAD") {
        Ok(head_content) => {
            let head_content = head_content.trim();

            // Check if it's a direct commit hash (detached HEAD)
            if head_content.len() == 40 && head_content.chars().all(|c| c.is_ascii_hexdigit()) {
                head_content.to_string()
            }
            // Check if it's a reference to a branch
            else if let Some(ref_path) = head_content.strip_prefix("ref: ") {
                match std::fs::read_to_string(format!(".git/{}", ref_path.trim())) {
                    Ok(commit_hash) => commit_hash.trim().to_string(),
                    Err(_) => "unknown".to_string(),
                }
            } else {
                "unknown".to_string()
            }
        }
        Err(_) => "unknown".to_string(),
    }
}
