use std::env;
use dotenv;

pub fn load_env() { 
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let env_path = current_dir.join(".env");
    dotenv::from_path(env_path).ok();
}