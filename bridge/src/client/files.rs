use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use crate::serialization::try_deserialize;

use super::client::BitVMClientPrivateData;

pub const BRIDGE_DATA_DIRECTORY_NAME: &str = "bridge_data";
pub const DEFAULT_PATH_PREFIX: &str = "default_user";
pub const PRIVATE_DATA_FILE_NAME: &str = "secret_data.json";
const PRIVATE_DATA_DIRECTORY_NAME: &str = "private";
const PUBLIC_DATA_DIRECTORY_NAME: &str = "public";

fn get_private_data_directory_path(data_root_path: &Path) -> PathBuf {
    data_root_path.join(PRIVATE_DATA_DIRECTORY_NAME)
}

pub fn get_private_data_file_path(data_root_path: &Path) -> PathBuf {
    get_private_data_directory_path(data_root_path).join(PRIVATE_DATA_FILE_NAME)
}

fn get_public_data_directory_path(data_root_path: &Path) -> PathBuf {
    data_root_path.join(PUBLIC_DATA_DIRECTORY_NAME)
}

pub fn create_directories_if_non_existent(data_root_path: &Path) {
    if !data_root_path.exists() {
        fs::create_dir_all(data_root_path).expect("Failed to create directories");
    }

    let public_data_folder = get_public_data_directory_path(data_root_path);
    if !public_data_folder.exists() {
        fs::create_dir(public_data_folder).expect("Failed to create 'public' directory");
    }

    let private_data_folder = get_private_data_directory_path(data_root_path);
    if !private_data_folder.exists() {
        fs::create_dir(private_data_folder).expect("Failed to create 'private' directory");
    }
}

pub fn get_private_data_from_file(path: &Path) -> BitVMClientPrivateData {
    println!("Reading private data from local file...");
    match read_file(path) {
        Some(data) => try_deserialize::<BitVMClientPrivateData>(&data)
            .expect("Could not deserialize private data"),
        None => {
            println!("New private data will be generated if required.");
            BitVMClientPrivateData {
                secret_nonces: HashMap::new(),
                commitment_secrets: HashMap::new(),
            }
        }
    }
}

fn read_file(path: &Path) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(content) => Some(content),
        Err(e) => {
            eprintln!("Could not read file {} due to error: {}", path.display(), e);
            None
        }
    }
}

pub fn save_local_public_file(data_root_path: &Path, file_name: &String, contents: &String) {
    create_directories_if_non_existent(data_root_path);
    println!("Saving public data in local file: {}...", file_name);
    fs::write(
        get_public_data_directory_path(data_root_path).join(file_name),
        contents,
    )
    .expect("Unable to write a file");
}

pub fn save_local_private_file(data_root_path: &Path, contents: &String) {
    create_directories_if_non_existent(data_root_path);
    println!("Saving private data in local file...");
    fs::write(get_private_data_file_path(data_root_path), contents)
        .expect("Unable to write a file");
}
