use super::base::DataStoreDriver;
use async_trait::async_trait;
use dotenv;
use futures::TryStreamExt;
use openssh_sftp_client::{
    file::TokioCompatFile,
    openssh::{KnownHosts, Session as SshSession},
    Sftp as _Sftp,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// To use this data store, create a .env file in the base directory with the following values:
// export BRIDGE_SFTP_HOST="..."
// export BRIDGE_SFTP_PORT="..."
// export BRIDGE_SFTP_USERNAME="..."
// export BRIDGE_SFTP_KEYFILE_PATH="..."
// export BRIDGE_SFTP_BASE_PATH="..."

// NOTE: BRIDGE_SFTP_HOST should be an ip/domain that supports SSH

struct SftpCredentials {
    pub host: String,
    pub port: String,
    pub username: String,
    // TODO: `keyfile_path` is currently never read, commenting out to reduce compiler warnings.
    // pub keyfile_path: String,
    pub base_path: String,
}

pub struct Sftp {
    credentials: SftpCredentials,
}

impl Sftp {
    pub async fn new() -> Option<Self> {
        dotenv::dotenv().ok();
        let host = dotenv::var("BRIDGE_SFTP_HOST");
        let port = dotenv::var("BRIDGE_SFTP_PORT");
        let username = dotenv::var("BRIDGE_SFTP_USERNAME");
        // let keyfile_path = dotenv::var("BRIDGE_SFTP_KEYFILE_PATH");
        let base_path = dotenv::var("BRIDGE_SFTP_BASE_PATH");

        if host.is_err()
            || port.is_err()
            || username.is_err()
            // || keyfile_path.is_err()
            || base_path.is_err()
        {
            return None;
        }

        let credentials = SftpCredentials {
            host: host.unwrap(),
            port: port.unwrap(),
            username: username.unwrap(),
            // keyfile_path: keyfile_path.unwrap(),
            base_path: base_path.unwrap(),
        };

        match test_connection(&credentials).await {
            Ok(_) => Some(Self { credentials }),
            Err(err) => {
                eprintln!("{err:?}");
                None
            }
        }
    }

    async fn get_object(&self, key: &str, file_path: Option<&str>) -> Result<Vec<u8>, String> {
        let mut buffer: Vec<u8> = vec![];

        match connect(&self.credentials).await {
            Ok(sftp) => {
                let mut full_filename = key.to_string();
                if file_path.is_some() {
                    full_filename = format!("{}/{}", file_path.unwrap(), key);
                }
                match sftp.open(full_filename).await.map(TokioCompatFile::from) {
                    Ok(_file) => {
                        let mut file = Box::pin(_file);
                        let result = file.read_to_end(&mut buffer).await;
                        drop(file);
                        match result {
                            Ok(_) => {
                                disconnect(sftp).await;
                                Ok(buffer)
                            }
                            Err(err) => {
                                disconnect(sftp).await;
                                Err(format!("Unable to get {}: {}", key, err))
                            }
                        }
                    }
                    Err(err) => {
                        disconnect(sftp).await;
                        Err(format!("Unable to get {}: {}", key, err))
                    }
                }
            }
            Err(err) => Err(format!("Unable to get {}: {}", key, err)),
        }
    }

    async fn upload_object(
        &self,
        key: &str,
        data: &[u8],
        file_path: Option<&str>,
    ) -> Result<(), String> {
        match connect(&self.credentials).await {
            Ok(sftp) => {
                match create_directories_if_non_existent(&sftp, file_path).await {
                    Ok(_) => {
                        let mut full_filename = key.to_string();
                        if file_path.is_some() {
                            full_filename = format!("{}/{}", file_path.unwrap(), key);
                        }
                        let result = sftp
                            .options()
                            .write(true)
                            .create_new(true)
                            .open(full_filename)
                            .await; // Use intermediate variable to prevent GC issue
                        match result {
                            Ok(_file) => {
                                let mut file = Box::pin(TokioCompatFile::from(_file));
                                match file.write(data).await {
                                    Ok(_) => match file.flush().await {
                                        Ok(_) => {
                                            drop(file);
                                            disconnect(sftp).await;
                                            Ok(())
                                        }
                                        Err(err) => {
                                            drop(file);
                                            disconnect(sftp).await;
                                            Err(format!(
                                                "Unable to write {}: {}",
                                                key, err
                                            ))
                                        }
                                    },
                                    Err(err) => {
                                        drop(file);
                                        disconnect(sftp).await;
                                        Err(format!("Unable to write {}: {}", key, err))
                                    }
                                }
                            }
                            Err(err) => {
                                disconnect(sftp).await;
                                Err(format!("Unable to write {}: {}", key, err))
                            }
                        }
                    }
                    Err(err) => Err(format!("Unable to write {}: {}", key, err)),
                }
            }
            Err(err) => Err(format!("Unable to write {}: {}", key, err)),
        }
    }
}

#[async_trait]
impl DataStoreDriver for Sftp {
    async fn list_objects(&self, file_path: Option<&str>) -> Result<Vec<String>, String> {
        match connect(&self.credentials).await {
            Ok(sftp) => {
                let mut fs = sftp.fs();
                match fs.open_dir(file_path.unwrap_or(".")).await {
                    Ok(dir) => {
                        let mut read_dir = Box::pin(dir.read_dir());
                        let mut buffer: Vec<String> = vec![];
                        while let Some(entry) = read_dir.try_next().await.unwrap() {
                            buffer.push(entry.filename().to_str().unwrap().to_string());
                        }
                        drop(read_dir);
                        drop(fs);
                        disconnect(sftp).await;
                        Ok(buffer)
                    }
                    Err(err) => {
                        drop(fs);
                        disconnect(sftp).await;
                        Err(format!("Unable to list objects: {}", err))
                    }
                }
            }
            Err(err) => Err(format!("Unable tolist objects: {}", err)),
        }
    }

    async fn fetch_json(&self, key: &str, file_path: Option<&str>) -> Result<String, String> {
        let response = self.get_object(key, file_path).await;
        match response {
            Ok(buffer) => {
                let json = String::from_utf8(buffer);
                match json {
                    Ok(json) => Ok(json),
                    Err(err) => Err(format!("Failed to parse json: {}", err)),
                }
            }
            Err(err) => Err(format!("Failed to get json file: {}", err)),
        }
    }

    async fn upload_json(
        &self,
        key: &str,
        json: String,
        file_path: Option<&str>,
    ) -> Result<usize, String> {
        let bytes = json.as_bytes().to_vec();
        let size = bytes.len();

        println!("Writing data file to {} (size: {})", key, size);

        match self.upload_object(key, &bytes, file_path).await {
            Ok(_) => Ok(size),
            Err(err) => Err(format!("Failed to save json file: {}", err)),
        }
    }
}

async fn test_connection(credentials: &SftpCredentials) -> Result<(), String> {
    match connect(credentials).await {
        Ok(sftp) => {
            disconnect(sftp).await;
            Ok(())
        }
        Err(err) => Err(format!("Failed to connect: {}", err)),
    }
}

async fn connect(credentials: &SftpCredentials) -> Result<_Sftp, String> {
    let result = SshSession::connect_mux(
        format!(
            "ssh://{}@{}:{}",
            &credentials.username, &credentials.host, &credentials.port
        ),
        KnownHosts::Add,
    )
    .await;
    if result.is_err() {
        return Err(format!(
            "Unable to connect to SSH server at {}:{} (error: {})",
            &credentials.host,
            &credentials.port,
            result.err().unwrap()
        ));
    }

    let ssh_session = result.unwrap();

    let result = _Sftp::from_session(ssh_session, Default::default()).await;
    if result.is_err() {
        return Err(format!(
            "Unable to establish to SFTP session from SSH session at {}:{} (error: {})",
            &credentials.host,
            &credentials.port,
            result.err().unwrap()
        ));
    }

    let sftp = result.unwrap();
    let result = change_directory(&sftp, Some(&credentials.base_path)).await;
    if result.is_err() {
        return Err(format!(
            "Invalid base path: {} (error: {})",
            &credentials.base_path,
            result.err().unwrap()
        ));
    }

    Ok(sftp)
}

async fn disconnect(sftp: _Sftp) {
    let result = sftp.close().await;
    if result.is_err() {
        eprintln!(
            "Unable to close connection: {}",
            result.err().unwrap()
        );
    }
}

async fn change_directory(sftp: &_Sftp, file_path: Option<&str>) -> Result<(), String> {
    if let Some(path) = file_path {
        let mut fs = sftp.fs();
        fs.set_cwd(path);
        let result = fs.open_dir(path).await;
        drop(fs);
        if result.is_err() {
            return Err(format!(
                "Failed to change directory to {}: {}",
                path,
                result.err().unwrap()
            ));
        }
    }

    Ok(())
}

async fn create_directories_if_non_existent(
    sftp: &_Sftp,
    file_path: Option<&str>,
) -> Result<(), String> {
    if file_path.is_some() {
        let file_path = String::from(file_path.unwrap());
        let folders: Vec<&str> = file_path.split("/").collect();
        let mut fs = sftp.fs();
        let mut processed_folders: Vec<String> = vec![];
        for folder in folders {
            match fs.open_dir(folder).await {
                Ok(_) => {
                    processed_folders.push(folder.to_string());
                    fs.set_cwd(processed_folders.join("/"));
                }
                Err(_) => match fs.create_dir(folder).await {
                    Ok(_) => match fs.open_dir(folder).await {
                        Ok(_) => {
                            processed_folders.push(folder.to_string());
                            fs.set_cwd(processed_folders.join("/"));
                        }
                        Err(err) => {
                            drop(fs);
                            return Err(format!("Failed to open {} folder: {}", folder, err));
                        }
                    },
                    Err(err) => {
                        drop(fs);
                        return Err(format!("Failed to create {} folder: {}", folder, err));
                    }
                },
            }
        }
        drop(fs);
    }

    Ok(())
}
