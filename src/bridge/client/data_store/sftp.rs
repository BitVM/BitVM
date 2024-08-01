use super::base::DataStoreDriver;
use async_trait::async_trait;
use dotenv;
use futures::{executor, TryStreamExt};
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
// export BRIDGE_SFTP_BASE_PATH="..."

// NOTE: BRIDGE_SFTP_HOST should be an ip/domain that supports SSH
// NOTE: BRIDGE_SFTP_HOST will be added to KNOWN_HOSTS

struct SftpCredentials {
    pub host: String,
    pub port: String,
    pub username: String,
    pub base_path: String,
}

pub struct Sftp {
    credentials: SftpCredentials,
}

impl Sftp {
    pub fn new() -> Option<Self> {
        dotenv::dotenv().ok();
        let host = dotenv::var("BRIDGE_SFTP_HOST");
        let port = dotenv::var("BRIDGE_SFTP_PORT");
        let username = dotenv::var("BRIDGE_SFTP_USERNAME");
        let base_path = dotenv::var("BRIDGE_SFTP_BASE_PATH");

        println!("SFTP 40");

        if host.is_err() || port.is_err() || username.is_err() || base_path.is_err() {
            return None;
        }

        println!("SFTP 46");

        let credentials = SftpCredentials {
            host: host.unwrap(),
            port: port.unwrap(),
            username: username.unwrap(),
            base_path: base_path.unwrap(),
        };

        println!("SFTP 55");

        match test_connection(&credentials) {
            Ok(_) => Some(Self { credentials }),
            Err(err) => {
                eprintln!("{err:?}");
                None
            }
        }
    }

    async fn get_object(&self, key: &str) -> Result<Vec<u8>, String> {
        let mut buffer: Vec<u8> = vec![];

        match connect(&self.credentials).await {
            Ok(sftp) => match sftp.open(key).await.map(TokioCompatFile::from) {
                Ok(file) => {
                    tokio::pin!(file);
                    match file.read_to_end(&mut buffer).await {
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
            },
            Err(err) => Err(format!("Unable to get {}: {}", key, err)),
        }
    }

    async fn upload_object(&self, key: &str, data: &Vec<u8>) -> Result<(), String> {
        match connect(&self.credentials).await {
            Ok(sftp) => match sftp
                .options()
                .write(true)
                .create_new(true)
                .open(key)
                .await
                .map(TokioCompatFile::from)
            {
                Ok(file) => {
                    tokio::pin!(file);
                    match file.write(data).await {
                        Ok(_) => match file.flush().await {
                            Ok(_) => {
                                disconnect(sftp).await;
                                Ok(())
                            }
                            Err(err) => {
                                disconnect(sftp).await;
                                return Err(format!("Unable to write {}: {}", key, err));
                            }
                        },
                        Err(err) => {
                            disconnect(sftp).await;
                            return Err(format!("Unable to write {}: {}", key, err));
                        }
                    }
                }
                Err(err) => {
                    disconnect(sftp).await;
                    return Err(format!("Unable to write {}: {}", key, err));
                }
            },
            Err(err) => Err(format!("Unable to write {}: {}", key, err)),
        }
    }
}

#[async_trait]
impl DataStoreDriver for Sftp {
    async fn list_objects(&self) -> Result<Vec<String>, String> {
        match connect(&self.credentials).await {
            Ok(sftp) => {
                let mut fs = sftp.fs();
                match fs.open_dir(".").await {
                    Ok(dir) => {
                        let read_dir = dir.read_dir();
                        tokio::pin!(read_dir);

                        let mut buffer: Vec<String> = vec![];
                        while let Some(entry) = read_dir.try_next().await.unwrap() {
                            buffer.push(entry.filename().to_str().unwrap().to_string());
                        }

                        disconnect(sftp).await;
                        Ok(buffer)
                    }
                    Err(err) => {
                        disconnect(sftp).await;
                        Err(format!("Unable to list objects: {}", err.to_string()))
                    }
                }
            }
            Err(err) => Err(format!("Unable tolist objects: {}", err.to_string())),
        }
    }

    async fn fetch_json(&self, key: &str) -> Result<String, String> {
        let response = self.get_object(key).await;
        match response {
            Ok(buffer) => {
                let json = String::from_utf8(buffer);
                match json {
                    Ok(json) => Ok(json),
                    Err(err) => Err(format!("Failed to parse json: {}", err.to_string())),
                }
            }
            Err(err) => Err(format!("Failed to get json file: {}", err.to_string())),
        }
    }

    async fn upload_json(&self, key: &str, json: String) -> Result<usize, String> {
        let bytes = json.as_bytes().to_vec();
        let size = bytes.len();

        println!("Writing data file to {} (size: {})", key, size);

        match self.upload_object(&key, &bytes).await {
            Ok(_) => Ok(size),
            Err(err) => Err(format!("Failed to save json file: {}", err)),
        }
    }
}

fn test_connection(credentials: &SftpCredentials) -> Result<(), String> {
    println!("SFTP 190");
    match executor::block_on(connect(credentials)) {
        Ok(sftp) => {
            println!("SFTP 192");
            executor::block_on(disconnect(sftp));
            Ok(())
        }
        Err(err) => Err(format!("Failed to connect: {}", err.to_string())),
    }
}

async fn connect(credentials: &SftpCredentials) -> Result<_Sftp, String> {
    println!("SFTP 200");

    let result = SshSession::connect_mux(
        format!(
            "ssh://{}@{}:{}",
            &credentials.username, &credentials.host, &credentials.port
        ),
        KnownHosts::Add,
    )
    .await;
    println!("SFTP 202");
    if result.is_err() {
        return Err(format!(
            "Unable to connect to SSH server at {}:{} (error: {})",
            &credentials.host,
            &credentials.port,
            result.err().unwrap()
        ));
    }
    println!("SFTP 209");

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
    println!("SFTP 220");

    let sftp = result.unwrap();

    let mut fs = sftp.fs();
    fs.set_cwd(&credentials.base_path);
    // let result = fs.open_dir(&credentials.base_path).await;
    // if result.is_err() {
    //     return Err(format!("Invalid base path: {}", &credentials.base_path));
    // }

    println!("SFTP 230");

    Ok(sftp)
}

async fn disconnect(sftp: _Sftp) {
    if sftp.close().await.is_ok() {
        return;
    }

    eprintln!("Unable to close connection");
}
