use futures::{executor, AsyncReadExt, AsyncWriteExt};
use suppaftp::{
    async_native_tls::TlsConnector, AsyncFtpStream, AsyncNativeTlsConnector,
    AsyncNativeTlsFtpStream,
};

pub struct FtpCredentials {
    pub is_secure: bool,
    pub host: String,
    pub port: String,
    pub username: String,
    pub password: String,
    pub base_path: String,
}

pub fn test_connection(credentials: &FtpCredentials) -> Result<(), String> {
    if credentials.is_secure {
        match executor::block_on(secure_connect(credentials)) {
            Ok(mut ftp_stream) => {
                executor::block_on(disconnect(None, Some(&mut ftp_stream)));
                Ok(())
            }
            Err(err) => Err(format!("Failed to connect: {}", err.to_string())),
        }
    } else {
        match executor::block_on(insecure_connect(credentials)) {
            Ok(mut ftp_stream) => {
                executor::block_on(disconnect(Some(&mut ftp_stream), None));
                Ok(())
            }
            Err(err) => Err(format!("Failed to connect: {}", err.to_string())),
        }
    }
}

pub async fn list_objects(credentials: &FtpCredentials) -> Result<Vec<String>, String> {
    if credentials.is_secure {
        match secure_connect(credentials).await {
            Ok(mut ftp_stream) => match ftp_stream.list(None).await {
                Ok(files) => {
                    disconnect(None, Some(&mut ftp_stream)).await;
                    Ok(files)
                }
                Err(err) => {
                    disconnect(None, Some(&mut ftp_stream)).await;
                    Err(format!("Unable to list objects: {}", err.to_string()))
                }
            },
            Err(err) => Err(format!("Unable to list objects: {}", err.to_string())),
        }
    } else {
        match insecure_connect(credentials).await {
            Ok(mut ftp_stream) => match ftp_stream.list(None).await {
                Ok(files) => {
                    disconnect(Some(&mut ftp_stream), None).await;
                    Ok(files)
                }
                Err(err) => {
                    disconnect(Some(&mut ftp_stream), None).await;
                    Err(format!("Unable to list objects: {}", err.to_string()))
                }
            },
            Err(err) => Err(format!("Unable to list objects: {}", err.to_string())),
        }
    }
}

pub async fn fetch_json(credentials: &FtpCredentials, key: &str) -> Result<String, String> {
    let response = get_object(credentials, key).await;
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

pub async fn upload_json(
    credentials: &FtpCredentials,
    key: &str,
    json: String,
) -> Result<usize, String> {
    let bytes = json.as_bytes().to_vec();
    let size = bytes.len();

    println!("Writing data file to {} (size: {})", key, size);
    let response = upload_object(credentials, &key, &bytes).await;

    match response {
        Ok(_) => Ok(size),
        Err(_) => Err("Failed to save json file".to_string()),
    }
}

async fn get_object(credentials: &FtpCredentials, key: &str) -> Result<Vec<u8>, String> {
    let mut buffer: Vec<u8> = vec![];

    if credentials.is_secure {
        match secure_connect(credentials).await {
            Ok(mut ftp_stream) => match ftp_stream.retr_as_stream(key).await {
                Ok(mut reader) => match reader.read_to_end(&mut buffer).await {
                    Ok(_) => {
                        disconnect(None, Some(&mut ftp_stream)).await;
                        Ok(buffer)
                    }
                    Err(err) => {
                        disconnect(None, Some(&mut ftp_stream)).await;
                        Err(format!("Unable to get {}: {}", key, err))
                    }
                },
                Err(err) => {
                    disconnect(None, Some(&mut ftp_stream)).await;
                    Err(format!("Unable to get {}: {}", key, err))
                }
            },
            Err(err) => Err(format!("Unable to get {}: {}", key, err)),
        }
    } else {
        match insecure_connect(credentials).await {
            Ok(mut ftp_stream) => match ftp_stream.retr_as_stream(key).await {
                Ok(mut reader) => match reader.read_to_end(&mut buffer).await {
                    Ok(_) => {
                        disconnect(Some(&mut ftp_stream), None).await;
                        Ok(buffer)
                    }
                    Err(err) => {
                        disconnect(Some(&mut ftp_stream), None).await;
                        Err(format!("Unable to get {}: {}", key, err))
                    }
                },
                Err(err) => {
                    disconnect(Some(&mut ftp_stream), None).await;
                    Err(format!("Unable to get {}: {}", key, err))
                }
            },
            Err(err) => Err(format!("Unable to get {}: {}", key, err)),
        }
    }
}

async fn upload_object(
    credentials: &FtpCredentials,
    key: &str,
    data: &Vec<u8>,
) -> Result<(), String> {
    if credentials.is_secure {
        match secure_connect(credentials).await {
            Ok(mut ftp_stream) => match ftp_stream.put_with_stream(key).await {
                Ok(mut writer) => match writer.write(data).await {
                    Ok(_) => match writer.flush().await {
                        Ok(_) => {
                            disconnect(None, Some(&mut ftp_stream)).await;
                            Ok(())
                        }
                        Err(err) => {
                            disconnect(None, Some(&mut ftp_stream)).await;
                            return Err(format!("Unable to write {}: {}", key, err));
                        }
                    },
                    Err(err) => {
                        disconnect(None, Some(&mut ftp_stream)).await;
                        return Err(format!("Unable to write {}: {}", key, err));
                    }
                },
                Err(err) => {
                    disconnect(None, Some(&mut ftp_stream)).await;
                    return Err(format!("Unable to write {}: {}", key, err));
                }
            },
            Err(err) => Err(format!("Unable to write {}: {}", key, err)),
        }
    } else {
        match insecure_connect(credentials).await {
            Ok(mut ftp_stream) => match ftp_stream.put_with_stream(key).await {
                Ok(mut writer) => match writer.write(data).await {
                    Ok(_) => match writer.flush().await {
                        Ok(_) => {
                            disconnect(Some(&mut ftp_stream), None).await;
                            Ok(())
                        }
                        Err(err) => {
                            disconnect(Some(&mut ftp_stream), None).await;
                            return Err(format!("Unable to write {}: {}", key, err));
                        }
                    },
                    Err(err) => {
                        disconnect(Some(&mut ftp_stream), None).await;
                        return Err(format!("Unable to write {}: {}", key, err));
                    }
                },
                Err(err) => {
                    disconnect(Some(&mut ftp_stream), None).await;
                    return Err(format!("Unable to write {}: {}", key, err));
                }
            },
            Err(err) => Err(format!("Unable to write {}: {}", key, err)),
        }
    }
}

async fn insecure_connect(credentials: &FtpCredentials) -> Result<AsyncFtpStream, String> {
    let result =
        AsyncFtpStream::connect(format!("{}:{}", &credentials.host, &credentials.port)).await;
    if result.is_err() {
        return Err(format!(
            "Unable to connect to FTP server at {}:{}",
            &credentials.host, &credentials.port
        ));
    }

    let mut ftp_stream = result.unwrap();

    let result = ftp_stream
        .login(&credentials.username, &credentials.password)
        .await;
    if result.is_err() {
        return Err("Invalid login credentials".to_string());
    }

    let result = ftp_stream.cwd(&credentials.base_path).await;
    if result.is_err() {
        return Err(format!("Invalid base path: {}", &credentials.base_path));
    }

    Ok(ftp_stream)
}

async fn secure_connect(credentials: &FtpCredentials) -> Result<AsyncNativeTlsFtpStream, String> {
    let result =
        AsyncNativeTlsFtpStream::connect(format!("{}:{}", &credentials.host, &credentials.port))
            .await;
    if result.is_err() {
        return Err(format!(
            "Unable to connect to FTP server at {}:{}",
            &credentials.host, &credentials.port
        ));
    }

    let result = result
        .unwrap()
        .into_secure(
            AsyncNativeTlsConnector::from(TlsConnector::new()),
            &credentials.host,
        )
        .await;
    if result.is_err() {
        return Err("Unable to switch to secure ssl".to_string());
    }

    let mut ftp_stream = result.unwrap();

    let result = ftp_stream
        .login(&credentials.username, &credentials.password)
        .await;
    if result.is_err() {
        return Err("Invalid login credentials".to_string());
    }

    let result = ftp_stream.cwd(&credentials.base_path).await;
    if result.is_err() {
        return Err(format!("Invalid base path: {}", &credentials.base_path));
    }

    Ok(ftp_stream)
}

async fn disconnect(
    insecure_ftp_stream: Option<&mut AsyncFtpStream>,
    secure_ftp_stream: Option<&mut AsyncNativeTlsFtpStream>,
) {
    if insecure_ftp_stream.is_some() && insecure_ftp_stream.unwrap().quit().await.is_ok() {
        return;
    } else if secure_ftp_stream.is_some() && secure_ftp_stream.unwrap().quit().await.is_ok() {
        return;
    }

    eprintln!("Unable to close connection");
}
