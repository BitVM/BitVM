use once_cell::sync::Lazy;
use regex::Regex;
use std::cmp::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::base::DataStoreDriver;
use super::{
    aws_s3::AwsS3,
    ftp::{ftp::Ftp, ftps::Ftps},
    sftp::Sftp,
};

static CLIENT_MISSING_CREDENTIALS_ERROR: &str =
    "Bridge client is missing AWS S3, FTP, FTPS, or SFTP credentials";

static CLIENT_DATA_SUFFIX: &str = "-bridge-client-data-musig2.json";
static CLIENT_DATA_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r"(\d{{13}}){}", CLIENT_DATA_SUFFIX)).unwrap());

pub struct DataStore {
    aws_s3: Option<AwsS3>,
    ftp: Option<Ftp>,
    ftps: Option<Ftps>,
    sftp: Option<Sftp>,
}

impl DataStore {
    pub fn new() -> Self {
        Self {
            aws_s3: AwsS3::new(),
            ftp: None,  // Ftp::new(),
            ftps: None, // Ftps::new(),
            sftp: None, // Sftp::new(),
        }
    }

    pub fn get_file_timestamp(file_name: &String) -> Result<u64, String> {
        if CLIENT_DATA_REGEX.is_match(file_name) {
            let mut timestamp_string = file_name.clone();
            timestamp_string.truncate(13);
            let timestamp = timestamp_string.parse::<u64>();
            return match timestamp {
                Ok(_) => Ok(timestamp.unwrap()),
                Err(_) => Err(String::from("Failed to parse file timestamp")),
            };
        }

        Err(String::from("Incorrect file name"))
    }

    pub async fn get_file_names(&self, file_path: Option<&str>) -> Result<Vec<String>, String> {
        match self.get_driver() {
            Ok(driver) => match driver.list_objects(file_path).await {
                Ok(keys) => {
                    let mut data_keys: Vec<String> = keys
                        .iter()
                        .map(|key| key.rsplit("/").next().unwrap().to_string())
                        .collect();

                    data_keys = data_keys
                        .iter()
                        .filter(|key| CLIENT_DATA_REGEX.is_match(key))
                        .cloned()
                        .collect();
                    data_keys.sort_by(|x, y| {
                        if x < y {
                            return Ordering::Less;
                        }
                        return Ordering::Greater;
                    });

                    Ok(data_keys)
                }
                Err(err) => Err(err.to_string()),
            },
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn fetch_data_by_key(
        &self,
        key: &String,
        file_path: Option<&str>,
    ) -> Result<Option<String>, String> {
        match self.get_driver() {
            Ok(driver) => {
                let json = driver.fetch_json(key, file_path).await;
                if json.is_ok() {
                    // println!("Fetched data file: {}", key);
                    return Ok(Some(json.unwrap()));
                }

                println!("No data file {} found", key);
                Ok(None)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn write_data(
        &self,
        json: String,
        file_path: Option<&str>,
    ) -> Result<String, String> {
        match self.get_driver() {
            Ok(driver) => {
                let time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();
                let key = Self::create_file_name(time);
                let response = driver.upload_json(&key, json, file_path).await;

                match response {
                    Ok(_) => Ok(key),
                    Err(_) => Err(String::from("Failed to save data file")),
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn get_past_max_file_name_by_timestamp(latest_timestamp: u64, period: u64) -> String {
        let past_max_timestamp =
            (Duration::from_millis(latest_timestamp) - Duration::from_secs(period)).as_millis();
        let past_max_file_name = Self::create_file_name(past_max_timestamp);

        return past_max_file_name;
    }

    fn create_file_name(timestamp: u128) -> String {
        return format!("{}{}", timestamp, CLIENT_DATA_SUFFIX);
    }

    fn get_driver(&self) -> Result<&dyn DataStoreDriver, &str> {
        if self.aws_s3.is_some() {
            return Ok(self.aws_s3.as_ref().unwrap());
        } else if self.ftp.is_some() {
            return Ok(self.ftp.as_ref().unwrap());
        } else if self.ftps.is_some() {
            return Ok(self.ftps.as_ref().unwrap());
        } else if self.sftp.is_some() {
            return Ok(self.sftp.as_ref().unwrap());
        } else {
            Err(CLIENT_MISSING_CREDENTIALS_ERROR)
        }
    }
}
