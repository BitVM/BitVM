use once_cell::sync::Lazy;
use regex::Regex;
use std::cmp::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::aws_s3::AwsS3;

static CLIENT_MISSING_CREDENTIALS_ERROR: &str = "Bridge client is missing AWS S3 credentials";

static CLIENT_DATA_SUFFIX: &str = "-bridge-client-data.json";
static CLIENT_DATA_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r"(\d{{13}}){}", CLIENT_DATA_SUFFIX)).unwrap());

pub struct DataStore {
    aws_s3: Option<AwsS3>,
}

impl DataStore {
    pub fn new() -> Self {
        Self {
            aws_s3: AwsS3::new(),
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
        return Err(String::from("Incorrect file name"));
    }

    pub async fn get_file_names(&self) -> Result<Vec<String>, String> {
        if self.aws_s3.is_none() {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR.to_string());
        }

        let keys = self.aws_s3.as_ref().unwrap().list_objects().await;
        let mut data_keys: Vec<String> = keys
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

        return Ok(data_keys);
    }

    pub async fn fetch_data_by_key(&self, key: &String) -> Result<Option<String>, String> {
        if self.aws_s3.is_none() {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR.to_string());
        }

        let json = self.aws_s3.as_ref().unwrap().fetch_json(key).await;
        if json.is_ok() {
            println!("Fetched data file: {}", key);
            return Ok(Some(json.unwrap()));
        }

        println!("No data file {} found", key);
        return Ok(None);
    }

    pub async fn fetch_latest_data(&self) -> Result<Option<String>, String> {
        if self.aws_s3.is_none() {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR.to_string());
        }

        let keys = self.aws_s3.as_ref().unwrap().list_objects().await;
        let mut data_keys: Vec<String> = keys
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

        while let Some(key) = data_keys.pop() {
            let json = self.aws_s3.as_ref().unwrap().fetch_json(&key).await;
            if json.is_ok() {
                println!("Fetched latest data file: {}", key);
                return Ok(Some(json.unwrap()));
            }
        }

        println!("No data file found");
        Ok(None)
    }

    pub async fn write_data(&self, json: String) -> Result<String, String> {
        if self.aws_s3.is_none() {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR.to_string());
        }

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let key = Self::create_file_name(time);

        let response = self.aws_s3.as_ref().unwrap().upload_json(&key, json).await;

        match response {
            Ok(_) => Ok(key),
            Err(_) => Err(String::from("Failed to save data file")),
        }
    }

    pub fn get_past_max_file_name_by_timestamp(latest_timestamp: u64, period: u64) -> String {
        let past_max_timestamp =
            (Duration::from_millis(latest_timestamp) - Duration::from_secs(period)).as_millis();
        let past_max_file_name = Self::create_file_name(past_max_timestamp);

        return past_max_file_name;
    }

    pub fn create_file_name(timestamp: u128) -> String {
        return format!("{}{}", timestamp, CLIENT_DATA_SUFFIX);
    }
}
