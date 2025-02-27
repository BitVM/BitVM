use serde::{Deserialize, Serialize};

pub fn serialize(object: &impl Serialize) -> String {
    serde_json::to_string(object)
        .map_err(|e| format!("Failed to serialize an object to JSON: {}", e))
        .unwrap()
}

pub fn deserialize<'a, T>(data: &'a str) -> T
where
    T: Deserialize<'a>,
{
    serde_json::from_str::<T>(data).unwrap()
}

pub fn try_deserialize<'a, T>(data: &'a str) -> Result<T, String>
where
    T: Deserialize<'a>,
{
    match serde_json::from_str::<T>(data) {
        Ok(x) => Ok(x),
        Err(err) => Err(format!("Failed to parse JSON string to object: {}", err)),
    }
}

pub fn try_deserialize_slice<'a, T>(data: &'a [u8]) -> Result<T, String>
where
    T: Deserialize<'a>,
{
    match serde_json::from_slice::<T>(data) {
        Ok(x) => Ok(x),
        Err(err) => Err(format!("Failed to decode JSON data to object: {}", err)),
    }
}
