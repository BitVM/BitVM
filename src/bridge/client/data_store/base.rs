use async_trait::async_trait;

#[async_trait]
pub trait DataStoreDriver {
    async fn list_objects(&self) -> Result<Vec<String>, String>;
    async fn fetch_json(&self, key: &str) -> Result<String, String>;
    async fn upload_json(&self, key: &str, json: String) -> Result<usize, String>;
}
