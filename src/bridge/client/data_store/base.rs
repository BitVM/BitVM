use async_trait::async_trait;

#[async_trait]
pub trait DataStoreDriver {
    async fn list_objects(&self, file_path: Option<&str>) -> Result<Vec<String>, String>;
    async fn fetch_json(&self, key: &str, file_path: Option<&str>) -> Result<String, String>;
    async fn upload_json(
        &self,
        key: &str,
        json: String,
        file_path: Option<&str>,
    ) -> Result<usize, String>;
}
