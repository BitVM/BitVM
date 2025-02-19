use async_trait::async_trait;

#[async_trait]
pub trait DataStoreDriver {
    async fn list_objects(&self, file_path: Option<&str>) -> Result<Vec<String>, String>;
    async fn fetch_object(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> Result<String, String>;
    async fn upload_object(
        &self,
        file_name: &str,
        contents: &str,
        file_path: Option<&str>,
    ) -> Result<usize, String>;
    async fn fetch_compressed_object(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> Result<(Vec<u8>, usize), String>;
    async fn upload_compressed_object(
        &self,
        file_name: &str,
        contents: &Vec<u8>,
        file_path: Option<&str>,
    ) -> Result<usize, String>;
}
