use std::{
    cell::RefCell,
    env,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    rc::Rc,
};

use once_cell::sync::Lazy;

use super::{
    serialization::{ChunkWithoutInputOutput, SerializableChunk, SerializableLayout},
    HashedInput, Layout,
};

use rayon::prelude::*;

static CACHE_LAYOUT_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let path = if let Ok(env_path) = env::var("CACHE_LAYOUT_PATH") {
        PathBuf::from(env_path)
    } else if cfg!(test) {
        PathBuf::from(".cache/test-layout")
    } else {
        PathBuf::from(".cache/layout")
    };

    if !path.exists() {
        eprintln!("Warning: Path {:?} does not exist. Creating it now.", path);

        if let Err(e) = fs::create_dir_all(&path) {
            eprintln!("Error: Failed to create directory {:?}: {:?}", path, e);
        }
    }

    path
});

trait SerializableStack {
    fn from_u8_vec(v: Vec<Vec<u8>>) -> Self;
    fn as_v8_vec(&self) -> Vec<Vec<u8>>;

    fn dump(&self, layout_name: &str, label: &str) -> Result<(), bincode::Error> {
        let subfolder_name = format!("{}.bin", label);
        let cache_path = CACHE_LAYOUT_PATH.join(layout_name).join(subfolder_name);
        let mut file = File::create(&cache_path).expect(format!("Failed to create file: {:?}", cache_path).as_str());
        let encoded = bincode::serialize(&self.as_v8_vec());
        match encoded {
            Ok(encoded) => file.write_all(&encoded).map_err(|e| e.into()),
            Err(e) => Err(e),
        }
    }

    fn load(layout_name: &str, label: &str) -> Result<Self, bincode::Error>
    where
        Self: Sized,
    {
        let subfolder_name = format!("{}.bin", label);
        let cache_path = CACHE_LAYOUT_PATH.join(layout_name).join(subfolder_name);
        let file = File::open(&cache_path).expect(format!("Failed to open file: {:?}", cache_path).as_str());
        let decoded = bincode::deserialize_from(file);
        match decoded {
            Ok(decoded) => Ok(Self::from_u8_vec(decoded)),
            Err(e) => Err(e),
        }
    }
}

impl SerializableChunk {
    fn dump(&self, layout_name: &str, label: &str) -> Result<(), bincode::Error> {
        let subfolder_name = format!("{}.bin", label);
        let cache_path = CACHE_LAYOUT_PATH.join(layout_name).join(subfolder_name);
        let mut file = File::create(&cache_path).expect(format!("Failed to create file: {:?}", cache_path).as_str());
        let encoded = bincode::serialize(&self);
        match encoded {
            Ok(encoded) => file.write_all(&encoded).map_err(|e| e.into()),
            Err(e) => Err(e),
        }
    }

    fn load(layout_name: &str, label: &str) -> Result<Self, bincode::Error> {
        let subfolder_name = format!("{}.bin", label);
        let cache_path = CACHE_LAYOUT_PATH.join(layout_name).join(subfolder_name);
        let file = File::open(&cache_path).expect(format!("Failed to open file: {:?}", cache_path).as_str());
        bincode::deserialize_from(file)
    }
}

impl SerializableLayout {
    fn dump(&self) -> Result<(), bincode::Error> {
        let layout_name = self.name.clone();
        let cache_path = CACHE_LAYOUT_PATH
            .join(layout_name)
            .join(format!("layout-info.bin"));
        let mut file = File::create(&cache_path).expect(format!("Failed to create file: {:?}", cache_path).as_str());
        let encoded = bincode::serialize(&self);
        match encoded {
            Ok(encoded) => file.write_all(&encoded).map_err(|e| e.into()),
            Err(e) => Err(e),
        }
    }

    fn load(name: &str) -> Result<Self, bincode::Error> {
        let layout_name = name;
        let cache_path = CACHE_LAYOUT_PATH
            .join(layout_name)
            .join(format!("layout-info.bin"));
        let file = File::open(&cache_path).expect(format!("Failed to open file: {:?}", cache_path).as_str());
        bincode::deserialize_from(file)
    }
}

impl Layout {
    pub fn saved_chunk_name(i: usize, chunk_name: &str) -> String {
        format!("chunk_{}_{}", i, chunk_name)
    }

    // Serialize the layout and write it to a file.
    pub fn dump(&self) -> Result<(), bincode::Error> {
        let layout_name = self.name.clone();
        let cache_path = CACHE_LAYOUT_PATH
            .join(&layout_name);
        if !cache_path.exists() {
            fs::create_dir_all(&cache_path).expect(format!("Failed to create directory: {:?}", cache_path).as_str());
        }
        let chunk_names: Vec<String> = self
            .chunks
            .iter()
            .map(|c| c.as_ref().borrow().name.clone())
            .collect();
        let mut inputs: Vec<(usize, usize, usize)> = vec![];
        for (index, c) in self.chunks.iter().enumerate() {
            let chunk = c.as_ref().borrow();
            let arc_indices: Vec<(usize, usize, usize)> = chunk
                .inputs
                .iter()
                .filter_map(|input_index| {
                    for (i, c) in self.chunks.iter().enumerate() {
                        if Rc::ptr_eq(c, &input_index.outputting_chunk) {
                            return Some((index, i, input_index.output_index));
                        }
                    }
                    return None;
                })
                .collect();
            inputs.extend(arc_indices);
        }
        let mut outputs: Vec<(usize, usize)> = vec![];
        for (index, c) in self.chunks.iter().enumerate() {
            let chunk = c.as_ref().borrow();
            let arc_indices: Vec<(usize, usize)> = chunk
                .outputs
                .iter()
                .map(|output_index| (index, *output_index))
                .collect();
            outputs.extend(arc_indices);
        }
        let serializable_layout = SerializableLayout {
            chunk_names,
            name: layout_name.clone(),
            outputs,
            inputs,
        };
        let chunk_withouts: Vec<ChunkWithoutInputOutput> = self
            .chunks
            .iter()
            .map(|c| ChunkWithoutInputOutput::from_chunk(&c.as_ref().borrow()))
            .collect();

        let res = chunk_withouts
            .par_iter()
            .enumerate()
            .try_for_each(|(i, c)| {
                let cs = c.as_serializable();
                cs.dump(
                    &layout_name.clone(),
                    Layout::saved_chunk_name(i, &cs.name).as_str(),
                )
            });

        match res {
            Ok(_) => {
                let res = serializable_layout.dump();
                match res {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn load(layout_name: &str) -> Self {
        let serializable_layout = SerializableLayout::load(layout_name).unwrap();
        let mut chunks = vec![];
        for (i, chunk_name) in serializable_layout.chunk_names.iter().enumerate() {
            let chunk =
                SerializableChunk::load(layout_name, &Layout::saved_chunk_name(i, chunk_name))
                    .unwrap();
            let chunk_without = ChunkWithoutInputOutput::from_serializable(chunk);
            let chunk = chunk_without.into_chunk();
            chunks.push(Rc::new(RefCell::new(chunk)));
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let mut chunk = chunk.borrow_mut();
            chunk.inputs = serializable_layout
                .inputs
                .iter()
                .filter_map(|pair| {
                    if pair.0 == i {
                        Some(HashedInput::new(chunks[pair.1].clone(), pair.2))
                    } else {
                        None
                    }
                })
                .collect();
            chunk.outputs = serializable_layout
                .outputs
                .iter()
                .filter_map(|pair| if pair.0 == i { Some(pair.1) } else { None })
                .collect();
        }
        let mut layout = Layout::new(layout_name);
        layout.chunks = chunks;
        layout
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::panic;
    use std::path::PathBuf;
    use std::rc::Rc;

    use crate::layout::example::example_combine_layout;
    use crate::layout::example::example_split_layout;
    use crate::layout::Layout;

    use super::CACHE_LAYOUT_PATH;

    #[test]
    fn test_dump_example_combine_layout() {
        let path: &PathBuf = &*CACHE_LAYOUT_PATH;
        fs::create_dir_all(path).expect("Failed to create cache directory");

        let result = panic::catch_unwind(|| {
            let layout_0 = example_combine_layout();
            layout_0.dump().unwrap();
            let layout_1 = Layout::load(layout_0.name.as_str());
            for (c0, c1) in layout_0.chunks.iter().zip(layout_1.chunks.iter()) {
                let c0 = c0.borrow();
                let c1 = c1.borrow();
                assert!(c0.name == c1.name);
                assert!(c0.execution_script.len() == c1.execution_script.len());
                assert!(c0.hints == c1.hints);
                let c0_output_indexs: Vec<usize> =
                    c0.inputs.iter().map(|i| i.output_index).collect();
                let c1_output_indexs: Vec<usize> =
                    c1.inputs.iter().map(|i| i.output_index).collect();
                assert!(c0_output_indexs == c1_output_indexs);
                assert!(c0.outputs == c1.outputs);
            }
        });

        fs::remove_dir_all(path).unwrap();

        if let Err(err) = result {
            panic::resume_unwind(err);
        }
    }


    #[test]
    fn test_dump_example_split_layout() {
        let path: &PathBuf = &*CACHE_LAYOUT_PATH;
        fs::create_dir_all(path).expect("Failed to create cache directory");

        let result = panic::catch_unwind(|| {
            let layout_0 = example_split_layout();
            layout_0.dump().unwrap();
            let layout_1 = Layout::load(layout_0.name.as_str());
            for (c0, c1) in layout_0.chunks.iter().zip(layout_1.chunks.iter()) {
                let c0 = c0.borrow();
                let c1 = c1.borrow();
                assert!(c0.name == c1.name);
                assert!(c0.execution_script.len() == c1.execution_script.len());
                assert!(c0.hints == c1.hints);
                let c0_output_indexs: Vec<usize> =
                    c0.inputs.iter().map(|i| i.output_index).collect();
                let c1_output_indexs: Vec<usize> =
                    c1.inputs.iter().map(|i| i.output_index).collect();
                assert!(c0_output_indexs == c1_output_indexs);
                assert!(c0.outputs == c1.outputs);
            }
        });

        fs::remove_dir_all(path).unwrap();

        if let Err(err) = result {
            panic::resume_unwind(err);
        }
    }
}
