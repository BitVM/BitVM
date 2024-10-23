use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use bitcoin::ScriptBuf;
use bitcoin_script::Script;
use serde::Deserialize;
use serde::Serialize;

use crate::treepp;

use super::Chunk;
use super::Hint;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableHint {
    pub label: String,
    pub bytes: Vec<u8>,
}

impl Hint {
    pub fn as_serializable(&self) -> SerializableHint {
        match self {
            Hint::Fr(fr) => SerializableHint {
                label: "Fr".to_string(),
                bytes: {
                    let mut bytes = Vec::new();
                    fr.serialize_uncompressed(&mut bytes).unwrap();
                    bytes
                },
            },
            Hint::Fq(fq) => SerializableHint {
                label: "Fq".to_string(),
                bytes: {
                    let mut bytes = Vec::new();
                    fq.serialize_uncompressed(&mut bytes).unwrap();
                    bytes
                },
            },
        }
    }
    pub fn from_serializable(v: &SerializableHint) -> Self {
        match v.label.as_str() {
            "Fr" => Hint::Fr(ark_bn254::Fr::deserialize_uncompressed(&v.bytes[..]).unwrap()),
            "Fq" => Hint::Fq(ark_bn254::Fq::deserialize_uncompressed(&v.bytes[..]).unwrap()),
            _ => panic!("Unknown hint type."),
        }
    }
}

impl Serialize for Hint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_serializable().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Hint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Hint::from_serializable(&SerializableHint::deserialize(
            deserializer,
        )?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableChunk {
    pub hints: Vec<SerializableHint>,
    pub execution_script_buf: Vec<u8>,
    pub name: String,
}

pub struct ChunkWithoutInputOutput {
    hints: Vec<Hint>,
    execution_script: Script,
    name: String,
}

impl ChunkWithoutInputOutput {
    pub fn as_serializable(&self) -> SerializableChunk {
        SerializableChunk {
            hints: self.hints.iter().map(|h| h.as_serializable()).collect(),
            execution_script_buf: {
                let script_buf = self.execution_script.clone().compile();
                script_buf.into_bytes()
            },
            name: self.name.clone(),
        }
    }

    pub fn from_serializable(v: SerializableChunk) -> Self {
        let mut script = treepp::Script::new("deserialized_script");
        script = script.push_script(ScriptBuf::from_bytes(v.execution_script_buf));
        ChunkWithoutInputOutput {
            hints: v.hints.iter().map(|h| Hint::from_serializable(h)).collect(),
            execution_script: script,
            name: v.name.clone(),
        }
    }

    pub fn from_chunk(chunk: &Chunk) -> Self {
        ChunkWithoutInputOutput {
            hints: chunk.hints.clone(),
            execution_script: chunk.execution_script.clone(),
            name: chunk.name.clone(),
        }
    }

    pub fn into_chunk(self) -> Chunk {
        Chunk {
            hints: self.hints,
            execution_script: self.execution_script,
            name: self.name,
            inputs: vec![],
            outputs: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableLayout {
    pub chunk_names: Vec<String>,
    pub name: String,
    // (chunk_index, output_chunk)
    pub outputs: Vec<(usize, usize)>,
    // (chunk_index, input_chunk_index, input_chunk_output_index)
    pub inputs: Vec<(usize, usize, usize)>,
}
