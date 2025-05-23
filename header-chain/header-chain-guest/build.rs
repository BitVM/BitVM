use risc0_binfmt::compute_image_id;
use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::{collections::HashMap, env, fs, path::Path};

fn main() {
    // Build environment variables
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    // Compile time constant environment variables
    println!("cargo:rerun-if-env-changed=BITCOIN_NETWORK");
    println!("cargo:rerun-if-env-changed=TEST_SKIP_GUEST_BUILD");

    if std::env::var("CLIPPY_ARGS").is_ok() {
        let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
        let dummy_path = Path::new(&out_dir).join("methods.rs");
        fs::write(dummy_path, "// dummy methods.rs for Clippy\n")
            .expect("Failed to write dummy methods.rs");
        println!("cargo:warning=Skipping guest build in Clippy");
        return;
    }

    // Check if we should skip the guest build for tests
    if let Ok("1" | "true") = env::var("TEST_SKIP_GUEST_BUILD").as_deref() {
        println!("cargo:warning=Skipping guest build in test. Exiting");
        return;
    }

    let network = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| {
        println!("cargo:warning=BITCOIN_NETWORK not set, defaulting to 'mainnet'");
        "mainnet".to_string()
    });
    println!("cargo:warning=Building for Bitcoin network: {}", network);

    let is_repr_guest_build = match env::var("REPR_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=REPR_GUEST_BUILD is set to true");
                true
            }
            "0" | "false" => {
                println!("cargo:warning=REPR_GUEST_BUILD is set to false");
                false
            }
            _ => {
                println!("cargo:warning=Invalid value for REPR_GUEST_BUILD: '{}'. Expected '0', '1', 'true', or 'false'. Defaulting to false.", value);
                false
            }
        },
        Err(env::VarError::NotPresent) => {
            println!("cargo:warning=REPR_GUEST_BUILD not set. Defaulting to false.");
            false
        }
        Err(env::VarError::NotUnicode(_)) => {
            println!(
                "cargo:warning=REPR_GUEST_BUILD contains invalid Unicode. Defaulting to false."
            );
            false
        }
    };

    // Use embed_methods_with_options with our custom options
    let guest_pkg_to_options = get_guest_options(network.clone());
    embed_methods_with_options(guest_pkg_to_options);

    // After the build is complete, copy the generated file to the elfs folder
    if is_repr_guest_build {
        println!("cargo:warning=Copying binary to elfs folder");
        copy_binary_to_elfs_folder(network);
    } else {
        println!("cargo:warning=Not copying binary to elfs folder");
    }
}

fn get_guest_options(network: String) -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut guest_pkg_to_options = HashMap::new();

    let opts = if env::var("REPR_GUEST_BUILD").is_ok() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let root_dir = format!("{manifest_dir}/../../");

        println!(
            "cargo:warning=Using Docker for guest build with root dir: {}",
            root_dir
        );

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .env(vec![("BITCOIN_NETWORK".to_string(), network.clone())])
            .build()
            .unwrap();

        GuestOptionsBuilder::default()
            // .features(features)
            .use_docker(docker_opts)
            .build()
            .unwrap()
    } else {
        println!("cargo:warning=Guest code is not built in docker");
        GuestOptionsBuilder::default()
            // .features(features)
            .build()
            .unwrap()
    };

    guest_pkg_to_options.insert("header-chain-guest", opts);
    guest_pkg_to_options
}

fn copy_binary_to_elfs_folder(network: String) {
    let current_dir = env::current_dir().expect("Failed to get current dir");
    // base_dir will be /home/ozan/workspace/BitVM/
    let base_dir = current_dir
        .join("../..")
        .canonicalize()
        .expect("Failed to canonicalize base_dir");

    // Create elfs directory if it doesn't exist
    let elfs_dir = base_dir.join("prover/elfs");
    if !elfs_dir.exists() {
        fs::create_dir_all(&elfs_dir).expect("Failed to create elfs directory");
        println!("cargo:warning=Created elfs directory at {:?}", elfs_dir);
    }

    // Build source path (ensure this path is correct based on risc0_build's actual output location)
    // This path assumes a specific structure relative to the workspace root.
    // A more robust way might be to get this path from OUT_DIR if risc0_build places it there predictably.
    let src_path = base_dir.join("target/riscv-guest/header-chain-circuit/header-chain-guest/riscv32im-risc0-zkvm-elf/docker/header-chain-guest.bin");

    if !src_path.exists() {
        // If the source ELF from the Docker build isn't found, the copy will fail.
        // This could indicate an issue with the guest build itself or the path construction.
        // The Docker build log (#8 and #9) suggests the ELF is built.
        // RISC0 build scripts often place final ELFs in OUT_DIR/{method_name}.
        // Consider using: let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        //                let src_path = out_dir.join("header-chain-guest"); // or "header-chain-guest.elf" / ".bin"
        println!(
            "cargo:warning=Source binary not found at {:?}, skipping copy. This might be the root cause if copy fails.",
            src_path
        );
        // It's important to ensure src_path is correct. For now, we assume it is based on your log.
        // If the copy fails below, investigate src_path more deeply.
        // return; // Or panic, as subsequent steps depend on this.
    }

    // Build destination path with network prefix
    let dest_filename = format!("{}-header-chain-guest.bin", network.to_lowercase());
    let dest_path = elfs_dir.join(&dest_filename); // This is an absolute PathBuf

    // Copy the file
    match fs::copy(&src_path, &dest_path) {
        Ok(_) => println!(
            "cargo:warning=Successfully copied binary from {:?} to {:?}",
            src_path, dest_path
        ),
        Err(e) => {
            // If the copy fails, the subsequent read will definitely fail.
            // It's crucial to handle this, e.g., by panicking to stop the build with a clear message.
            panic!(
                "Failed to copy binary from {:?} to {:?}: {}. Subsequent ELF read will fail.",
                src_path, dest_path, e
            );
        }
    }

    // The `elf_path` string below is used as a logical identifier or for constructing paths within the prover,
    // but it should not be used directly for fs::read from the build script's CWD.
    let logical_elf_path_for_id = match network.as_str() {
        "mainnet" => "prover/elfs/mainnet-header-chain-guest.bin",
        "testnet4" => "prover/elfs/testnet4-header-chain-guest.bin",
        "signet" => "prover/elfs/signet-header-chain-guest.bin",
        "regtest" => "prover/elfs/regtest-header-chain-guest.bin",
        _ => {
            println!(
                "cargo:warning=Invalid network specified, defaulting to mainnet for logical path"
            );
            "prover/elfs/mainnet-header-chain-guest.bin"
        }
    };

    println!(
        "cargo:warning=Logical ELF path for ID computation: {:?}",
        logical_elf_path_for_id
    );

    // --- THIS IS THE FIX ---
    // Read the ELF file from `dest_path`, where it was actually copied.
    // `dest_path` is already an absolute `PathBuf`.
    println!(
        "cargo:warning=Attempting to read ELF file from: {:?}",
        dest_path
    );
    let elf_bytes: Vec<u8> = fs::read(&dest_path) // Use &dest_path here
        .unwrap_or_else(|e| panic!("Failed to read ELF file from {:?}: {}", dest_path, e));

    let method_id = compute_image_id(elf_bytes.as_slice()).unwrap();
    println!("cargo:warning=Computed method ID: {:x?}", method_id);
    println!(
        "cargo:warning=Computed method ID words: {:?}",
        method_id.as_words()
    );
}
