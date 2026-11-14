use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/ebpf/pathchord_tproxy.c");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let object = out_dir.join("pathchord_tproxy.o");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        fs::write(&object, []).expect("write non-Linux eBPF placeholder");
        println!("cargo:rustc-env=PATHCHORD_EBPF_OBJECT={}", object.display());
        return;
    }

    let source = PathBuf::from("src/ebpf/pathchord_tproxy.c");
    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-c",
            source.to_str().expect("eBPF source path"),
            "-o",
            object.to_str().expect("eBPF object path"),
        ])
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => {
            let _ = fs::write(&object, []);
            println!(
                "cargo:warning=PathChord eBPF object generation failed with status {status}; the ebpf backend will report an unavailable diagnostic"
            );
        }
        Err(error) => {
            let _ = fs::write(&object, []);
            println!(
                "cargo:warning=clang is unavailable ({error}); the ebpf backend will report an unavailable diagnostic"
            );
        }
    }
    println!("cargo:rustc-env=PATHCHORD_EBPF_OBJECT={}", object.display());
}
