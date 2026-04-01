use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // Generate vmlinux.h from running kernel's BTF
    let vmlinux_path = format!("{out_dir}/vmlinux.h");
    if !Path::new(&vmlinux_path).exists() {
        let output = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("Failed to run bpftool — is bpftool installed?");
        assert!(
            output.status.success(),
            "bpftool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(&vmlinux_path, &output.stdout).expect("Failed to write vmlinux.h");
    }

    // Build BPF skeleton
    libbpf_cargo::SkeletonBuilder::new()
        .source("src/bpf/main.bpf.c")
        .clang_args([format!("-I{out_dir}"), "-Isrc/bpf".into()])
        .build_and_generate(format!("{out_dir}/skel.rs"))
        .expect("Failed to build BPF skeleton");

    println!("cargo:rerun-if-changed=src/bpf/main.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/intf.h");
}
