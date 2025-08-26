use std::fs;
use autocxx_build::Builder;
use std::path::PathBuf;

fn main() -> miette::Result<()> {
    let cpp_dir   = PathBuf::from("./Lattice-IBE");
    let ffi_dir   = cpp_dir.join("ffi");
    let ffi_src   = ffi_dir.join("lattice_ibe_ffi.cc");

    // ①  Directories that hold headers ────────────────────────┐
    let mut build = Builder::new(
        "src/lib.rs",
        &[ cpp_dir.to_str().unwrap(),           //  …/Latice-IBE
            ffi_dir.to_str().unwrap() ]           //  …/Latice-IBE/ffi
    )
        // ②  Compiler flags go here (extra_clang_args) ────────┘
        .extra_clang_args(&[
            "-std=c++17",
            "-I/opt/homebrew/Cellar/ntl/11.5.1/include",
            "-I/opt/homebrew/Cellar/gmp/6.3.0/include",
        ])
        .build()                      // → cc::Build
        .expect("autocxx codegen failed");

    // add wrapper translation unit, optimise, link
    build.file(&ffi_src);

    // 3) add **all the real scheme sources** (skip main.cc if present)
    for entry in fs::read_dir(&cpp_dir).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().and_then(|s| s.to_str()) == Some("cc")
            && p.file_name().unwrap() != "main.cc"
        {
            build.file(&p);
        }
    }

    // 4) search paths & optimisation flags
    build
        .include("/opt/homebrew/Cellar/ntl/11.5.1/include")
        .include("/opt/homebrew/Cellar/gmp/6.3.0/include")
        .include("/opt/homebrew/include")
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-Ofast")
        .compile("latice_ibe_ffi");

    println!("cargo:rerun-if-changed={}", ffi_src.display());
    println!("cargo:rerun-if-changed=build.rs");
    // NTL and GMP search paths
    println!("cargo:rustc-link-search=native=/opt/homebrew/Cellar/ntl/11.5.1/lib");
    println!("cargo:rustc-link-search=native=/opt/homebrew/Cellar/gmp/6.3.0/lib");
    println!("cargo:rustc-link-lib=dylib=ntl");
    println!("cargo:rustc-link-lib=dylib=gmp");

    Ok(())
}
