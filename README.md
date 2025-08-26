# Practical Post-Quantum Secure Publicly Verifiable Secret Sharing and Applications

This repository contains the benchmarking code and experimental artifacts for the paper:

**Practical Post-Quantum Secure Publicly Verifiable Secret Sharing and Applications**

---

## 📦 Prerequisites

Our schemes rely on the [Lattice-IBE library](https://github.com/tprest/Lattice-IBE), which requires the [NTL](https://www.shoup.net/ntl/) and [GMP](https://gmplib.org/) libraries to be installed.

### 1. Install NTL and GMP

On **macOS**, you can install NTL via Homebrew:

```bash
brew install ntl
```

Make sure GMP is also installed (e.g., `brew install gmp`).

### 2. Adjust Include Paths

In the following files:

- `rust-bindings-lattice-ibe/Lattice-IBE/Makefile`  
- `rust-bindings-lattice-ibe/build.rs`  

update the **include paths** for `ntl` and `gmp` according to your system installation.  
After these adjustments, you should be able to build the Lattice-IBE library successfully.

---

## ▶️ Running Benchmarks

### PVSS Benchmarks

Adjust n and t as required in test_share_basic in the following files:

- `pqppvss/prot_pvss_hash_ibe.rs`  
- `pqppvss/prot_pvss_pedcom_ibe.rs`  

Then to run the benchmarks:

```bash
cd pqppvss
cargo test --release --package pqppvss --lib -- prot_pvss_hash_ibe::tests::test_share_basic --exact --show-output
```


```bash
cd pqppvss
cargo test --release --package pqppvss --lib -- prot_pvss_pedcom_ibe::tests::test_share_basic --exact --show-output
```

### Private Polling Benchmarks

To run the polling benchmarks:

```bash
cd private-polling/rust/private_polling/
cargo bench -- --nocapture
```

---

## 📖 Notes

- All benchmarks are run in **release mode** to ensure optimized performance results.  
- Please ensure your Rust toolchain is up to date (`rustup update`).  
- Results may vary depending on your hardware and system configuration.  

