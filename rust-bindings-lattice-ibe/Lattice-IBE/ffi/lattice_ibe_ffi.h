#pragma once
#include <cstddef>
#include <memory>

namespace lattice_ibe_ffi {

constexpr std::size_t N0 = 1024;

// Opaque forward declarations – Rust never sees internals.
class MasterPublicKey;
class MasterSecretKey;
class SkIdFFT;
struct Ciphertext { long C[2][N0]; };

struct MasterKeypair {
    std::unique_ptr<MasterPublicKey> pk;
    std::unique_ptr<MasterSecretKey> sk;

    MasterKeypair(std::unique_ptr<MasterPublicKey>&& p,
                std::unique_ptr<MasterSecretKey>&& s) noexcept;

    MasterKeypair(const MasterKeypair&)            = delete;
    MasterKeypair& operator=(const MasterKeypair&) = delete;
    MasterKeypair(MasterKeypair&&) noexcept;
    MasterKeypair& operator=(MasterKeypair&&) noexcept;
    ~MasterKeypair();
};

struct SecretKeyID {
    std::unique_ptr<SkIdFFT> sk_id_fft;
    SecretKeyID(const SecretKeyID&)            = delete;
    SecretKeyID& operator=(const SecretKeyID&) = delete;
    SecretKeyID() noexcept;
    SecretKeyID(SecretKeyID&&) noexcept;
    SecretKeyID& operator=(SecretKeyID&&) noexcept;
    ~SecretKeyID();
};

std::unique_ptr<MasterKeypair>  keygen();            // returns UniquePtr
const MasterPublicKey* keypair_pk(const MasterKeypair& kp);
const MasterSecretKey* keypair_sk(const MasterKeypair& kp);

// ----------------------------  FFI surface  ----------------------------

// Encrypt m[0..N0), identity id[0..N0).
std::unique_ptr<Ciphertext> ibe_encrypt(const MasterPublicKey& pk,
                                        const long*      m,
                                        const long*      id);

// Decrypt into out_msg[0..N0).
void ibe_decrypt(const Ciphertext& ct,
                 const SecretKeyID&  sk_id,
                 long*             out_msg);


std::unique_ptr<SecretKeyID> ibe_extract(const long* id_raw, const MasterSecretKey&  sk);

} // namespace lattice_ibe_ffi