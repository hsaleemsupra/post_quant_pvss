#include "lattice_ibe_ffi.h"
#include "../Scheme.h"
#include "FFT.h"

#include <array>

namespace lattice_ibe_ffi {

class MasterPublicKey {
public:
    ZZ_pX MPK;
    MPK_Data MPKD;
};

class MasterSecretKey {
public:
    ZZX MSK[4];
    MSK_Data MSKD;
};

class SkIdFFT {
public:
    CC_t inner[N0];
};

MasterKeypair::MasterKeypair(std::unique_ptr<MasterPublicKey>&& p,
                 std::unique_ptr<MasterSecretKey>&& s) noexcept
    : pk(std::move(p)), sk(std::move(s)) {}

MasterKeypair::MasterKeypair(MasterKeypair&&) noexcept            = default;
MasterKeypair& MasterKeypair::operator=(MasterKeypair&&) noexcept = default;
MasterKeypair::~MasterKeypair()                             = default;

SecretKeyID::SecretKeyID(SecretKeyID&&) noexcept            = default;
SecretKeyID::SecretKeyID() noexcept
    : sk_id_fft(std::make_unique<SkIdFFT>()) {};
SecretKeyID& SecretKeyID::operator=(SecretKeyID&&) noexcept = default;
SecretKeyID::~SecretKeyID()                             = default;

std::unique_ptr<MasterKeypair> keygen()
{
    auto pk = std::make_unique<MasterPublicKey>();
    auto sk = std::make_unique<MasterSecretKey>();

    ::Keygen(pk->MPK, sk->MSK);
    CompleteMSK(&sk->MSKD, sk->MSK);
    CompleteMPK(&pk->MPKD, pk->MPK);

    return std::make_unique<MasterKeypair>(std::move(pk), std::move(sk));
}

const MasterPublicKey* keypair_pk(const MasterKeypair& kp) { return kp.pk.get(); }
const MasterSecretKey* keypair_sk(const MasterKeypair& kp) { return kp.sk.get(); }

// ---------- encrypt --------------------------------------------------
std::unique_ptr<Ciphertext> ibe_encrypt(const MasterPublicKey& pk,
                                        const long*      m,
                                        const long*      id)
{
    auto ct = std::make_unique<Ciphertext>();
    IBE_Encrypt(ct->C, m, id, &pk.MPKD);
    return ct;
}

// ---------- decrypt --------------------------------------------------
void ibe_decrypt(const Ciphertext& ct,
                 const SecretKeyID&  sk_id,
                 long*             out_msg)
{
    IBE_Decrypt(out_msg, ct.C, sk_id.sk_id_fft->inner);
}

std::unique_ptr<SecretKeyID> ibe_extract(const long* id_raw, const MasterSecretKey&  sk){

    auto sk_id = std::make_unique<SecretKeyID>();

    vec_ZZ id;
    id.SetLength(N0);
    for (unsigned i = 0; i < N0; ++i)
        id[i] = conv<ZZ>( id_raw[i] );

    ZZX SK_id[2];
    IBE_Extract(SK_id, id, &sk.MSKD);
    ZZXToFFT(sk_id->sk_id_fft->inner, SK_id[1]);
    return sk_id;
}

} // namespace lattice_ibe_ffi