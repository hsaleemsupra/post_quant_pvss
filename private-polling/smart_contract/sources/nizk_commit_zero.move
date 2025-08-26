module Sender::nizk_commit_zero {

    use std::option::Option;
    use std::vector;
    use aptos_std::ristretto255::{RistrettoPoint, Scalar, point_clone, point_identity, point_equals, point_mul,
        point_sub_assign, point_to_bytes, point_compress, new_scalar_from_sha2_512, scalar_equals, new_scalar_from_bytes
    };

    struct ZkInstancePedersenZero has drop {
        g: RistrettoPoint,
        h: RistrettoPoint,
        commit: RistrettoPoint,
    }

    struct ZkProofPedersenZero has drop {
        z: Scalar,
        c: Scalar
    }

    struct ZkProofElgamalZeroBytes has copy, drop, store{
        z: vector<u8>,
        c: vector<u8>
    }

    public fun get_nizk_pedersen_zero_bytes(z: vector<u8>, c: vector<u8>): ZkProofElgamalZeroBytes{

        ZkProofElgamalZeroBytes{
            z,
            c
        }
    }
    
    public fun nizk_pedersen_zero_from_bytes(bytes: &ZkProofElgamalZeroBytes): Option<ZkProofPedersenZero>{

        let z_option = new_scalar_from_bytes(bytes.z);
        let c_option = new_scalar_from_bytes(bytes.c);

        if(std::option::is_none(&z_option) || std::option::is_none(&c_option)){
            std::option::none<ZkProofPedersenZero>()
        }
        else{
            std::option::some(
                ZkProofPedersenZero {
                    z: std::option::extract(&mut z_option),
                    c: std::option::extract(&mut c_option),
                })
        }
    }

    public fun get_zkproof_pedersen_zero(z: Scalar, c: Scalar): ZkProofPedersenZero {
        let proof = ZkProofPedersenZero {
            z,
            c
        };
        proof
    }

    public fun get_domain_separator_nizk_elgamal_zero(): vector<u8>{
        let domain_str:vector<u8> = b"crypto-ristretto-zk-proof-of-pedersen-zero-challenge";
        domain_str
    }

    public fun create_nizk_pedersen_zero_instance(g: &RistrettoPoint, h: &RistrettoPoint,
                                                  commit: &RistrettoPoint): ZkInstancePedersenZero {

        ZkInstancePedersenZero {
            g: point_clone(g),
            h: point_clone(h),
            commit: point_clone(commit),
        }
    }

    fun check_instance(instance: &ZkInstancePedersenZero): bool{
        let identity = point_identity();
        if (point_equals(&instance.h, &identity) ||
            point_equals(&instance.commit, &identity) )
            {
                false;
            };

        true
    }

    fun zk_pedersen_zero_proof_challenge(instance: &ZkInstancePedersenZero, aa: &RistrettoPoint): Scalar{

        let transcript:vector<u8> = vector::empty<u8>();

        let g = point_to_bytes(&point_compress(&instance.g));
        let h = point_to_bytes(&point_compress(&instance.h));
        let commitment= point_to_bytes(&point_compress(&instance.commit));
        let a = point_to_bytes(&point_compress(aa));

        vector::append(&mut transcript, get_domain_separator_nizk_elgamal_zero());
        vector::append(&mut transcript, b"g");
        vector::append(&mut transcript, g);
        vector::append(&mut transcript, b"h");
        vector::append(&mut transcript, h);
        vector::append(&mut transcript, b"commitment");
        vector::append(&mut transcript, commitment);
        vector::append(&mut transcript, b"A");
        vector::append(&mut transcript, a);

        new_scalar_from_sha2_512(transcript)
    }


    public fun verify_nizk_pedersen_zero(instance: &ZkInstancePedersenZero, nizk: &ZkProofPedersenZero): bool {

        if (!check_instance(instance)){
            false;
        };

        let aa = point_mul(&instance.h, &nizk.z);
        let c_cmt = point_mul(&instance.commit, &nizk.c);
        point_sub_assign(&mut aa, &c_cmt);

        let challenge_prime = zk_pedersen_zero_proof_challenge(instance, &aa,);

        if (!scalar_equals(&nizk.c, &challenge_prime)) {
            false;
        };

        true
    }

}
