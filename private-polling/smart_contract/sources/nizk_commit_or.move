module Sender::nizk_commit_or {
    use std::option::Option;
    use std::vector;
    use aptos_std::ristretto255::{Scalar, RistrettoPoint, point_clone, point_identity, point_equals, point_to_bytes,
        point_compress, new_scalar_from_sha2_512, multi_scalar_mul, scalar_add, scalar_equals, scalar_neg,
        new_scalar_from_bytes, scalar_zero
    };

    struct ZkInstancePedersenOr has drop {
        g: RistrettoPoint,
        h: RistrettoPoint,
        c: RistrettoPoint,
        d: RistrettoPoint,
    }
    
    struct ZkProofPedersenOr has drop{
        challenge_1: Scalar,
        challenge_2: Scalar,
        z1: Scalar,
        z2: Scalar,
    }

    struct ZkProofPedersenOrBytes has copy, drop, store{
        challenge_1: vector<u8>,
        challenge_2: vector<u8>,
        z1: vector<u8>,
        z2: vector<u8>,
    }
    
    public fun get_dummy_zkproof_pedersen_or(): ZkProofPedersenOr {
        ZkProofPedersenOr {
            challenge_1: scalar_zero(),
            challenge_2: scalar_zero(),
            z1: scalar_zero(),
            z2: scalar_zero(),
        }
    }
    
    public fun get_nizk_pedersen_or_bytes(challenge_1: vector<u8>,
                                          challenge_2: vector<u8>,
                                          z1: vector<u8>,
                                          z2: vector<u8>): ZkProofPedersenOrBytes {
        ZkProofPedersenOrBytes {
            challenge_1,
            challenge_2,
            z1,
            z2
        }
    }

    public fun nizk_pedersen_or_from_bytes(bytes: &ZkProofPedersenOrBytes): Option<ZkProofPedersenOr>{
        let challenge_1_option = new_scalar_from_bytes(bytes.challenge_1);
        let challenge_2_option = new_scalar_from_bytes(bytes.challenge_2);
        let z1_option = new_scalar_from_bytes(bytes.z1);
        let z2_option = new_scalar_from_bytes(bytes.z2);
        
        if(std::option::is_none(&challenge_1_option) || std::option::is_none(&challenge_2_option) ||
            std::option::is_none(&z1_option) || std::option::is_none(&z2_option)){
            std::option::none<ZkProofPedersenOr>()
        }
        else {
            std::option::some(
                ZkProofPedersenOr {
                    challenge_1: std::option::extract(&mut challenge_1_option),
                    challenge_2: std::option::extract(&mut challenge_2_option),
                    z1: std::option::extract(&mut z1_option),
                    z2: std::option::extract(&mut z2_option),
                }
            )
        }
    }

    public fun get_zkproof_pedersen_or(challenge_1: Scalar, challenge_2: Scalar,
                                       z1: Scalar, z2: Scalar): ZkProofPedersenOr {
        let proof = ZkProofPedersenOr {
            challenge_1,
            challenge_2,
            z1,
            z2
        };
        proof
    }

    public fun get_domain_separator_nizk_pedersen_or(): vector<u8>{
        let domain_str:vector<u8> = b"crypto-zk-proof-of-or-pedersen-challenge";
        domain_str
    }

    public fun create_nizk_pedersen_or_instance(g: &RistrettoPoint, h: &RistrettoPoint,
                                                c: &RistrettoPoint, d: &RistrettoPoint): ZkInstancePedersenOr {

        ZkInstancePedersenOr {
            g: point_clone(g),
            h: point_clone(h),
            c: point_clone(c),
            d: point_clone(d),
        }
    }

    fun check_instance(instance: &ZkInstancePedersenOr): bool{
        let identity = point_identity();
        if (point_equals(&instance.h, &identity) ||
            point_equals(& instance.c, &identity) ||
            point_equals(& instance.d, &identity))
            {
                false;
            };

        true
    }

    fun zk_pedersen_or_proof_challenge(instance: &ZkInstancePedersenOr
                                       , aa1: &RistrettoPoint
                                       , aa2: &RistrettoPoint): Scalar{

        let transcript:vector<u8> = vector::empty<u8>();
        let g = point_to_bytes(&point_compress(&instance.g));
        let h = point_to_bytes(&point_compress(&instance.h));
        let c= point_to_bytes(&point_compress(&instance.c));
        let d= point_to_bytes(&point_compress(&instance.d));
        let a1 = point_to_bytes(&point_compress(aa1));
        let a2 = point_to_bytes(&point_compress(aa2));

        vector::append(&mut transcript, get_domain_separator_nizk_pedersen_or());
        vector::append(&mut transcript, b"g");
        vector::append(&mut transcript, g);
        vector::append(&mut transcript, b"h");
        vector::append(&mut transcript, h);
        vector::append(&mut transcript, b"c");
        vector::append(&mut transcript, c);
        vector::append(&mut transcript, b"d");
        vector::append(&mut transcript, d);
        vector::append(&mut transcript, b"A1");
        vector::append(&mut transcript, a1);
        vector::append(&mut transcript, b"A2");
        vector::append(&mut transcript, a2);
        new_scalar_from_sha2_512(transcript)
    }

    public fun verify_nizk_pedersen_or_relation(instance: &ZkInstancePedersenOr, nizk: &ZkProofPedersenOr): bool {

        if (!check_instance(instance)){
            false;
        };

        let aa1 = multi_scalar_mul(&vector[point_clone(&instance.h), point_clone(&instance.c)], &vector[nizk.z1, scalar_neg(&nizk.challenge_1)]);
        let aa2 = multi_scalar_mul(&vector[point_clone(&instance.h), point_clone(&instance.d)], &vector[nizk.z2, scalar_neg(&nizk.challenge_2)]);

        let challenge = scalar_add(&nizk.challenge_1, &nizk.challenge_2);
        let challenge_prime = zk_pedersen_or_proof_challenge(instance, &aa1, &aa2);

        if (!scalar_equals(&challenge, &challenge_prime)) {
            false;
        };

        true
    }
}
