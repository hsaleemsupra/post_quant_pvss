module Sender::nizk_or_proof {
    use std::option::{Option, some, none};
    use std::vector;
    use aptos_std::ristretto255::{Scalar, RistrettoPoint, point_clone, point_identity, point_equals, point_to_bytes,
        point_compress, new_scalar_from_sha2_512, multi_scalar_mul, scalar_equals, scalar_neg,
        scalar_to_bytes, point_mul, point_add, scalar_zero, scalar_add_assign, new_scalar_from_bytes
    };

    struct ZkInstanceOrRelation has drop {
        g: RistrettoPoint,
        h: RistrettoPoint,
        comm: RistrettoPoint,
        ms: vector<Scalar>,
    }

    struct ZkProofOrRelation has drop{
        challenges: vector<Scalar>,
        zs: vector<Scalar>,
    }

    struct ZkProofOrRelationBytes has copy, drop, store{
        challenges: vector<vector<u8>>,
        zs: vector<vector<u8>>,
    }
    
    public fun get_nizk_or_relation_bytes(challenges: vector<vector<u8>>, zs: vector<vector<u8>>): ZkProofOrRelationBytes{
        ZkProofOrRelationBytes{
            challenges,
            zs
        }
    }

    public fun nizk_or_relation_from_bytes(bytes: &ZkProofOrRelationBytes): Option<ZkProofOrRelation>{

        let is_canonical = true;
        
        let zk_proof_or = ZkProofOrRelation{
            challenges: vector::map<vector<u8>, Scalar>( bytes.challenges, |c| {

                let chall_option = new_scalar_from_bytes(c);
                if(std::option::is_none(&chall_option)){
                    is_canonical = false;
                    scalar_zero()
                }
                else{
                    std::option::extract(&mut chall_option)
                }
            } ),
            zs: vector::map<vector<u8>, Scalar>( bytes.zs, |z|
                {
                    let z_option = new_scalar_from_bytes(z);
                    if(std::option::is_none(&z_option)){
                        is_canonical = false;
                        scalar_zero()
                    }
                    else{
                        std::option::extract(&mut z_option)
                    }
                })
        };
        
        if(is_canonical){
            some(zk_proof_or)
        }
        else {
            none<ZkProofOrRelation>()
        }
    }

    public fun get_zkproof_or_relation(challenges: vector<Scalar>, zs: vector<Scalar>): ZkProofOrRelation{
        let proof = ZkProofOrRelation{
            challenges,
            zs,
        };
        proof
    }

    public fun get_domain_separator_nizk_or_relation(): vector<u8>{
        let domain_str:vector<u8> = b"crypto-zk-proof-of-or-relation-challenge";
        domain_str
    }

    public fun create_nizk_or_relation_instance(g: &RistrettoPoint, h: &RistrettoPoint,
                                               comm: &RistrettoPoint, ms: vector<Scalar>): ZkInstanceOrRelation{

        ZkInstanceOrRelation {
            g: point_clone(g),
            h: point_clone(h),
            comm: point_clone(comm),
            ms,
        }
    }

    fun check_instance(instance: &ZkInstanceOrRelation): bool{
        let identity = point_identity();
        if ( point_equals(&instance.g, &identity) ||
            point_equals(&instance.h, &identity) ||
            point_equals(& instance.comm, &identity))
            {
                false;
            };

        true
    }

    fun zk_or_relation_proof_challenge(instance: &ZkInstanceOrRelation,
                                       dds: &vector<RistrettoPoint>): Scalar{

        let transcript:vector<u8> = vector::empty<u8>();
        let g = point_to_bytes(&point_compress(&instance.g));
        let h = point_to_bytes(&point_compress(&instance.h));
        let a= point_to_bytes(&point_compress(&instance.comm));

        vector::append(&mut transcript, get_domain_separator_nizk_or_relation());
        vector::append(&mut transcript, b"g");
        vector::append(&mut transcript, g);
        vector::append(&mut transcript, b"h");
        vector::append(&mut transcript, h);
        vector::append(&mut transcript, b"Commitment");
        vector::append(&mut transcript, a);

        vector::append(&mut transcript, b"M");
        for(i in 0..vector::length(&instance.ms)){
            let m_bytes = scalar_to_bytes(vector::borrow(&instance.ms, i));
            vector::append(&mut transcript, m_bytes);
        };

        vector::append(&mut transcript, b"D");
        for(i in 0..vector::length(dds)){
            let dd_bytes = point_to_bytes(&point_compress(vector::borrow(dds,i)));
            vector::append(&mut transcript, dd_bytes);
        };

        new_scalar_from_sha2_512(transcript)
    }

    public fun verify_nizk_or_relation(instance: &ZkInstanceOrRelation, nizk: &ZkProofOrRelation): bool {

        if (!check_instance(instance)){
            false;
        };

        let aa = vector[];
        for(i in 0..vector::length(&instance.ms)){
            let a = point_add(&instance.comm, &point_mul(&instance.g, &scalar_neg(vector::borrow(&instance.ms,i))));
            vector::push_back(&mut aa, a);
        };

        let dds = vector[];
        let challenge = scalar_zero();
        for(i in 0..vector::length(&aa)){
            let dd = multi_scalar_mul(&vector[point_clone(&instance.h), point_clone(vector::borrow(&aa,i))], &vector[*vector::borrow(&nizk.zs,i), scalar_neg(vector::borrow(&nizk.challenges,i))]);
            vector::push_back(&mut dds, dd);
            scalar_add_assign(&mut challenge, vector::borrow(&nizk.challenges,i));
        };

        //challenge = H(g,h,C,Ms,Ds)
        let challenge_prime = zk_or_relation_proof_challenge(instance, &dds);

        if (!scalar_equals(&challenge, &challenge_prime)) {
            false;
        };

        true
    }

}
