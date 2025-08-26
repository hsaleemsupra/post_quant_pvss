module Sender::vote {
    use std::vector;
    use aptos_std::ristretto255::{RistrettoPoint, Scalar, point_identity, point_add, basepoint, point_sub, scalar_one
    };
    use aptos_std::ristretto255_pedersen::{randomness_base_for_bulletproof, new_commitment, commitment_from_point,
        commitment_equals
    };
    use Sender::nizk_commit_zero::{ZkProofPedersenZero, create_nizk_pedersen_zero_instance, verify_nizk_pedersen_zero};
    use Sender::nizk_commit_or::{ZkProofPedersenOr, create_nizk_pedersen_or_instance, verify_nizk_pedersen_or_relation,
    };

    /// error codes
    const E_VOTE_VERIFICATION_FAILED: u64 = 20;

    struct Vote has drop{
        commitment_vote_answer: vector<RistrettoPoint>,
        commit_pad: RistrettoPoint,
        commitment_r_sum: Scalar,
        nizk_commit_pad_zero: ZkProofPedersenZero,
        nizk_commit_zero_or_one: vector<ZkProofPedersenOr>,
    }

    public fun create_vote(commitment_vote_answer: vector<RistrettoPoint>,
                           commit_pad: RistrettoPoint,
                           commitment_r_sum: Scalar,
                           nizk_commit_pad_zero: ZkProofPedersenZero,
                           nizk_commit_zero_or_one: vector<ZkProofPedersenOr>): Vote{

        Vote{
            commitment_vote_answer,
            commit_pad,
            commitment_r_sum,
            nizk_commit_pad_zero,
            nizk_commit_zero_or_one
        }
    }

    public fun verify_vote(vote: &mut Vote): bool{

        // 1. verify that sum(comm_i) commit to 1
        let g = basepoint();
        let h = randomness_base_for_bulletproof();

        let sum_commitment = point_identity();
        for (i in 0..vector::length(&vote.commitment_vote_answer)){
            sum_commitment = point_add(&sum_commitment, vector::borrow(&vote.commitment_vote_answer, i));
        };

        sum_commitment = point_add(&sum_commitment, &vote.commit_pad);
        let sum_comm = commitment_from_point(sum_commitment);
        let comm = new_commitment(&scalar_one(), &g, &vote.commitment_r_sum, &h);
        commitment_equals(&sum_comm, &comm);

        // 2. verify that commit_pad encrypts zero
        let instance = create_nizk_pedersen_zero_instance(&g, &h, &vote.commit_pad);
        verify_nizk_pedersen_zero(&instance, &vote.nizk_commit_pad_zero);

        // 3. verify that for each commitment, m is either 0 or 1
        for(i in 0..vector::length(&vote.commitment_vote_answer)){
            let comm = vector::borrow(&vote.commitment_vote_answer, i);
            let instance = create_nizk_pedersen_or_instance(&g, &h, comm, &point_sub(comm, &g));
            verify_nizk_pedersen_or_relation(&instance, &vote.nizk_commit_zero_or_one[i])
        };

        true
    }
}
