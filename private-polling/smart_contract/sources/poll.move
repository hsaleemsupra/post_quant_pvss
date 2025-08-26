module Sender::poll {

    #[test_only]
    use std::option;
    #[test_only]
    use std::vector;
    #[test_only]
    use aptos_std::ristretto255;
    #[test_only]
    use aptos_std::ristretto255::{scalar_zero, scalar_add, scalar_to_bytes};
    #[test_only]
    use aptos_std::ristretto255_pedersen::{new_commitment_for_bulletproof,
        commitment_into_point
    };
    #[test_only]
    use Sender::nizk_commit_or::{get_nizk_pedersen_or_bytes, nizk_pedersen_or_from_bytes};
    #[test_only]
    use Sender::nizk_commit_zero::{get_nizk_pedersen_zero_bytes, nizk_pedersen_zero_from_bytes};
    #[test_only]
    use Sender::vote::{create_vote, Vote, verify_vote};

    #[test_only]
    fun test_setup(poll_choices: u32): Vote{

        let poll_answer_bit_vec = vector[];
        for(i in 0..poll_choices){
            vector::push_back(&mut poll_answer_bit_vec, ristretto255::scalar_zero());
        };
        poll_answer_bit_vec[1] = ristretto255::scalar_one();

        let answer_commitment =  vector[];
        let r_s =  vector[];
        for(i in 0..poll_choices){
            let r = ristretto255::random_scalar();
            vector::push_back(&mut r_s, r);
            vector::push_back(&mut answer_commitment, commitment_into_point(new_commitment_for_bulletproof(&poll_answer_bit_vec[i as u64], &r)));
        };

        // Compute commit_pad and r_sum
        let r_pad = ristretto255::random_scalar();
        let commit_pad = new_commitment_for_bulletproof(&scalar_zero(), &r_pad);
        let commitment_r_sum = r_pad;

        for(i in 0..vector::length(&poll_answer_bit_vec)) {
            let r = vector::borrow(&r_s, i);
            commitment_r_sum = scalar_add(&commitment_r_sum, r);
        };

        // create dummy proofs for benchmarking
        let nizk_pedersen_zero_bytes = get_nizk_pedersen_zero_bytes(scalar_to_bytes(&ristretto255::random_scalar()), scalar_to_bytes(&ristretto255::random_scalar()));
        let nizk_pedersen_zero = option::extract(&mut nizk_pedersen_zero_from_bytes(&nizk_pedersen_zero_bytes));

        let nizk_commit_zero_or_one_vec = vector[];
        for(i in 0..poll_choices) {

            let nizk_commit_zero_or_one_bytes =
                get_nizk_pedersen_or_bytes(scalar_to_bytes(&ristretto255::random_scalar()),
                    scalar_to_bytes(&ristretto255::random_scalar()),
                    scalar_to_bytes(&ristretto255::random_scalar()),
                    scalar_to_bytes(&ristretto255::random_scalar()));

            let nizk_pedersen_or = option::extract(&mut nizk_pedersen_or_from_bytes(&nizk_commit_zero_or_one_bytes));
            vector::push_back(&mut nizk_commit_zero_or_one_vec, nizk_pedersen_or);
        };

        create_vote(answer_commitment,
            commitment_into_point(commit_pad),
            commitment_r_sum,
            nizk_pedersen_zero,
            nizk_commit_zero_or_one_vec)
    }

    #[test]
    fun test_verify_vote() {

        let poll_choices = 4;
        let test_vote = test_setup(poll_choices);
        verify_vote(&mut test_vote);
    }

}
