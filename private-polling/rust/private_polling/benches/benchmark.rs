use std::vec;
use bulletproofs::PedersenGens;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, black_box};
use curve25519_dalek::{RistrettoPoint, Scalar};
use group::Group;
use rand::{thread_rng};
use rand_core::OsRng;
use rust_bindings::{IbeMasterKeypair};
use private_polling::crypto::ibe_encryption::{ibe_decrypt, ibe_encrypt, ibe_extract_id_secret_key};
use private_polling::crypto::interpolate::interpolate_scalar;
use private_polling::crypto::nizk_commit_or::{prove_nizk_pedersen_or_relation_one, prove_nizk_pedersen_or_relation_zero, verify_nizk_pedersen_or_relation, ZkInstancePedersenOr, ZkWitnessPedersenOr};
use private_polling::crypto::nizk_commit_zero::{prove_nizk_pedersen_zero, verify_nizk_pedersen_zero, ZkInstancePedersenZero, ZkWitnessPedersenZero};
use private_polling::crypto::public_evals::PublicEvals;
use private_polling::crypto::share_commitment::compute_commited_shares;
use private_polling::crypto::vote::Vote;
use private_polling::serde_types::compute_ibe_identity;

fn create_vote(poll_answer_bit_vector: &Vec<u16>, num_nodes: u32, threshold: u32,
               server_key_pairs: &Vec<IbeMasterKeypair>, server_identities: &Vec<Vec<u8>>) -> Vote {
    let pedersen_gens = PedersenGens::default();
    let choice_selected_index = poll_answer_bit_vector.iter().position(|x| *x == 1).unwrap();
    let comm_shares = poll_answer_bit_vector
        .iter()
        .map(|x| compute_commited_shares(&Scalar::from(*x), num_nodes, threshold))
        .collect::<Vec<_>>();

    // Commitments Zero or One Proof
    let mut nizk_commit_zero_or_one = Vec::new();
    for i in 0..poll_answer_bit_vector.len() {
        let (r, _x_shares, _r_shares, comm_shares) = comm_shares[i].clone();

        let instance = ZkInstancePedersenOr {
            g: pedersen_gens.B,
            h: pedersen_gens.B_blinding,
            c: comm_shares[0],
            d: comm_shares[0] - pedersen_gens.B,
        };
        let witness = ZkWitnessPedersenOr {
            r,
        };

        if i != choice_selected_index {
            let nizk_proof = prove_nizk_pedersen_or_relation_zero(&instance, &witness).unwrap();
            nizk_commit_zero_or_one.push(nizk_proof);
        }
        else {
            let nizk_proof = prove_nizk_pedersen_or_relation_one(&instance, &witness).unwrap();
            nizk_commit_zero_or_one.push(nizk_proof);
        }
    }

    // encrypt shares for all servers
    let mut server_enc_shares = Vec::new();
    for i in 0..poll_answer_bit_vector.len(){
        let (_r, x_shares, r_shares, _comm_shares) = comm_shares[i].clone();

        for j in 0..num_nodes{

            let x_share_server_j = x_shares[j as usize];
            let r_share_server_j = r_shares[j as usize];
            let x_share_enc = ibe_encrypt(&x_share_server_j,
                                          server_key_pairs[j as usize].master_pk(),
                                          &server_identities[j as usize]);
            let r_share_enc = ibe_encrypt(&r_share_server_j,
                                          server_key_pairs[j as usize].master_pk(),
                                          &server_identities[j as usize]);
            server_enc_shares.push((x_share_enc, r_share_enc));
        }
    }

    // Compute commit_pad and r_sum
    let r_pad = Scalar::random(&mut thread_rng());
    let commit_zero = pedersen_gens.commit(Scalar::ZERO, r_pad);
    let mut commitment_r_sum = r_pad;

    for i in 0..poll_answer_bit_vector.len() {
        let (r, _x_shares, _r_shares, _comm_shares) = comm_shares[i].clone();
        commitment_r_sum += r;
    }

    // proof that for commit_pad encrypts zero
    let instance = ZkInstancePedersenZero {
        g: pedersen_gens.B,
        h: pedersen_gens.B_blinding,
        commitment: commit_zero,
    };
    let witness = ZkWitnessPedersenZero {
        commitment_r: r_pad,
    };
    let nizk_proof_commit_pad_zero = prove_nizk_pedersen_zero(&instance, &witness).unwrap();

    Vote{
        commited_shares: comm_shares.iter().map(|(_,_,_,c)| c.clone()).collect(),
        nizk_commit_zero_or_one: nizk_commit_zero_or_one,
        encrypted_shares: server_enc_shares,
        commit_pad: commit_zero,
        commitment_r_sum,
        nizk_commit_pad_zero: nizk_proof_commit_pad_zero,
    }
}

fn compute_vote_size(num_nodes: u32, total_choices: u32){

    let vote_size_bytes = (total_choices*num_nodes)*(32) // commited_shares
        + total_choices*(4*32) // nizk_commit_zero_or_one
        + (total_choices*num_nodes)*(2*2048) // encrypted_shares
        + 32 // commit_pad
        + 32 // commitment_r_sum
        + (2*32); // nizk_commit_pad_zero

    println!("Vote size: {} KB, servers: {}, poll_choices: {}", (vote_size_bytes as f64)/(1024.0), num_nodes, total_choices);
}

fn verify_vote_sc(vote: &Vote){
    let pedersen_gens = PedersenGens::default();
    // 1. verify that sum(comm_i) commit to 1
    let mut sum_commitment = RistrettoPoint::identity();
    vote.commited_shares.iter().for_each(|comm_shares|sum_commitment+=comm_shares[0]);
    sum_commitment+= vote.commit_pad;
    let commitment_sum = pedersen_gens.commit(Scalar::ONE, vote.commitment_r_sum);
    assert_eq!(commitment_sum, sum_commitment);

    // 2. verify that commit_pad encrypts zero
    let instance = ZkInstancePedersenZero {
        g: pedersen_gens.B,
        h: pedersen_gens.B_blinding,
        commitment: vote.commit_pad,
    };
    assert_eq!(verify_nizk_pedersen_zero(&instance, &vote.nizk_commit_pad_zero), Ok(()));

    // 3. verify that for each commitment, m is either 0 or 1
    for i in 0..vote.commited_shares.len(){
        let comm_shares = vote.commited_shares[i].clone();

        let instance = ZkInstancePedersenOr {
            g: pedersen_gens.B,
            h: pedersen_gens.B_blinding,
            c: comm_shares[0],
            d: comm_shares[0] - pedersen_gens.B,
        };
        assert!(verify_nizk_pedersen_or_relation(&instance, &vote.nizk_commit_zero_or_one[i]).is_ok());
    }
}

fn verify_vote_server(vote: &Vote, num_nodes: u32, threshold: u32, server_key_pairs: &Vec<IbeMasterKeypair>, server_identities: &Vec<Vec<u8>>){
    let pedersen_gens = PedersenGens::default();
    let total_choices = vote.commited_shares.len();
    // Server share verification
    // scrape test
    for i in 0..total_choices{
        let comm_shares = vote.commited_shares[i].clone();
        let commitment_shares = PublicEvals{
            g: pedersen_gens.B,
            evals: comm_shares,
        };
        assert!(commitment_shares.perform_low_degree_test(num_nodes, threshold));
    }

    // decrypt shares + verification
    let sk_id = ibe_extract_id_secret_key(&server_identities[0], &server_key_pairs[0]);
    let mut serverj_xr_shares = Vec::new();
    for i in 0..total_choices{
        let comm_shares = vote.commited_shares[i].clone();

        let server_j_index  = 0;
        let x_j_share_enc = &vote.encrypted_shares[i*total_choices + server_j_index].0;
        let r_j_share_enc = &vote.encrypted_shares[i*total_choices + server_j_index].1;
        let x_j_share = ibe_decrypt(&x_j_share_enc, &sk_id);
        let r_j_share = ibe_decrypt(&r_j_share_enc, &sk_id);
        serverj_xr_shares.push((x_j_share, r_j_share));

        let com = pedersen_gens.commit(x_j_share, r_j_share);
        // assert equality
        let _ = com == comm_shares[1];
    }
}

// creating random test shares for benchmarking purposes
fn create_test_shares_for_benchmarking(total_choices: usize, num_clients: u32) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Vec<Vec<RistrettoPoint>>) {
    let mut serverj_x_all_option = Vec::new();
    let mut serverj_r_all_option = Vec::new();
    let mut comm_output = Vec::new();
    for _i in 0..total_choices{
        serverj_x_all_option.push(vec![Scalar::random(&mut thread_rng()); num_clients as usize]);
        serverj_r_all_option.push(vec![Scalar::random(&mut thread_rng()); num_clients as usize]);
        comm_output.push(vec![RistrettoPoint::random(&mut thread_rng()); num_clients as usize]);
    }

    (serverj_x_all_option, serverj_r_all_option, comm_output)
}

fn aggregate_shares_reconstruct_output(threshold: u32,
                                       serverj_x_all_option: &Vec<Vec<Scalar>>,
                                       serverj_r_all_option: &Vec<Vec<Scalar>>,
                                       comm_output: &Vec<Vec<RistrettoPoint>>, ){
    let pedersen_gens = PedersenGens::default();

    for ((server_x_shares, server_r_shares), comm_out) in serverj_x_all_option.iter().zip(serverj_r_all_option.iter()).zip(comm_output.iter()) {

        // sum own shares for validated clients
        let _x_out: Scalar = server_x_shares.iter().sum();
        let _r_out: Scalar = server_r_shares.iter().sum();
        let comm_out: RistrettoPoint = comm_out.iter().sum();

        // each server would post their output share on chain

        // output computation
        // lets assume, the server gathers the following threshold shares from other servers
        // random shares for benchmarking purposes
        let server_output_shares = vec![Scalar::random(&mut thread_rng()); threshold as usize];
        let server_r_shares = vec![Scalar::random(&mut thread_rng()); threshold as usize];

        let lagrange_shares_output: Vec<(_,_)> = server_output_shares.iter()
            .enumerate()
            .map(|(i,x)|{
                (Scalar::from(i as u64), x.clone())
            }).collect();
        let result_output = interpolate_scalar(lagrange_shares_output.as_slice()).unwrap();

        let lagrange_r_output: Vec<(_,_)> = server_r_shares.iter()
            .enumerate()
            .map(|(i,x)|{
                (Scalar::from(i as u64), x.clone())
            }).collect();
        let result_r = interpolate_scalar(lagrange_r_output.as_slice()).unwrap();
        let commit = pedersen_gens.commit(result_output, result_r);
        // assert equality
        let _ = comm_out == commit;
    }
}

fn benchmark_private_polling(c: &mut Criterion) {

    // Create a benchmark group
    let mut group = c.benchmark_group("Private Polling (post quant)");
    // Set the sample size for benchmarking group
    group.sample_size(10);

    // we vary the total choices to see how that affects the total cost
    let total_choices_vec = [4,8,16];
    let poll_id = 10;
    let num_clients = 100_000;
    let num_nodes_vec = [16, 32, 64, 128];
    for num_nodes in num_nodes_vec {

        let threshold = num_nodes / 2;
        let mut server_key_pairs = Vec::new();
        for _i in 0..num_nodes {
            let master_keypair = IbeMasterKeypair::generate();
            server_key_pairs.push(master_keypair);
        }

        for total_choices in total_choices_vec{

            let client_sk = Scalar::random(&mut OsRng);
            let client_pk = RistrettoPoint::generator() * client_sk;

            let server_identities: Vec<_> = (0..num_nodes)
                .map(|server_id|{compute_ibe_identity(&client_pk, poll_id, server_id as u64)})
                .collect();

            let choice_selected_index = 1; // the client selects a choice out of the available choices
            let mut poll_answer_bit_vector: Vec<u16> = vec![0; total_choices];
            poll_answer_bit_vector[choice_selected_index] = 1;

            group.bench_with_input(BenchmarkId::new("(Client) Encrypted Vote + Proofs", format!("total_choices: {}, num_servers: {}", total_choices, num_nodes)), &total_choices, |b, _cfg| {
                b.iter(|| {

                    let vote = create_vote(&poll_answer_bit_vector, num_nodes, threshold,
                                           &server_key_pairs, &server_identities);
                    black_box(vote);
                });
            });

            let vote = create_vote(&poll_answer_bit_vector, num_nodes, threshold,
                                   &server_key_pairs, &server_identities);

            compute_vote_size(num_nodes, total_choices as u32);

            // smart contract verifies the commitment proofs
            group.bench_with_input(BenchmarkId::new("(Smart Contract) vote verification", format!("total_choices: {}, num_servers: {}", total_choices, num_nodes)), &total_choices, |b, _cfg| {
                b.iter(|| {
                    verify_vote_sc(&vote);
                });
            });

            group.bench_with_input(BenchmarkId::new("(Server) vote verification", format!("total_choices: {}, num_nodes: {}", total_choices, num_nodes)), &total_choices, |b, _cfg| {
                b.iter(|| {
                    verify_vote_server(&vote, num_nodes, threshold, &server_key_pairs, &server_identities);
                });
            });

            let (serverj_x_all_option, serverj_r_all_option, comm_output)
                = create_test_shares_for_benchmarking(total_choices, num_clients);

            group.bench_with_input(BenchmarkId::new("(Server) share agg + output recon", format!("total_choices: {}, num_nodes: {}", total_choices, num_nodes)), &total_choices, |b, _cfg| {
                b.iter(|| {
                    aggregate_shares_reconstruct_output(threshold,
                                                        &serverj_x_all_option,
                                                        &serverj_r_all_option,
                                                        &comm_output);
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, benchmark_private_polling);
criterion_main!(benches);