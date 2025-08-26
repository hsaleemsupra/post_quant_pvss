use curve25519_dalek::{Scalar};
use rust_bindings::lattice_ibe_ffi::{MasterPublicKey};
use rust_bindings::{decrypt, encrypt, IbeCiphertext, IbeMasterKeypair, IbeSecretKeyID};

/// maps a 32-byte block <--> N0-length bit vector
pub mod bitcodec {
    use rust_bindings::N0;

    /*----------------------------------------------------------*
     |  1. bytes -> message coefficients (encrypt direction)     |
     *----------------------------------------------------------*/
    pub fn scalar_bytes_to_encryption_input(bytes: &[u8; 32]) -> [i64; N0] {
        assert!(N0 >= 256, "N0 must be ≥ 256 to embed 256 bits");

        let mut msg = [0_i64; N0];

        // little-endian bit ordering: LSB = bit-0
        for (byte_idx, &b) in bytes.iter().enumerate() {
            let base = byte_idx * 8;
            for bit in 0..8 {
                let bitval = (b >> bit) & 1;
                msg[base + bit] = bitval as i64;          // 0 / 1
            }
        }
        msg
    }

    /*----------------------------------------------------------*
     |  2. message coefficients -> bytes (decrypt direction)     |
     *----------------------------------------------------------*/
    pub fn decryption_output_to_scalar_bytes(msg: &[i64; N0]) -> [u8; 32] {
        assert!(N0 >= 256, "N0 must be ≥ 256");
        let mut bytes = [0_u8; 32];

        for bit_idx in 0..256 {
            let coef = msg[bit_idx] & 1;                  // be tolerant
            let byte   = bit_idx / 8;
            let offset = bit_idx % 8;
            bytes[byte] |= (coef as u8) << offset;
        }
        bytes
    }

    pub fn convert_id_to_ibe_format(id: &Vec<u8>) -> [i64; N0] {
        assert!(N0 >= id.len(), "N0 must be ≥ id len");
        let mut id_arr = [0i64; N0];
        for i in 0..id.len() {
            id_arr[i] = id[i] as i64;
        }
        id_arr
    }

    #[cfg(test)]
    mod tests {
        use rust_bindings::N0;
        use crate::crypto::ibe_encryption::bitcodec;

        #[test]
        fn bitcodec_roundtrip() {
            assert!(N0 >= 256, "N0 must be at least 256 for the codec");

            // ❶ deterministic pseudo-random pattern
            let mut bytes = [0u8; 32];
            for i in 0..32 {
                bytes[i] = (i as u8).wrapping_mul(37).wrapping_add(11);
            }

            let msg_vec  = bitcodec::scalar_bytes_to_encryption_input(&bytes);
            let bytes_rt = bitcodec::decryption_output_to_scalar_bytes(&msg_vec);

            assert_eq!(bytes, bytes_rt, "round-trip failed");

            // ❷ all-zero pattern
            let zeros = [0u8; 32];
            assert_eq!(
                zeros,
                bitcodec::decryption_output_to_scalar_bytes(&bitcodec::scalar_bytes_to_encryption_input(&zeros))
            );

            // ❸ all-ones pattern
            let ones = [0xFFu8; 32];
            assert_eq!(
                ones,
                bitcodec::decryption_output_to_scalar_bytes(&bitcodec::scalar_bytes_to_encryption_input(&ones))
            );
        }
    }
}

pub fn ibe_extract_id_secret_key(id: &Vec<u8>, mkp: &IbeMasterKeypair) -> IbeSecretKeyID {
    let id_ibe = bitcodec::convert_id_to_ibe_format(id);
    mkp.extract_sk_id(&id_ibe)
}

pub fn ibe_encrypt(input: &Scalar, master_public_key: &MasterPublicKey, id: &Vec<u8>) ->IbeCiphertext{
    let id_ibe = bitcodec::convert_id_to_ibe_format(id);
    let input_data_ser = bitcodec::scalar_bytes_to_encryption_input(&input.to_bytes());
    encrypt(&input_data_ser, master_public_key, &id_ibe)
}

pub fn ibe_decrypt(cipher: &IbeCiphertext, sk_id: &IbeSecretKeyID) -> Scalar{
    let result_ser = bitcodec::decryption_output_to_scalar_bytes(&decrypt(cipher, sk_id));
    Scalar::from_bytes_mod_order(result_ser)
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use rust_bindings::IbeMasterKeypair;
    use super::*;

    #[test]
    fn test_encrypt_decrypt_100() {
        let master_keypair = IbeMasterKeypair::generate();
        
        for i in 0..100{
            let id = [i as u8; 32];
            let sk_id = ibe_extract_id_secret_key(&id.to_vec(), &master_keypair);
            let msg = Scalar::random(&mut thread_rng());
            let result = ibe_encrypt(&msg, master_keypair.master_pk(), &id.to_vec());
            let decrypted = ibe_decrypt(&result, &sk_id);
            assert_eq!(msg, decrypted);
        }
    }

}