use rust_bindings::{
    lattice_ibe_ffi::MasterPublicKey,
    decrypt, encrypt, IbeCiphertext, IbeMasterKeypair, IbeSecretKeyID
};

/// maps a 32-byte block <--> N0-length bit vector
pub mod bitcodec {
    use rust_bindings::N0;

    /*----------------------------------------------------------*
     |  1. bytes -> message coefficients (encrypt direction)     |
     *----------------------------------------------------------*/
    pub fn scalar_bytes_to_encryption_input(bytes: &[u8; 96]) -> [i64; N0] {
        assert!(N0 >= 1024, "N0 must be ≥ 1024 to embed 1024 bits");

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
    pub fn decryption_output_to_scalar_bytes(msg: &[i64; N0]) -> [u8; 96] {
        assert!(N0 >= 1024, "N0 must be ≥ 1024");
        let mut bytes = [0_u8; 96];

        for bit_idx in 0..768 {
            let coef = msg[bit_idx] & 1;                  // be tolerant
            let byte   = bit_idx / 8;
            let offset = bit_idx % 8;
            bytes[byte] |= (coef as u8) << offset;
        }
        bytes
    }

    pub fn convert_id_to_ibe_format(id: &[u8; 96]) -> [i64; N0] {
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
        use crate::ibe::bitcodec;

        #[test]
        fn bitcodec_roundtrip() {
            assert!(N0 >= 1024, "N0 must be at least 1024 for the codec");

            // ❶ deterministic pseudo-random pattern
            let mut bytes = [0u8; 96];
            for i in 0..96 {
                bytes[i] = (i as u8).wrapping_mul(37).wrapping_add(11);
            }

            let msg_vec  = bitcodec::scalar_bytes_to_encryption_input(&bytes);
            let bytes_rt = bitcodec::decryption_output_to_scalar_bytes(&msg_vec);

            assert_eq!(bytes, bytes_rt, "round-trip failed");

            // ❷ all-zero pattern
            let zeros = [0u8; 96];
            assert_eq!(
                zeros,
                bitcodec::decryption_output_to_scalar_bytes(&bitcodec::scalar_bytes_to_encryption_input(&zeros))
            );

            // ❸ all-ones pattern
            let ones = [0xFFu8; 96];
            assert_eq!(
                ones,
                bitcodec::decryption_output_to_scalar_bytes(&bitcodec::scalar_bytes_to_encryption_input(&ones))
            );
        }
    }
}

pub fn ibe_keygen() -> IbeMasterKeypair {
    IbeMasterKeypair::generate()
}

pub fn ibe_extract_id_secret_key(id: &[u8; 96], mkp: &IbeMasterKeypair) -> IbeSecretKeyID {
    let id_ibe = bitcodec::convert_id_to_ibe_format(id);
    mkp.extract_sk_id(&id_ibe)
}

pub fn ibe_encrypt(msg: &[u8; 96], master_public_key: &MasterPublicKey, id: &[u8; 96]) -> IbeCiphertext {
    let id_ibe = bitcodec::convert_id_to_ibe_format(id);
    let input_data_ser = bitcodec::scalar_bytes_to_encryption_input(msg);
    encrypt(&input_data_ser, master_public_key, &id_ibe)
}

pub fn ibe_decrypt(cipher: &IbeCiphertext, sk_id: &IbeSecretKeyID) -> [u8; 96] {
    bitcodec::decryption_output_to_scalar_bytes(&decrypt(cipher, sk_id))
}

#[cfg(test)]
mod test {
    use rust_bindings::IbeMasterKeypair;
    use super::*;
    use rand::Rng;

    #[test]
    fn test_encrypt_decrypt_100() {
        let master_keypair = IbeMasterKeypair::generate();
        let mut rng = rand::thread_rng();

        for i in 0..100 {
            let id = [i as u8; 96];
            let sk_id = ibe_extract_id_secret_key(&id, &master_keypair);
            let mut msg: [u8; 96] = [0; 96];
            rng.fill(&mut msg[..64]);
            let result = ibe_encrypt(&msg, master_keypair.master_pk(), &id);
            let decrypted = ibe_decrypt(&result, &sk_id);
            assert_eq!(msg, decrypted);
        }
    }

}