use curve25519_dalek::{RistrettoPoint, Scalar};
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::error::PrivatePollingError;

pub fn bytes_to_ristretto_point(bytes: &Vec<u8>) -> Result<RistrettoPoint, PrivatePollingError> {
    let point_comp = CompressedRistretto::from_slice(bytes);
    if let Ok(point_comp_ser) = point_comp {
        let point = point_comp_ser.decompress();
        if point.is_some() {
            return Ok(point.unwrap());
        }
    }

    Err(PrivatePollingError::DeserializationError(String::from("Could not deserialize Ristretto point")))
}

pub fn bytes_to_scalar(bytes: &Vec<u8>) -> Result<Scalar, PrivatePollingError> {

    let scalar_bytes = bytes.clone().try_into();
    if let Ok(scalar_ser) = scalar_bytes {
        let scalar = Scalar::from_bytes_mod_order(scalar_ser);
        Ok(scalar)
    }
    else {
        Err(PrivatePollingError::DeserializationError(String::from("Could not deserialize Scalar")))
    }
}

pub fn compute_ibe_identity(vk: &RistrettoPoint, poll_id: u64, server_id: u64) -> Vec<u8> {
    let mut id = Vec::new();
    id.extend(vk.compress().0.to_vec());
    id.extend(poll_id.to_le_bytes().to_vec());
    id.extend(server_id.to_le_bytes().to_vec());
    id
}