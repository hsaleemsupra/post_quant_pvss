use autocxx::prelude::*;
use cxx::{UniquePtr};
use autocxx::{c_long};

// -------------------- 1.  Bindings  ----------------------------------
include_cpp! {
    #include "lattice_ibe_ffi.h"
    safety!(unsafe)

    // expose constants & opaque types
    generate!("lattice_ibe_ffi::N0")
    generate!("lattice_ibe_ffi::MasterPublicKey")
    generate!("lattice_ibe_ffi::MasterSecretKey")
    generate!("lattice_ibe_ffi::Ciphertext")
    generate!("lattice_ibe_ffi::MasterKeypair")
    generate!("lattice_ibe_ffi::SecretKeyID")

    // functions
    generate!("lattice_ibe_ffi::keygen")
    generate!("lattice_ibe_ffi::keypair_pk")   
    generate!("lattice_ibe_ffi::keypair_sk")   
    generate!("lattice_ibe_ffi::ibe_encrypt")
    generate!("lattice_ibe_ffi::ibe_decrypt")
    generate!("lattice_ibe_ffi::ibe_extract")
}

pub use ffi::lattice_ibe_ffi;
pub const N0: usize = lattice_ibe_ffi::N0 as usize;

// -------------------- 2.  Safe wrappers  -----------------------------
pub struct IbeMasterKeypair {
    inner: UniquePtr<lattice_ibe_ffi::MasterKeypair>,
}

pub struct IbeCiphertext {
    pub inner: UniquePtr<lattice_ibe_ffi::Ciphertext>,
}

pub struct IbeSecretKeyID {
    pub inner: UniquePtr<lattice_ibe_ffi::SecretKeyID>,
}

impl IbeMasterKeypair {
    pub fn generate() -> Self {
        Self {
            inner: lattice_ibe_ffi::keygen(),
        }
    }
    // getters for &MasterPublicKey / &MasterSecretKey
    pub fn master_pk(&self) -> &lattice_ibe_ffi::MasterPublicKey {
        let kp_ref = self.inner.as_ref().expect("null keypair from C++");
        unsafe { &*lattice_ibe_ffi::keypair_pk(kp_ref) }
    }
    pub fn master_sk(&self) -> &lattice_ibe_ffi::MasterSecretKey {
        let kp_ref = self.inner.as_ref().expect("null keypair from C++");
        unsafe { &*lattice_ibe_ffi::keypair_sk(kp_ref) }
    }
    
    pub fn extract_sk_id(&self, id:  &[i64; N0])
        -> IbeSecretKeyID {
        unsafe {
            IbeSecretKeyID {
                inner: lattice_ibe_ffi::ibe_extract(
                    id.as_ptr()  as *const c_long,
                    self.master_sk()
                )
            }
        }
    }
}

pub fn encrypt(
    msg: &[i64; N0],
    master_pk: &lattice_ibe_ffi::MasterPublicKey,
    id:  &[i64; N0],
) -> IbeCiphertext {
    unsafe {
        IbeCiphertext {
            inner: lattice_ibe_ffi::ibe_encrypt(
                master_pk,
                msg.as_ptr() as *const c_long,
                id.as_ptr()  as *const c_long,
            )
        }
    }
}

pub fn decrypt(ct: &IbeCiphertext, sk_id: &IbeSecretKeyID,) -> [i64; N0] {
    let mut out = [0i64; N0];
    unsafe {
        lattice_ibe_ffi::ibe_decrypt(
            &ct.inner,
            &sk_id.inner,
            out.as_mut_ptr() as *mut c_long,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let kp = IbeMasterKeypair::generate();

        let mut msg = [0i64; N0];
        msg[0] = 1;
        msg[5] = 1;

        let mut id  = [0i64; N0];
        for i in 0..N0 { id[i] = (i % 3 == 0) as i64; }

        let ct  = encrypt(&msg, kp.master_pk(), &id);
        
        let sk_id = kp.extract_sk_id(&id);
        let dec = decrypt(&ct, &sk_id);

        assert_eq!(msg[..], dec[..]);
    }
}