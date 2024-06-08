use core::marker::PhantomData;

// Re-export the necessary crates
pub use aead;
pub use blake3;
pub use chacha20;
pub use cipher;
pub use zeroize;

// Use
use aead::{
    consts::{U0, U12, U16, U24, U32},
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace,
};

use chacha20::{ChaCha12, ChaCha20, ChaCha8, XChaCha12, XChaCha20, XChaCha8};

use cipher::{KeyInit, KeyIvInit, KeySizeUser, StreamCipher, StreamCipherSeek};

use zeroize::{Zeroize, ZeroizeOnDrop};

use blake3::Hasher as Blake3;

const BLOCK_SIZE: u64 = 64;

const MAX_BLOCKS: usize = core::u32::MAX as usize;

pub type ChaCha8Blake3 = ChaChaBlake3<ChaCha8, U12>;

pub type ChaCha12Blake3 = ChaChaBlake3<ChaCha12, U12>;

pub type ChaCha20Blake3 = ChaChaBlake3<ChaCha20, U12>;

pub type XChaCha8Blake3 = ChaChaBlake3<XChaCha8, U24>;

pub type XChaCha12Blake3 = ChaChaBlake3<XChaCha12, U24>;

pub type XChaCha20Blake3 = ChaChaBlake3<XChaCha20, U24>;

pub struct ChaChaBlake3<C, N: ArrayLength<u8> = U12> {
    key: GenericArray<u8, U32>,
    cipher: PhantomData<C>,
    nonce_size: PhantomData<N>,
}

impl<C, N> Drop for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

impl<C, N> ZeroizeOnDrop for ChaChaBlake3<C, N> where N: ArrayLength<u8> {}

impl<C, N> KeySizeUser for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    type KeySize = U32;
}

impl<C, N> KeyInit for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    fn new(key: &GenericArray<u8, U32>) -> Self {
        Self {
            key: *key,
            cipher: PhantomData,
            nonce_size: PhantomData,
        }
    }
}

impl<C, N> AeadCore for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    type NonceSize = N;

    type TagSize = U32;

    type CiphertextOverhead = U0;
}

impl<C, N> AeadInPlace for ChaChaBlake3<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        let (mut cipher, mut hasher) = new_cipher(C::new(&self.key, nonce));
        if buffer.len() / BLOCK_SIZE as usize >= MAX_BLOCKS {
            return Err(aead::Error);
        }

        hasher.update(associated_data);

        // apply_keystream
        cipher.apply_keystream(buffer);

        hasher.update(buffer);

        mac_auth_len(&mut hasher, associated_data, buffer)?;

        Ok(*GenericArray::from_slice(
            hasher.finalize().as_bytes().as_slice(),
        ))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        let (mut cipher, mut hasher) = new_cipher(C::new(&self.key, nonce));

        hasher.update(associated_data).update(buffer);

        mac_auth_len(&mut hasher, associated_data, buffer)?;

        if hasher.finalize().as_bytes().as_slice().eq(tag.as_slice()) == false {
            Err(aead::Error)?
        }

        // apply_keystream
        cipher.apply_keystream(buffer);

        Ok(())
    }
}

fn new_cipher<C>(mut cipher: C) -> (C, Blake3)
where
    C: StreamCipher + StreamCipherSeek,
{
    let mut key = [0u8; 32];

    cipher.apply_keystream(&mut key);

    let hasher = Blake3::new_keyed(&key);
    key.zeroize();

    cipher.seek(BLOCK_SIZE);

    (cipher, hasher)
}

fn mac_auth_len(hasher: &mut Blake3, aad: &[u8], buf: &[u8]) -> Result<(), aead::Error> {
    let aad_len: u64 = aad.len().try_into().map_err(|_| aead::Error)?;

    let buf_len: u64 = buf.len().try_into().map_err(|_| aead::Error)?;

    let mut generic_array: GenericArray<u8, U16> = GenericArray::default();

    generic_array[..8].copy_from_slice(&aad_len.to_le_bytes());

    generic_array[8..].copy_from_slice(&buf_len.to_le_bytes());

    hasher.update(&generic_array);

    Ok(())
}