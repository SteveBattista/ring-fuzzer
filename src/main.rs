#![forbid(unsafe_code)]
#[macro_use]
extern crate honggfuzz;

use std::error::Error;
use ring::aead::*;
use ring::digest::{Context, SHA256, SHA384, SHA512, SHA512_256, Digest};

fn test_digest(data :&[u8], aglo: &digest::Algorithm )-> Result<Digest, Box<dyn Error>> {
    let mut context = Context::new(aglo);
    context.update(data);
    Ok(context.finish())
}

fn test_aead(key : &mut u8, data :&[u8], aglo: &aead::Algorithmm ) {
    let content = data.to_vec();

    // Ring uses the same input variable as output
    let mut in_out = content.clone();

    // The input/output variable need some space for a suffix
    //println!("Tag len {}", CHACHA20_POLY1305.tag_len());
    for _ in 0..algo.tag_len() {
        in_out.push(0);
    }

    // Opening key used to decrypt data
    let opening_key = OpeningKey::new(&algo, key).unwrap();

    // Sealing key used to encrypt data
    let sealing_key = SealingKey::new(algo, key).unwrap();

    // Random nonce is first 12 bytes of a hash of the key
    let nonce_byte = &mut [0; 12];
    let mut context = Context::new(&SHA256);
    context.update(&key[..]);
    nonce_byte.copy_from_slice(&context.finish().as_ref()[0..12]);

    // Encrypt data into in_out variable
    seal_in_place(
        &sealing_key,
        Nonce::assume_unique_for_key(*nonce_byte),
        Aad::empty(),
        &mut in_out,
        algo.tag_len(),
    )
    .unwrap();

    // println!("Encrypted data's size {}", output_size);

    let decrypted_data = open_in_place(
        &opening_key,
        Nonce::assume_unique_for_key(*nonce_byte),
        Aad::empty(),
        0,
        &mut in_out,
    )
    .unwrap();

    //println!("{:?}", String::from_utf8(decrypted_data.to_vec()).unwrap());
    assert_eq!(content, decrypted_data);
}

fn main() {
    // Here you can parse `std::env::args and
    // setup / initialize your project
    // You have full control over the loop but
    // you're supposed to call `fuzz` ad vitam aeternam
    loop {
        // The fuzz macro gives an arbitrary object (see `arbitrary crate`)
        // to a closure-like block of code.
        // For performance reasons, it is recommended that you use the native type
        // `&[u8]` when possible.
        // Here, this slice will contain a "random" quantity of "random" data.
        fuzz!(|data: &[u8]| {
            // Use this to create a 32 bit key from random input
            let key = &mut [0; 32];
            let mut context = Context::new(&SHA256);
            context.update(&data);
            key.copy_from_slice(&context.finish().as_ref()[..]);
            test_digest(data,&SHA256);
            test_digest(data,&SHA384);
            test_digest(data,&SHA512);
            test_digest(data,&SHA512_256);
            test_aead(key,data,&CHACHA20_POLY1305);
            test_aead(key,data,&AES_128_GCM);
            test_aead(key,data,&AES_256_GCM);

        });
    }
}
