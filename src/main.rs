#![forbid(unsafe_code)]
#[macro_use]
extern crate honggfuzz;

use rand::*;
use ring::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use ring::agreement::{ECDH_P256, ECDH_P384, X25519};
use ring::digest::{Context, SHA256, SHA384, SHA512, SHA512_256};
use ring::hkdf::{HKDF_SHA256, HKDF_SHA384, HKDF_SHA512};
use ring::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};
use ring::pbkdf2::{PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512};
use ring::signature::KeyPair;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING,ECDSA_P256_SHA256_FIXED,ECDSA_P256_SHA256_ASN1_SIGNING,ECDSA_P256_SHA256_ASN1};
use ring::signature::{ECDSA_P384_SHA384_FIXED_SIGNING,ECDSA_P384_SHA384_FIXED,ECDSA_P384_SHA384_ASN1_SIGNING,ECDSA_P384_SHA384_ASN1};

//use ring::test::rand as testrand;
//use data_encoding::BASE64;
extern crate arrayref;

const NONCELEN: usize= 12;
const KEY128: usize = 16;
const KEY256: usize = 32;
const KEY384: usize = 48;

const MAXRANDLEN: usize = 500;

fn test_aead(key: &[u8], data: &[u8], _random1: &[u8], algo: &'static ring::aead::Algorithm) {
    // Ring uses the same input variable as output
    let mut in_out = data.to_vec();


    // The input/output variable need some space for a suffix
    for _ in 0..algo.tag_len() {
        in_out.push(0);
    }

    // Opening key used to decrypt data
    let unboud_key = ring::aead::UnboundKey::new(algo, key).unwrap();
    let less_safe_key = ring::aead::LessSafeKey::new(unboud_key);

    let nonce_byte = &mut [0; NONCELEN];

    nonce_byte.copy_from_slice(&key[0..NONCELEN]);

    // Encrypt data into in_out variable
    ring::aead::LessSafeKey::seal_in_place_append_tag(
        &less_safe_key,
        ring::aead::Nonce::assume_unique_for_key(*nonce_byte),
        ring::aead::Aad::empty(),
        &mut in_out,
    )
    .unwrap();

    // println!("Encrypted data's size {}", output_size);

    let decrypted_data = ring::aead::LessSafeKey::open_in_place(
        &less_safe_key,
        ring::aead::Nonce::assume_unique_for_key(*nonce_byte),
        ring::aead::Aad::empty(),
        &mut in_out,
    )
    .unwrap();

    //println!("{}", BASE64.encode(&data[..]));
    //println!("{}", BASE64.encode(&decrypted_data[..datalength]));
    assert_eq!(data[..], decrypted_data[..data.len()]);
}
fn test_agreement(key: &[u8], algo: &'static ring::agreement::Algorithm) {
    //let rng = ringrand::SystemRandom::new();
    //TODO make the key a SHA512 hash of data then take values
    let rng = ring::test::rand::FixedSliceRandom {
        bytes: &key,
    };
    let my_private_key = ring::agreement::EphemeralPrivateKey::generate(&algo, &rng).unwrap();

    // Make `my_public_key` a byte slice containing my public key. In a real
    // application, this would be sent to the peer in an encoded protocol
    // message.
    let _my_public_key = my_private_key.compute_public_key().unwrap();
    let peer_private_key = ring::agreement::EphemeralPrivateKey::generate(&algo, &rng).unwrap();
    let peer_public_key = peer_private_key.compute_public_key().unwrap();
    let peer_public_key = ring::agreement::UnparsedPublicKey::new(&algo, peer_public_key);

    // In a real application, the peer public key would be parsed out of a
    // protocol message. Here we just generate one.

    ring::agreement::agree_ephemeral(
        my_private_key,
        &peer_public_key,
        ring::error::Unspecified,
        |_key_material| {
            // In a real application, we'd apply a KDF to the key material and the
            // public keys (as recommended in RFC 7748) and then derive session
            // keys from the result. We omit all that here.
            Ok(())
        },
    )
    .unwrap();
}

fn test_digest(data: &[u8], aglo: &'static ring::digest::Algorithm) {
    let mut context = Context::new(aglo);
    context.update(data);
    context.finish();
}
struct My<T>(T);

impl ring::hkdf::KeyType for My<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<ring::hkdf::Okm<'_, My<usize>>> for My<Vec<u8>> {
    fn from(okm: ring::hkdf::Okm<My<usize>>) -> Self {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r).unwrap();
        My(r)
    }
}
fn test_hkdf(
    data: &[u8],
    _random1: &[u8],
    random2: &[u8],
    key: &[u8],
    algo: ring::hkdf::Algorithm,
) {
    //println!("datalen: {} , random1len {} , random2len {}, keylen {}",data.len(),random1.len(),random2.len(),key.len());
    let salt = ring::hkdf::Salt::new(algo, key);
    let prk = salt.extract(key);
    let My(_out) = prk.expand(&[&data], My(random2.len())).unwrap().into();
    //println!("HDKF: {}", BASE64.encode(out.as_ref()));
}

fn test_hmac(key: &[u8], data: &[u8], algo: ring::hmac::Algorithm) {
    let key = ring::hmac::Key::new(algo, key);
    let signature = ring::hmac::sign(&key, data);
    assert_eq!(
        true,
        ring::hmac::verify(&key, data, signature.as_ref()).is_ok()
    );
}

fn test_pbkdf2(
    data: &[u8],
    random1: &[u8],
    random2: &[u8],
    algo:ring::pbkdf2::Algorithm,
) {
    let mut out = vec![0; random1.len()];
    let iterations = random2.len();
    let iterations = std::num::NonZeroU32::new(iterations as u32).unwrap();
    ring::pbkdf2::derive(algo, iterations, &random2, &data, &mut out);
    let answer = ring::pbkdf2::verify(algo, iterations, &random2, &data, out.as_ref());
    //println!("out: {}", BASE64.encode(out.as_ref()));
    assert_eq!(answer, Ok(()));
}

fn test_ed25519(data: &[u8], key: &[u8]) {
    let rng = ring::test::rand::FixedSliceRandom { bytes: &key };
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let sig = key_pair.sign(data);

    // Normally an application would extract the bytes of the signature and
    // send them in a protocol message to the peer(s). Here we just get the
    // public key key directly from the key pair.
    let peer_public_key_bytes = key_pair.public_key().as_ref();

    // Verify the signature of the message using the public key. Normally the
    // verifier of the message would parse the inputs to this code out of the
    // protocol message(s) sent by the signer.
    let peer_public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, peer_public_key_bytes);
    peer_public_key.verify(data, sig.as_ref()).unwrap();
}

fn test_ecdsa(data: &[u8], key: &[u8], signalgo : &'static ring::signature::EcdsaSigningAlgorithm , verifyalgo :&'static ring::signature::EcdsaVerificationAlgorithm) {
    //println!("{}",BASE64.encode(key.as_ref()));
    let rng = ring::test::rand::FixedSliceRandom { bytes: &key};
    //println!("{}",BASE64.encode(key.as_ref()));
    let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(signalgo,&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(signalgo, pkcs8_bytes.as_ref()).unwrap();

    let sig = key_pair.sign(&rng,data).unwrap();

    // Normally an application would extract the bytes of the signature and
    // send them in a protocol message to the peer(s). Here we just get the
    // public key key directly from the key pair.
    let peer_public_key_bytes = key_pair.public_key().as_ref();

    // Verify the signature of the message using the public key. Normally the
    // verifier of the message would parse the inputs to this code out of the
    // protocol message(s) sent by the signer.
    let peer_public_key =
        ring::signature::UnparsedPublicKey::new(verifyalgo, peer_public_key_bytes);
    peer_public_key.verify(data, sig.as_ref()).unwrap();
}

/*fn test_rsa(data: &[u8], key: &[u8], padding_alg: &ring::signature::RsaEncoding ,  signalgo : &'static ring::signature::RsaParameters:: , verifyalgo :&'static ring::signature::VerificationAlgorithm) {
    let rng = ring::test::rand::FixedSliceRandom { bytes: &key};
    let pkcs8_bytes = ring::signature::RsaKeyPair::generate_pkcs8(signalgo,&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let signature : &mut [u8] =&mut [0;1024]; //need to fix length
    key_pair.sign(padding_alg,&rng,data,signature).unwrap();

    // Normally an application would extract the bytes of the signature and
    // send them in a protocol message to the peer(s). Here we just get the
    // public key key directly from the key pair.
    let peer_public_key_bytes = key_pair.public_key().as_ref();

    // Verify the signature of the message using the public key. Normally the
    // verifier of the message would parse the inputs to this code out of the
    // protocol message(s) sent by the signer.
    let peer_public_key =
        ring::signature::UnparsedPublicKey::new(verifyalgo, peer_public_key_bytes);
    peer_public_key.verify(data, signature.as_ref()).unwrap();
}*/

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

        //println!("Data: {}", BASE64.encode(data));

        let mut context = ring::digest::Context::new(&SHA384);
        context.update(data);
        let digest = context.finish();
        let key =digest.as_ref();
        //println!("{}",key.len());
        //println!("{}",BASE64.encode(key.as_ref()));

        let mut rng: rand::rngs::StdRng =
            rand::SeedableRng::from_seed(*arrayref::array_ref!(&key[..KEY256], 0, KEY256));
        // Can't be 0 needed for pbkdf2
        let randomlen = rng.gen_range(1, MAXRANDLEN);
        let mut content = Vec::new();
        for _ in 0..randomlen {
            let value: u8 = rng.gen();
            content.push(value);
        }
        let random1: &[u8] = content.as_ref();
        //println!("random1len: {}", random1.len());
        //println!("random1: {}", BASE64.encode(random1));
        // Can't be 0 needed for pbkdf2
        let randomlen = rng.gen_range(1, MAXRANDLEN); //Needs to be non-zero
        let mut content = Vec::new();
        for _ in 0..randomlen {
            let value: u8 = rng.gen();
            content.push(value);
        }
        let random2: &[u8] = content.as_ref();
        //println!("random2len: {}", random2.len());
        //println!("random2: {}", BASE64.encode(random2));

        // Should I re-key the key with random values rather than use hash?
        /*let mut content = Vec::new();
        for _ in 0..48{
            let value: u8 = rng.gen();
            content.push(value);
        }
        let key: &[u8] = content.as_ref(); */

        test_aead(&key[..KEY256], data, random1, &CHACHA20_POLY1305);
        test_aead(&key[0..KEY128], data, random1, &AES_128_GCM);
        test_aead(&key[..KEY256], data, random1, &AES_256_GCM);
        //println!("done aead");

        test_agreement(&key[..KEY256],&ECDH_P256);
        test_agreement(&key[..KEY384],&ECDH_P384);
        test_agreement(&key[..KEY256],&X25519);
        //println!("done agreement");

        test_digest(data, &SHA256);
        //test_digest(data, &SHA384); Used in generation of key.
        test_digest(data, &SHA512);
        test_digest(data, &SHA512_256);
        //println!("done digest");

        test_hkdf(data, random1, random2, &key[..KEY256], HKDF_SHA256);
        test_hkdf(data, random1, random2, &key[..KEY256], HKDF_SHA384);
        test_hkdf(data, random1, random2, &key[..KEY256], HKDF_SHA512);
        //println!("done hkdf");

        test_hmac(data, &key[..KEY256], HMAC_SHA256);
        test_hmac(data, &key[..KEY256], HMAC_SHA384);
        test_hmac(data, &key[..KEY256], HMAC_SHA512);
        //println!("done hmac");

        test_pbkdf2(data, random1, random2, PBKDF2_HMAC_SHA256);
        test_pbkdf2(data, random1, random2, PBKDF2_HMAC_SHA384);
        test_pbkdf2(data, random1, random2, PBKDF2_HMAC_SHA512);
        //println!("done pbkdf2");

        test_ecdsa(data, &key[..KEY256],&ECDSA_P256_SHA256_FIXED_SIGNING,&ECDSA_P256_SHA256_FIXED);
        test_ecdsa(data, &key[..KEY256],&ECDSA_P256_SHA256_ASN1_SIGNING,&ECDSA_P256_SHA256_ASN1);
        test_ecdsa(data, &key,&ECDSA_P384_SHA384_FIXED_SIGNING,&ECDSA_P384_SHA384_FIXED);
        test_ecdsa(data, &key,&ECDSA_P384_SHA384_ASN1_SIGNING,&ECDSA_P384_SHA384_ASN1);
        //println!("done ecdsa");

        test_ed25519(data, &key[..KEY256]);
        //println!("done ed25519");
    });
}
}
