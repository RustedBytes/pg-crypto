use pgrx::prelude::*;

const MAX_RANDOM_BYTES: i32 = 1024;

pub(crate) fn random_vec(length: usize) -> Vec<u8> {
    let mut output = vec![0; length];
    dryoc::rng::copy_randombytes(&mut output);
    output
}

#[pg_extern(volatile, parallel_safe)]
fn gen_random_bytes(length: i32) -> Vec<u8> {
    if !(1..=MAX_RANDOM_BYTES).contains(&length) {
        pgrx::error!("length must be between 1 and {MAX_RANDOM_BYTES}");
    }
    random_vec(usize::try_from(length).expect("positive random byte length"))
}

#[pg_extern(volatile, parallel_safe)]
fn random_bytes(length: i32) -> Vec<u8> {
    gen_random_bytes(length)
}

#[pg_extern(volatile, parallel_safe)]
fn gen_random_uuid() -> pgrx::Uuid {
    pgrx::Uuid::from_bytes(*uuid::Uuid::new_v4().as_bytes())
}
