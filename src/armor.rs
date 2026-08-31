use std::io::{Cursor, Read, Write};

use pgrx::prelude::*;
use sequoia_openpgp::armor::{Kind, Reader, ReaderMode, Writer};

fn armor_error(context: &str, error: impl std::fmt::Display) -> ! {
    pgrx::error!("{context}: {error}")
}

fn encode_armor(data: &[u8], headers: &[(String, String)]) -> String {
    let mut writer = Writer::with_headers(
        Vec::new(),
        Kind::Message,
        headers.iter().map(|(key, value)| (key, value)),
    )
    .unwrap_or_else(|error| armor_error("could not initialize ASCII armor", error));
    writer
        .write_all(data)
        .unwrap_or_else(|error| armor_error("could not encode ASCII armor", error));
    String::from_utf8(
        writer
            .finalize()
            .unwrap_or_else(|error| armor_error("could not finalize ASCII armor", error)),
    )
    .unwrap_or_else(|error| armor_error("ASCII armor was not UTF-8", error))
}

#[pg_extern(immutable, parallel_safe)]
fn armor(data: &[u8]) -> String {
    encode_armor(data, &[])
}

#[pg_extern(name = "armor", immutable, parallel_safe)]
#[allow(clippy::needless_pass_by_value)] // pgrx SQL array arguments are passed by value.
fn armor_with_headers(data: &[u8], keys: Array<'_, &str>, values: Array<'_, &str>) -> String {
    let key_array = keys
        .iter()
        .map(|key| {
            let key = key.unwrap_or_else(|| pgrx::error!("armor header keys cannot be NULL"));
            key.to_owned()
        })
        .collect::<Vec<_>>();
    let key_dimensions = unsafe { (*keys.into_array_type()).ndim };
    let value_array = values
        .iter()
        .map(|value| {
            let value = value.unwrap_or_else(|| pgrx::error!("armor header values cannot be NULL"));
            value.to_owned()
        })
        .collect::<Vec<_>>();
    let value_dimensions = unsafe { (*values.into_array_type()).ndim };
    if key_dimensions > 1 || key_dimensions != value_dimensions {
        pgrx::error!("wrong number of armor header array subscripts");
    }
    if key_array.len() != value_array.len() {
        pgrx::error!("armor header arrays have mismatched dimensions");
    }
    let headers = key_array
        .into_iter()
        .zip(value_array)
        .map(|(key, value)| {
            if !key.is_ascii() {
                pgrx::error!("armor header key must not contain non-ASCII characters");
            }
            if key.contains(": ") {
                pgrx::error!("armor header key must not contain ': '");
            }
            if key.contains('\n') {
                pgrx::error!("armor header key must not contain newlines");
            }
            if !value.is_ascii() {
                pgrx::error!("armor header value must not contain non-ASCII characters");
            }
            if value.contains('\n') {
                pgrx::error!("armor header value must not contain newlines");
            }
            (key, value)
        })
        .collect::<Vec<_>>();
    encode_armor(data, &headers)
}

#[pg_extern(immutable, parallel_safe)]
fn dearmor(data: &str) -> Vec<u8> {
    let mut reader = Reader::from_reader(
        Cursor::new(data.as_bytes()),
        ReaderMode::Tolerant(Some(Kind::Message)),
    );
    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .unwrap_or_else(|error| armor_error("invalid ASCII armor", error));
    output
}

#[pg_extern(immutable, parallel_safe)]
fn pgp_armor_headers(
    data: &str,
) -> TableIterator<'static, (name!(key, String), name!(value, String))> {
    let mut reader = Reader::from_reader(
        Cursor::new(data.as_bytes()),
        ReaderMode::Tolerant(Some(Kind::Message)),
    );
    let headers = reader
        .headers()
        .unwrap_or_else(|error| armor_error("invalid ASCII armor", error))
        .to_vec();
    TableIterator::new(headers)
}
