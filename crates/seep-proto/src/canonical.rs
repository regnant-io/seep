//! Deterministic serialization for hashing and signing.
//!
//! Every signature in SeeP covers the output of [`to_canonical_bytes`]. Two peers
//! that serialize the same logical value MUST produce byte-identical output, on any
//! platform, in any build, at any version of `serde_json`. The rules:
//!
//! * Object keys are sorted by Unicode scalar value (not by locale, not by insertion).
//! * No insignificant whitespace anywhere.
//! * Strings use the shortest valid JSON escaping, with `/` left unescaped.
//! * Integers render without a fraction or exponent; non-integral floats use
//!   `serde_json`'s shortest-round-trip formatting, which is platform independent.
//! * `null` fields are *retained*, because dropping them would let two different
//!   logical values collide.
//!
//! This is RFC 8785 (JCS) in spirit. It is deliberately implemented by hand rather
//! than delegated to `serde_json::to_vec`, whose key ordering depends on whether the
//! `preserve_order` feature happens to be enabled somewhere in the dependency graph —
//! a footgun that would silently invalidate every signature in the fleet.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("value could not be serialized: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("non-finite number cannot be canonicalized")]
    NonFinite,
}

/// Serialize any `Serialize` value into its canonical byte form.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let json = serde_json::to_value(value)?;
    let mut out = String::with_capacity(256);
    write_canonical(&json, &mut out)?;
    Ok(out.into_bytes())
}

/// Canonical bytes rendered as a UTF-8 string. Useful for debugging and for
/// embedding the exact signed payload into an audit record.
pub fn to_canonical_string<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    Ok(String::from_utf8(to_canonical_bytes(value)?).expect("canonical form is always UTF-8"))
}

/// SHA-256 over the canonical bytes, rendered as `sha256:<hex>`.
///
/// This is the identifier that operators sign and that nodes re-derive before
/// executing anything. A plan whose hash does not match its content is refused.
pub fn canonical_hash<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let bytes = to_canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// SHA-256 over arbitrary bytes, in the same `sha256:<hex>` form used everywhere else.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn write_canonical(value: &serde_json::Value, out: &mut String) -> Result<(), CanonicalError> {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort by Unicode scalar order. `str`'s `Ord` is byte-wise over UTF-8,
            // which yields exactly code-point order — the JCS requirement.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_canonical(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), CanonicalError> {
    if let Some(u) = n.as_u64() {
        let _ = write!(out, "{}", u);
    } else if let Some(i) = n.as_i64() {
        let _ = write!(out, "{}", i);
    } else if let Some(f) = n.as_f64() {
        if !f.is_finite() {
            return Err(CanonicalError::NonFinite);
        }
        // An integral float must render as an integer so that `1.0` and `1`
        // cannot produce two different hashes for the same logical value.
        if f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 {
            let _ = write!(out, "{}", f as i64);
        } else {
            // `serde_json`'s float writer emits the shortest string that
            // round-trips, using a platform-independent algorithm.
            let _ = write!(out, "{}", serde_json::Number::from_f64(f).ok_or(CanonicalError::NonFinite)?);
        }
    } else {
        return Err(CanonicalError::NonFinite);
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_regardless_of_input_order() {
        let a = json!({ "b": 1, "a": 2, "c": 3 });
        let b = json!({ "c": 3, "a": 2, "b": 1 });
        assert_eq!(to_canonical_string(&a).unwrap(), to_canonical_string(&b).unwrap());
        assert_eq!(to_canonical_string(&a).unwrap(), r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn nested_objects_are_sorted_recursively() {
        let v = json!({ "z": { "y": 1, "x": 2 }, "a": [ { "n": 1, "m": 2 } ] });
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            r#"{"a":[{"m":2,"n":1}],"z":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn nulls_are_retained_so_values_cannot_collide() {
        let with_null = json!({ "a": 1, "b": null });
        let without = json!({ "a": 1 });
        assert_ne!(
            to_canonical_string(&with_null).unwrap(),
            to_canonical_string(&without).unwrap()
        );
    }

    #[test]
    fn integral_floats_render_as_integers() {
        assert_eq!(to_canonical_string(&json!(1.0)).unwrap(), "1");
        assert_eq!(to_canonical_string(&json!(1)).unwrap(), "1");
        assert_eq!(to_canonical_string(&json!(-0.0)).unwrap(), "0");
    }

    #[test]
    fn control_characters_are_escaped() {
        let v = json!({ "k": "a\nb\tc\u{1}" });
        // Literal control characters must never survive into canonical output.
        assert_eq!(to_canonical_string(&v).unwrap(), r#"{"k":"a\nb\tc\u0001"}"#);
    }

    #[test]
    fn slash_is_not_escaped() {
        let v = json!({ "url": "https://example.com/a" });
        assert_eq!(to_canonical_string(&v).unwrap(), r#"{"url":"https://example.com/a"}"#);
    }

    #[test]
    fn array_order_is_significant() {
        assert_ne!(
            to_canonical_string(&json!([1, 2])).unwrap(),
            to_canonical_string(&json!([2, 1])).unwrap()
        );
    }

    #[test]
    fn hash_is_stable_and_prefixed() {
        let h = canonical_hash(&json!({ "a": 1 })).unwrap();
        assert!(h.starts_with("sha256:"));
        assert_eq!(h, canonical_hash(&json!({ "a": 1 })).unwrap());
        assert_ne!(h, canonical_hash(&json!({ "a": 2 })).unwrap());
    }

    #[test]
    fn unicode_keys_sort_by_code_point() {
        let v = json!({ "é": 1, "e": 2, "z": 3 });
        // 'e' (0x65) < 'z' (0x7A) < 'é' (0xE9)
        assert_eq!(to_canonical_string(&v).unwrap(), r#"{"e":2,"z":3,"é":1}"#);
    }
}
