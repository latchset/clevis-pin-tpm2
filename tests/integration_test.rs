// SPDX-FileCopyrightText: 2021 Red Hat, Inc.
//
// SPDX-License-Identifier: MIT

use std::{io::Write, os::unix::process::CommandExt, process::Command};

use anyhow::{bail, Context, Result};
use base64::Engine;

type CheckFunction = dyn Fn(&str) -> Result<()>;
struct EncryptFunc {
    #[allow(clippy::type_complexity)]
    func: Box<dyn Fn(&str, &str) -> Result<String>>,
    name: &'static str,
}
struct DecryptFunc {
    #[allow(clippy::type_complexity)]
    func: Box<dyn Fn(&str) -> Result<String>>,
    name: &'static str,
}

const EXENAME: &str = env!("CARGO_BIN_EXE_clevis-pin-tpm2");

// An arbitrary non-zero 32-byte value that will not match PCR 23's
// initial all-zeros state. The specific byte values do not matter.
const PCR23_SHA256_WRONG_DIGEST: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

// An arbitrary non-zero 64-byte value for multi-PCR mismatch testing.
const PCR16_23_SHA256_WRONG_DIGEST: &str =
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

const CONFIG_STRINGS: &[(&str, &CheckFunction)] = &[
    // No sealing
    (r#"{}"#, &always_success),
    // No sealing, RSA
    (r#"{"key": "rsa"}"#, &always_success),
    // No sealing with sha1 name alg
    (r#"{"hash": "sha1"}"#, &always_success),
    // Sealed against PCR23
    (r#"{"pcr_ids": [23]}"#, &always_success),
    // sealed against SHA1 PCR23
    (r#"{"pcr_bank": "sha1", "pcr_ids": [23]}"#, &always_success),
    // Sealed against PCR23 with caller-supplied pcr_digest matching swtpm state
    (
        r#"{"pcr_ids": [23], "pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        &check_no_pcr_digest_in_token,
    ),
    // Multi-PCR: sealed against PCR 16+23 with caller-supplied pcr_digest
    (
        r#"{"pcr_ids": [16, 23], "pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        &check_no_pcr_digest_in_token,
    ),
    // SHA-1 bank: sealed against PCR 23 with caller-supplied pcr_digest
    (
        r#"{"pcr_bank": "sha1", "pcr_ids": [23], "pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        &check_no_pcr_digest_in_token,
    ),
];

// Check functions
fn always_success(_token: &str) -> Result<()> {
    Ok(())
}

// Regression guard: verify pcr_digest is not persisted in the JWE token.
fn check_no_pcr_digest_in_token(token: &str) -> Result<()> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 5 {
        bail!("JWE token does not have 5 parts (got {})", parts.len());
    }
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .context("Failed to decode JWE protected header")?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).context("Failed to parse JWE header as JSON")?;
    if let Some(tpm2) = header.get("clevis").and_then(|c| c.get("tpm2")) {
        if tpm2.get("pcr_digest").is_some() {
            bail!("pcr_digest was leaked into the JWE token header");
        }
    }
    if header.get("pcr_digest").is_some() {
        bail!("pcr_digest was leaked into the top-level JWE header");
    }
    Ok(())
}

fn call_cmd_and_get_output(cmd: &mut Command, input: &str) -> Result<String> {
    if let Ok(val) = std::env::var("TCTI") {
        cmd.env("TCTI", &val);
        cmd.env("TPM2TOOLS_TCTI", &val);
    }

    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn process")?;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .context("Failed to write input")?;
    let output = child
        .wait_with_output()
        .context("Failed to wait for process")?;
    if !output.status.success() {
        bail!("Command failed: {:?}", cmd);
    }
    Ok(String::from_utf8(output.stdout)?)
}

// Encrypt/Decrypt functions
fn generate_encrypt_us(renamed: bool) -> EncryptFunc {
    EncryptFunc {
        name: if renamed { "us_renamed" } else { "us" },
        func: Box::new(move |plaintext: &str, config: &str| -> Result<String> {
            let mut cmd = Command::new(EXENAME);
            call_cmd_and_get_output(
                if renamed {
                    cmd.arg0("clevis-encrypt-tpm2plus").arg(config)
                } else {
                    cmd.arg("encrypt").arg(config)
                },
                plaintext,
            )
        }),
    }
}

fn generate_decrypt_us(renamed: bool) -> DecryptFunc {
    DecryptFunc {
        name: if renamed { "us_renamed" } else { "us" },
        func: Box::new(move |input: &str| -> Result<String> {
            let mut cmd = Command::new(EXENAME);
            call_cmd_and_get_output(
                if renamed {
                    cmd.arg0("clevis-decrypt-tpm2plus")
                } else {
                    cmd.arg("decrypt")
                },
                input,
            )
        }),
    }
}

fn generate_encrypt_clevis() -> EncryptFunc {
    EncryptFunc {
        name: "clevis",
        func: Box::new(move |plaintext: &str, config: &str| -> Result<String> {
            call_cmd_and_get_output(
                Command::new("clevis")
                    .arg("encrypt")
                    .arg("tpm2")
                    .arg(config),
                plaintext,
            )
        }),
    }
}

fn generate_decrypt_clevis() -> DecryptFunc {
    DecryptFunc {
        name: "clevis",
        func: Box::new(move |input: &str| -> Result<String> {
            call_cmd_and_get_output(Command::new("clevis").arg("decrypt"), input)
        }),
    }
}

const INPUT: &str = "some-static-content";

const FAIL_FAST: Option<&'static str> = option_env!("FAIL_FAST");
const SKIP_CLEVIS: Option<&'static str> = option_env!("SKIP_CLEVIS");

// Testing against clevis requires https://github.com/latchset/clevis/commit/c6fc63fc055c18927decc7bcaa07821d5ae37614
#[test]
fn pcr_tests() {
    let mut encrypters = vec![generate_encrypt_us(false), generate_encrypt_us(true)];
    let mut decrypters = vec![generate_decrypt_us(false), generate_decrypt_us(true)];
    if SKIP_CLEVIS.is_none() {
        encrypters.push(generate_encrypt_clevis());
        decrypters.push(generate_decrypt_clevis());
    }

    let mut failed: u64 = 0;

    for (config, checker) in CONFIG_STRINGS {
        for encrypt_fn in &encrypters {
            for decrypt_fn in &decrypters {
                if encrypt_fn.name == decrypt_fn.name && encrypt_fn.name == "clevis" {
                    // This is a boring case we're not interested in
                    continue;
                }

                if failed != 0 && FAIL_FAST.is_some() {
                    panic!("At least one test failed, and fail-fast enabled");
                }

                eprintln!(
                    "Executing with encrypt: {}, decrypt: {}, config: '{}'",
                    encrypt_fn.name, decrypt_fn.name, config,
                );

                eprintln!("\tStarting encrypter");
                let encrypted = (encrypt_fn.func)(INPUT, config);
                if let Err(e) = encrypted {
                    eprintln!("FAILED: error: {e:?}");
                    failed += 1;
                    continue;
                }
                let encrypted = encrypted.unwrap();
                eprintln!("\tStarting checker");
                if let Err(e) = checker(&encrypted) {
                    eprintln!("FAILED: error: {e:?}");
                    failed += 1;
                    continue;
                }
                eprintln!("\tStarting decrypter");
                let decrypted = (decrypt_fn.func)(&encrypted);
                if let Err(e) = decrypted {
                    eprintln!("FAILED: error: {e:?}");
                    failed += 1;
                    continue;
                }
                let decrypted = decrypted.unwrap();
                eprintln!("\tStarting contents checker");
                if decrypted != INPUT {
                    eprintln!("FAILED: '{INPUT}' (input) != '{decrypted}' (decrypted)");
                    failed += 1;
                    continue;
                }
                eprintln!("\tPASSED");
            }
        }
    }

    if failed != 0 {
        panic!("{} tests failed", failed);
    }

    // Negative test: sealing with a pcr_digest that does not match the
    // live PCR values must encrypt successfully but fail to decrypt (the
    // TPM refuses to unseal). This is the primary regression guard against
    // the original bug where pcr_digest was silently ignored.
    let mismatch_cases: &[(&str, &str)] = &[
        (
            &format!(
                r#"{{"pcr_ids": [23], "pcr_digest": "{}"}}"#,
                PCR23_SHA256_WRONG_DIGEST
            ),
            "single-PCR",
        ),
        (
            &format!(
                r#"{{"pcr_ids": [16, 23], "pcr_digest": "{}"}}"#,
                PCR16_23_SHA256_WRONG_DIGEST
            ),
            "multi-PCR",
        ),
    ];

    let encrypt_fn = generate_encrypt_us(false);
    let decrypt_fn = generate_decrypt_us(false);

    for (config, label) in mismatch_cases {
        eprintln!("pcr_digest_mismatch ({label}): encrypting with non-matching digest");
        let encrypted = (encrypt_fn.func)(INPUT, config)
            .expect("encrypt with mismatched pcr_digest should succeed");

        let parts: Vec<&str> = encrypted.trim().split('.').collect();
        assert_eq!(
            parts.len(),
            5,
            "encrypted output is not a valid JWE (expected 5 parts, got {})",
            parts.len()
        );

        eprintln!("pcr_digest_mismatch ({label}): decrypting (should fail)");
        let result = (decrypt_fn.func)(&encrypted);
        assert!(
            result.is_err(),
            "decrypt should fail when pcr_digest does not match live PCR values ({})",
            label
        );
        eprintln!("pcr_digest_mismatch ({label}): PASSED");
    }
}
