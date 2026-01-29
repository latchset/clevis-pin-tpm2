// SPDX-FileCopyrightText: 2021 Red Hat, Inc.
//
// SPDX-License-Identifier: MIT

use std::{io::Write, os::unix::process::CommandExt, process::Command};

use anyhow::{bail, Context, Result};

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
];

// Check functions
fn always_success(_token: &str) -> Result<()> {
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
}
