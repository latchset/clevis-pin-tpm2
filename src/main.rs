// SPDX-FileCopyrightText: 2020 Patrick Uiterwijk
// SPDX-FileCopyrightText: 2021 Red Hat, Inc.
//
// SPDX-License-Identifier: MIT

use std::convert::{TryFrom, TryInto};
use std::env;
use std::io::{self, Read, Write};

use anyhow::{bail, Context, Error, Result};
use base64::Engine;
use josekit::jwe::{alg::direct::DirectJweAlgorithm::Dir, enc::A256GCM};
use serde::{Deserialize, Serialize};
use tpm2_policy::TPMPolicyStep;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{MaxBuffer, PcrSelectionListBuilder, PcrSlot, SensitiveData};

mod cli;
mod tpm_objects;
mod utils;

use cli::TPM2Config;

/// Compute a policy digest using caller-supplied PCR values instead of
/// reading them from the TPM. This is a workaround until tpm2-policy
/// supports pcr_digest natively.
///
/// The pcr_digest is the base64url-no-padding encoding of the concatenated
/// raw PCR values (same format as tpm2_pcrread -o output / jose b64 enc).
fn compute_policy_digest_with_pcr_digest(
    ctx: &mut tss_esapi::Context,
    pcr_digest_b64: &str,
    pcr_ids: &[u64],
    pcr_hash_alg: HashingAlgorithm,
    name_hash_alg: HashingAlgorithm,
) -> Result<(Option<AuthSession>, Option<tss_esapi::structures::Digest>)> {
    use tss_esapi::constants::SessionType;
    use tss_esapi::structures::SymmetricDefinition;

    // Decode the base64url-no-padding pcr_digest
    let concatenated_pcr_values = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pcr_digest_b64)
        .context("Error decoding pcr_digest base64")?;
    let concatenated_pcr_values = MaxBuffer::try_from(concatenated_pcr_values)
        .context("Error converting pcr_digest to MaxBuffer")?;

    // Build PCR selection
    // PcrSlot values are bitmask positions (Slot7 = 0x80 = 1 << 7),
    // so we need to convert PCR IDs to bitmask form.
    let pcr_slots: Result<Vec<PcrSlot>> = pcr_ids
        .iter()
        .map(|id| {
            if *id > 23 {
                anyhow::bail!("PCR ID {} out of valid range (0-23)", id);
            }
            let bitmask = 1u32 << (*id as u32);
            PcrSlot::try_from(bitmask).map_err(|e| anyhow::anyhow!("Invalid PCR ID {}: {}", id, e))
        })
        .collect();
    let pcr_sel = PcrSelectionListBuilder::new()
        .with_selection(pcr_hash_alg, &pcr_slots?)
        .build()
        .context("Error building PCR selection")?;

    // Hash the concatenated PCR values using the session hash algorithm
    // (per TPM 2.0 Part 3, Section 23.7: pcrDigest uses the session hash,
    // not the PCR bank hash).
    let (hashed_data, _ticket) = ctx.execute_without_session(|context| {
        context.hash(concatenated_pcr_values, name_hash_alg, Hierarchy::Owner)
    })?;

    // Create a trial policy session
    let trial_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            name_hash_alg,
        )?
        .ok_or_else(|| anyhow::anyhow!("Failed to create trial session"))?;

    // Apply the PCR policy and retrieve the digest. The closure ensures
    // the trial session is always flushed, even on error.
    let result = (|| -> Result<tss_esapi::structures::Digest> {
        ctx.policy_pcr(trial_session.try_into()?, hashed_data, pcr_sel)?;
        Ok(ctx.policy_get_digest(trial_session.try_into()?)?)
    })();

    let session_handle: tss_esapi::handles::SessionHandle = trial_session.into();
    let _ = ctx.flush_context(session_handle.into());

    Ok((None, Some(result?)))
}

fn perform_encrypt(cfg: TPM2Config, input: Vec<u8>) -> Result<()> {
    let key_type = match &cfg.key {
        None => "ecc",
        Some(key_type) => key_type,
    };
    let key_public = tpm_objects::get_key_public(key_type, cfg.get_name_hash_alg())?;

    let mut ctx = utils::get_tpm2_ctx()?;
    let key_handle = utils::get_tpm2_primary_key(&mut ctx, key_public)?;

    let policy_runner: TPMPolicyStep = TPMPolicyStep::try_from(&cfg)?;

    let pin_type = match policy_runner {
        TPMPolicyStep::NoStep => "tpm2",
        TPMPolicyStep::PCRs(_, _, _) => "tpm2",
        _ => "tpm2plus",
    };

    // If pcr_digest is provided, bypass tpm2-policy's PCR reading and
    // manually construct the trial policy with the caller-supplied digest.
    // This enables sealing to predicted/future PCR values.
    let (_, policy_digest) = if let (Some(ref pcr_digest_b64), Some(ref pcr_ids)) =
        (&cfg.pcr_digest, &cfg.get_pcr_ids())
    {
        compute_policy_digest_with_pcr_digest(
            &mut ctx,
            pcr_digest_b64,
            pcr_ids,
            cfg.get_pcr_hash_alg(),
            cfg.get_name_hash_alg(),
        )?
    } else {
        policy_runner.send_policy(&mut ctx, true)?
    };

    let mut jwk = josekit::jwk::Jwk::generate_oct_key(32).context("Error generating random JWK")?;
    jwk.set_key_operations(vec!["encrypt", "decrypt"]);
    let jwk_str = serde_json::to_string(&jwk.as_ref())?;

    let public = tpm_objects::create_tpm2b_public_sealed_object(policy_digest)?.try_into()?;
    let jwk_str = SensitiveData::try_from(jwk_str.as_bytes().to_vec())?;
    let jwk_result = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create(key_handle, public, None, Some(jwk_str), None, None)
    })?;

    let jwk_priv = tpm_objects::get_tpm2b_private(jwk_result.out_private.into())?;

    let jwk_pub = tpm_objects::get_tpm2b_public(jwk_result.out_public.try_into()?)?;

    let private_hdr = ClevisInner {
        pin: pin_type.to_string(),
        tpm2: Tpm2Inner {
            hash: cfg.hash.as_ref().unwrap_or(&"sha256".to_string()).clone(),
            key: key_type.to_string(),
            jwk_pub,
            jwk_priv,
            pcr_bank: cfg.pcr_bank.clone(),
            pcr_ids: cfg.get_pcr_ids_str(),
            policy_pubkey_path: cfg.policy_pubkey_path,
            policy_ref: cfg.policy_ref,
            policy_path: cfg.policy_path,
        },
    };

    let mut hdr = josekit::jwe::JweHeader::new();
    hdr.set_algorithm(Dir.name());
    hdr.set_content_encryption(A256GCM.name());
    hdr.set_claim(
        "clevis",
        Some(serde_json::value::to_value(private_hdr).context("Error serializing private header")?),
    )
    .context("Error adding clevis claim")?;

    let encrypter = Dir
        .encrypter_from_jwk(&jwk)
        .context("Error creating direct encrypter")?;
    let jwe_token = josekit::jwe::serialize_compact(&input, &hdr, &encrypter)
        .context("Error serializing JWE token")?;

    io::stdout().write_all(jwe_token.as_bytes())?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Tpm2Inner {
    hash: String,
    #[serde(
        deserialize_with = "utils::deserialize_as_base64_url_no_pad",
        serialize_with = "utils::serialize_as_base64_url_no_pad"
    )]
    jwk_priv: Vec<u8>,
    #[serde(
        deserialize_with = "utils::deserialize_as_base64_url_no_pad",
        serialize_with = "utils::serialize_as_base64_url_no_pad"
    )]
    jwk_pub: Vec<u8>,
    key: String,

    // PCR Binding may be specified, may not
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_bank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_ids: Option<String>,

    // Public key (in PEM format) for a wildcard policy that's OR'd with the PCR one
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_pubkey_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<String>,
}

impl Tpm2Inner {
    fn get_pcr_ids(&self) -> Option<Vec<u64>> {
        Some(
            self.pcr_ids
                .as_ref()?
                .split(',')
                .map(|x| x.parse::<u64>().unwrap())
                .collect(),
        )
    }
}

impl TryFrom<&Tpm2Inner> for TPMPolicyStep {
    type Error = Error;

    fn try_from(cfg: &Tpm2Inner) -> Result<Self> {
        match (&cfg.pcr_ids, &cfg.policy_pubkey_path) {
            (Some(_), Some(pubkey_path)) => Ok(TPMPolicyStep::Or([
                Box::new(TPMPolicyStep::PCRs(
                    utils::get_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                    cfg.get_pcr_ids().unwrap(),
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(utils::get_authorized_policy_step(
                    pubkey_path,
                    &cfg.policy_path,
                    &cfg.policy_ref,
                )?),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
            ])),
            (Some(_), None) => Ok(TPMPolicyStep::PCRs(
                utils::get_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                cfg.get_pcr_ids().unwrap(),
                Box::new(TPMPolicyStep::NoStep),
            )),
            (None, Some(pubkey_path)) => {
                utils::get_authorized_policy_step(pubkey_path, &cfg.policy_path, &cfg.policy_ref)
            }
            (None, None) => Ok(TPMPolicyStep::NoStep),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ClevisInner {
    pin: String,
    tpm2: Tpm2Inner,
}

fn perform_decrypt(input: Vec<u8>) -> Result<()> {
    let input = String::from_utf8(input)
        .context("Error reading input")?
        .trim()
        .to_string();
    let hdr = josekit::jwt::decode_header(&input).context("Error decoding header")?;
    let hdr_clevis = hdr.claim("clevis").context("Error getting clevis claim")?;
    let hdr_clevis: ClevisInner =
        serde_json::from_value(hdr_clevis.clone()).context("Error deserializing clevis header")?;

    if hdr_clevis.pin != "tpm2" && hdr_clevis.pin != "tpm2plus" {
        bail!("JWE pin mismatch");
    }

    let jwkpub = tpm_objects::build_tpm2b_public(&hdr_clevis.tpm2.jwk_pub)?.try_into()?;
    let jwkpriv = tpm_objects::build_tpm2b_private(&hdr_clevis.tpm2.jwk_priv)?;

    let policy = TPMPolicyStep::try_from(&hdr_clevis.tpm2)?;

    let name_alg = crate::utils::get_hash_alg_from_name(Some(&hdr_clevis.tpm2.hash));
    let key_public = tpm_objects::get_key_public(hdr_clevis.tpm2.key.as_str(), name_alg)?;

    let mut ctx = utils::get_tpm2_ctx()?;
    let key_handle = utils::get_tpm2_primary_key(&mut ctx, key_public)?;

    let key =
        ctx.execute_with_nullauth_session(|ctx| ctx.load(key_handle, jwkpriv.try_into()?, jwkpub))?;

    let (policy_session, _) = policy.send_policy(&mut ctx, false)?;

    let unsealed = ctx.execute_with_session(policy_session, |ctx| ctx.unseal(key.into()))?;
    let unsealed = &unsealed.value();
    let mut jwk = josekit::jwk::Jwk::from_bytes(unsealed).context("Error unmarshaling JWK")?;
    jwk.set_parameter("alg", None)
        .context("Error removing the alg parameter")?;
    let decrypter = Dir
        .decrypter_from_jwk(&jwk)
        .context("Error creating decrypter")?;

    let (payload, _) =
        josekit::jwe::deserialize_compact(&input, &decrypter).context("Error decrypting JWE")?;

    io::stdout().write_all(&payload)?;

    Ok(())
}

fn print_summary() {
    println!("Encrypts using a TPM2.0 chip binding policy");
}

fn print_help() {
    eprintln!(
        "
Usage (encryption): clevis encrypt tpm2 CONFIG < PLAINTEXT > JWE
Usage (decryption): clevis decrypt tpm2 CONFIG < JWE > PLAINTEXT

Encrypts or decrypts using a TPM2.0 chip binding policy

This command uses the following configuration properties:

  hash: <string>  Hash algorithm used in the computation of the object name (default: sha256)

  key: <string>  Algorithm type for the generated key (options: ecc, rsa; default: ecc)

  pcr_bank: <string>  PCR algorithm bank to use for policy (default: sha256)

  pcr_ids: <string>  PCR list used for policy. If not present, no PCR policy is used

  pcr_digest: <string>  base64url-no-pad encoded concatenation of PCR values to seal
                        against, in ascending PCR index order. Requires pcr_ids. When
                        provided, uses the given values instead of reading live PCR state

  use_policy: <bool>  Whether to use a policy

  policy_ref: <string>  Reference to search for in signed policy file (default: {})

  > For policies, the path is {}, and the public key is at {}
",
        cli::DEFAULT_POLICY_REF,
        cli::DEFAULT_POLICY_PATH,
        cli::DEFAULT_PUBKEY_PATH,
    );

    std::process::exit(2);
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let (mode, cfg) = match cli::get_mode_and_cfg(&args) {
        Err(e) => {
            eprintln!("Error during parsing operation: {e}");
            std::process::exit(1);
        }
        Ok((mode, cfg)) => (mode, cfg),
    };

    match mode {
        cli::ActionMode::Summary => {
            print_summary();
            return Ok(());
        }
        cli::ActionMode::Help => {
            print_help();
            return Ok(());
        }
        _ => {}
    };

    let mut input = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut input) {
        eprintln!("Error getting input token: {e}");
        std::process::exit(1);
    }

    match mode {
        cli::ActionMode::Encrypt => perform_encrypt(cfg.unwrap(), input),
        cli::ActionMode::Decrypt => perform_decrypt(input),
        cli::ActionMode::Summary => unreachable!(),
        cli::ActionMode::Help => unreachable!(),
    }
}
