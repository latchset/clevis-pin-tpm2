// SPDX-FileCopyrightText: 2021 Red Hat, Inc.
//
// SPDX-License-Identifier: MIT

use std::env;
use std::fs;
use std::str::FromStr;

use anyhow::{Context as anyhow_context, Result};
use base64::Engine;
use serde::Deserialize;
use tpm2_policy::{PublicKey, SignedPolicyList, TPMPolicyStep};
use tss_esapi::{
    handles::KeyHandle,
    interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
    structures::Public,
    Context, Tcti,
};

pub(crate) fn get_authorized_policy_step(
    policy_pubkey_path: &str,
    policy_path: &Option<String>,
    policy_ref: &Option<String>,
) -> Result<TPMPolicyStep> {
    let policy_ref = match policy_ref {
        Some(policy_ref) => policy_ref.as_bytes().to_vec(),
        None => vec![],
    };

    let signkey = {
        let contents =
            fs::read_to_string(policy_pubkey_path).context("Error reading policy signkey")?;
        serde_json::from_str::<PublicKey>(&contents)
            .context("Error deserializing signing public key")?
    };

    let policies = match policy_path {
        None => None,
        Some(policy_path) => {
            let contents = fs::read_to_string(policy_path).context("Error reading policy")?;
            Some(
                serde_json::from_str::<SignedPolicyList>(&contents)
                    .context("Error deserializing policy")?,
            )
        }
    };

    Ok(TPMPolicyStep::Authorized {
        signkey,
        policy_ref,
        policies,
        next: Box::new(TPMPolicyStep::NoStep),
    })
}

pub(crate) fn get_hash_alg_from_name(name: Option<&String>) -> HashingAlgorithm {
    match name {
        None => HashingAlgorithm::Sha256,
        Some(val) => match val.to_lowercase().as_str() {
            "sha1" => HashingAlgorithm::Sha1,
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            _ => panic!("Unsupported hash algo: {:?}", name),
        },
    }
}

pub(crate) fn serialize_as_base64_url_no_pad<S>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn deserialize_as_base64_url_no_pad<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(string)
            .map_err(serde::de::Error::custom)
    })
}

pub(crate) fn get_tpm2_ctx() -> Result<tss_esapi::Context> {
    let tcti_path = match env::var("TCTI") {
        Ok(val) => val,
        Err(_) => {
            if std::path::Path::new("/dev/tpmrm0").exists() {
                "device:/dev/tpmrm0".to_string()
            } else {
                "device:/dev/tpm0".to_string()
            }
        }
    };

    let tcti = Tcti::from_str(&tcti_path).context("Error parsing TCTI specification")?;
    Context::new(tcti).context("Error initializing TPM2 context")
}

pub(crate) fn get_tpm2_primary_key(ctx: &mut Context, pub_template: Public) -> Result<KeyHandle> {
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, pub_template, None, None, None, None)
            .map(|r| r.key_handle)
    })
    .map_err(|e| e.into())
}
