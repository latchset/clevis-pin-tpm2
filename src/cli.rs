// SPDX-FileCopyrightText: 2021 Red Hat, Inc.
//
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;

use anyhow::{anyhow, bail, Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use tpm2_policy::TPMPolicyStep;

use crate::utils::get_authorized_policy_step;

#[derive(Serialize, Deserialize, std::fmt::Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct TPM2Config {
    pub hash: Option<String>,
    pub key: Option<String>,
    pub pcr_bank: Option<String>,
    // PCR IDs can be passed in as comma-separated string or json array
    pub pcr_ids: Option<serde_json::Value>,
    pub pcr_digest: Option<String>,
    // Whether to use a policy. If this is specified without pubkey path or policy path, they get set to defaults
    pub use_policy: Option<bool>,
    // Public key (in JSON format) for a wildcard policy that's possibly OR'd with the PCR one
    pub policy_pubkey_path: Option<String>,
    pub policy_ref: Option<String>,
    pub policy_path: Option<String>,
}

impl TryFrom<&TPM2Config> for TPMPolicyStep {
    type Error = Error;

    fn try_from(cfg: &TPM2Config) -> Result<Self> {
        match (&cfg.pcr_ids, &cfg.policy_pubkey_path) {
            (Some(_), Some(pubkey_path)) => Ok(TPMPolicyStep::Or([
                Box::new(TPMPolicyStep::PCRs(
                    cfg.get_pcr_hash_alg()?,
                    cfg.get_pcr_ids()?
                        .ok_or_else(|| anyhow!("pcr_ids unexpectedly empty"))?,
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(get_authorized_policy_step(
                    pubkey_path,
                    &None,
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
                cfg.get_pcr_hash_alg()?,
                cfg.get_pcr_ids()?
                    .ok_or_else(|| anyhow!("pcr_ids unexpectedly empty"))?,
                Box::new(TPMPolicyStep::NoStep),
            )),
            (None, Some(pubkey_path)) => {
                get_authorized_policy_step(pubkey_path, &None, &cfg.policy_ref)
            }
            (None, None) => Ok(TPMPolicyStep::NoStep),
        }
    }
}

pub(crate) const DEFAULT_POLICY_PATH: &str = "/boot/clevis_policy.json";
pub(crate) const DEFAULT_PUBKEY_PATH: &str = "/boot/clevis_pubkey.json";
pub(crate) const DEFAULT_POLICY_REF: &str = "";

impl TPM2Config {
    pub(super) fn get_pcr_hash_alg(
        &self,
    ) -> anyhow::Result<tss_esapi::interface_types::algorithm::HashingAlgorithm> {
        crate::utils::get_hash_alg_from_name(self.pcr_bank.as_ref())
    }

    pub(super) fn get_name_hash_alg(
        &self,
    ) -> anyhow::Result<tss_esapi::interface_types::algorithm::HashingAlgorithm> {
        crate::utils::get_hash_alg_from_name(self.hash.as_ref())
    }

    pub(super) fn get_pcr_ids(&self) -> Result<Option<Vec<u64>>> {
        match &self.pcr_ids {
            None => Ok(None),
            Some(serde_json::Value::Array(vals)) => {
                let ids: Result<Vec<u64>> = vals
                    .iter()
                    .map(|x| {
                        x.as_u64()
                            .ok_or_else(|| anyhow!("non-u64 value in pcr_ids"))
                    })
                    .collect();
                Ok(Some(ids?))
            }
            _ => bail!("Unexpected type found for pcr_ids"),
        }
    }

    pub(super) fn get_pcr_ids_str(&self) -> Result<Option<String>> {
        match &self.pcr_ids {
            None => Ok(None),
            Some(serde_json::Value::Array(vals)) => {
                let strs: Result<Vec<String>> = vals
                    .iter()
                    .map(|x| {
                        x.as_u64()
                            .map(|v| v.to_string())
                            .ok_or_else(|| anyhow!("non-u64 value in pcr_ids"))
                    })
                    .collect();
                Ok(Some(strs?.join(",")))
            }
            _ => bail!("Unexpected type found for pcr_ids"),
        }
    }

    fn normalize(mut self) -> Result<TPM2Config> {
        self.normalize_pcr_ids()?;
        if self.pcr_ids.is_some() && self.pcr_bank.is_none() {
            self.pcr_bank = Some("sha256".to_string());
        }
        if let Some(ref hash) = self.hash {
            crate::utils::get_hash_alg_from_name(Some(hash))?;
        }
        if let Some(ref bank) = self.pcr_bank {
            crate::utils::get_hash_alg_from_name(Some(bank))?;
        }
        // tpm2-policy 0.6.0 hardcodes SHA-256 for policy sessions on the
        // decrypt path, so non-SHA-256 name hash with PCR binding would
        // produce tokens that encrypt successfully but can never be unsealed.
        if self.pcr_ids.is_some() {
            if let Some(ref hash) = self.hash {
                if hash.to_lowercase() != "sha256" {
                    bail!(
                        "non-SHA-256 hash is not supported with PCR binding \
                         (tpm2-policy hardcodes SHA-256 for policy sessions)"
                    );
                }
            }
        }
        if self.pcr_digest.is_some() && self.pcr_ids.is_none() {
            bail!("pcr_digest requires pcr_ids");
        }
        if let Some(ref digest) = self.pcr_digest {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(digest)
                .map_err(|e| anyhow!("invalid pcr_digest base64: {}", e))?;
            if decoded.is_empty() {
                bail!("pcr_digest must not be empty");
            }
            if let Some(ref pcr_ids) = self.pcr_ids {
                let num_pcrs = match pcr_ids {
                    serde_json::Value::Array(v) => v.len(),
                    _ => bail!("pcr_ids has unexpected type (expected array)"),
                };
                let hash_size = crate::utils::hash_digest_size(self.pcr_bank.as_ref())?;
                let expected = num_pcrs * hash_size;
                if decoded.len() != expected {
                    bail!(
                        "pcr_digest length {} does not match expected {} ({} PCRs * {} bytes)",
                        decoded.len(),
                        expected,
                        num_pcrs,
                        hash_size
                    );
                }
            }
        }
        // Make use of the defaults if not specified
        if self.use_policy.is_some() && self.use_policy.unwrap() {
            if self.policy_path.is_none() {
                self.policy_path = Some(DEFAULT_POLICY_PATH.to_string());
            }
            if self.policy_pubkey_path.is_none() {
                self.policy_pubkey_path = Some(DEFAULT_PUBKEY_PATH.to_string());
            }
            if self.policy_ref.is_none() {
                self.policy_ref = Some(DEFAULT_POLICY_REF.to_string());
            }
        } else if self.policy_pubkey_path.is_some()
            || self.policy_path.is_some()
            || self.policy_ref.is_some()
        {
            eprintln!("To use a policy, please specifiy use_policy: true. Not specifying this will be a fatal error in a next release");
        }
        if self.pcr_digest.is_some() && self.policy_pubkey_path.is_some() {
            bail!("pcr_digest cannot be combined with authorized policy");
        }
        if (self.policy_pubkey_path.is_some()
            || self.policy_path.is_some()
            || self.policy_ref.is_some())
            && (self.policy_pubkey_path.is_none()
                || self.policy_path.is_none()
                || self.policy_ref.is_none())
        {
            bail!("Not all of policy pubkey, path and ref are specified",);
        }
        Ok(self)
    }

    fn normalize_pcr_ids(&mut self) -> Result<()> {
        // Normalize from array with one string to just string
        if let Some(serde_json::Value::Array(vals)) = &self.pcr_ids {
            if vals.len() == 1 {
                if let serde_json::Value::String(val) = &vals[0] {
                    self.pcr_ids = Some(serde_json::Value::String(val.to_string()));
                }
            }
        }
        // Normalize pcr_ids from comma-separated string to array
        if let Some(serde_json::Value::String(val)) = &self.pcr_ids {
            // Was a string, do a split
            let newval: Vec<serde_json::Value> = val
                .split(',')
                .map(|x| serde_json::Value::String(x.trim().to_string()))
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newval));
        }
        // Normalize pcr_ids from array of Strings to array of Numbers
        if let Some(serde_json::Value::Array(vals)) = &self.pcr_ids {
            let newvals: Result<Vec<serde_json::Value>, _> = vals
                .iter()
                .map(|x| match x {
                    serde_json::Value::String(val) => {
                        match val.trim().parse::<serde_json::Number>() {
                            Ok(res) => {
                                let new = serde_json::Value::Number(res);
                                if !new.is_u64() {
                                    bail!("Non-positive string int");
                                }
                                let v = new.as_u64().unwrap();
                                if v > 23 {
                                    bail!("PCR ID {} out of valid range (0-23)", v);
                                }
                                Ok(new)
                            }
                            Err(_) => Err(anyhow!("Unparseable string int")),
                        }
                    }
                    serde_json::Value::Number(n) => {
                        let new = serde_json::Value::Number(n.clone());
                        if !new.is_u64() {
                            return Err(anyhow!("Non-positive int"));
                        }
                        let v = new.as_u64().unwrap();
                        if v > 23 {
                            bail!("PCR ID {} out of valid range (0-23)", v);
                        }
                        Ok(new)
                    }
                    _ => Err(anyhow!("Invalid value in pcr_ids")),
                })
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newvals?));
        }

        if let Some(serde_json::Value::Array(ref mut vals)) = self.pcr_ids {
            vals.sort_by_key(|v| v.as_u64().unwrap_or(0));
        }

        match &self.pcr_ids {
            None => Ok(()),
            Some(serde_json::Value::Array(_)) => Ok(()),
            _ => Err(anyhow!("Invalid type")),
        }
    }
}

#[derive(Debug)]
pub(super) enum ActionMode {
    Encrypt,
    Decrypt,
    Summary,
    Help,
}

pub(super) fn get_mode_and_cfg(args: &[String]) -> Result<(ActionMode, Option<TPM2Config>)> {
    if args.len() > 1 && args[1] == "--summary" {
        return Ok((ActionMode::Summary, None));
    }
    if args.len() > 1 && args[1] == "--help" {
        return Ok((ActionMode::Help, None));
    }
    if std::io::stdin().is_terminal() {
        return Ok((ActionMode::Help, None));
    }
    let (mode, cfgstr) = if args[0].contains("encrypt") && args.len() >= 2 {
        (ActionMode::Encrypt, Some(&args[1]))
    } else if args[0].contains("decrypt") {
        (ActionMode::Decrypt, None)
    } else if args.len() > 1 {
        if args[1] == "encrypt" && args.len() >= 3 {
            (ActionMode::Encrypt, Some(&args[2]))
        } else if args[1] == "decrypt" {
            (ActionMode::Decrypt, None)
        } else {
            bail!("No command specified");
        }
    } else {
        bail!("No command specified");
    };

    let cfg: Option<TPM2Config> = match cfgstr {
        None => None,
        Some(cfgstr) => Some(serde_json::from_str::<TPM2Config>(cfgstr)?.normalize()?),
    };

    Ok((mode, cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config_parsing() {
        let config_str = r#"{"pcr_ids": "7"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_field_name_rejected() {
        // Using "pcrs_ids" instead of "pcr_ids" should fail
        let config_str = r#"{"pcrs_ids": "7"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_multiple_invalid_fields_rejected() {
        let config_str = r#"{"invalid_field": "value", "another_invalid": "value2"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_complex_config() {
        let config_str = r#"{"pcr_ids": [7, 11], "pcr_bank": "sha256", "hash": "sha256"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pcr_digest_with_policy_rejected() {
        let config_str = r#"{"pcr_ids": [23], "pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "use_policy": true}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("pcr_digest cannot be combined"));
    }

    #[test]
    fn test_pcr_digest_empty_rejected() {
        let config_str = r#"{"pcr_ids": [23], "pcr_digest": ""}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not be empty"));
    }

    #[test]
    fn test_pcr_digest_invalid_base64_rejected() {
        let config_str = r#"{"pcr_ids": [23], "pcr_digest": "not!valid!base64"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid pcr_digest"));
    }

    #[test]
    fn test_pcr_digest_wrong_length_rejected() {
        // 27 A's = 20 bytes (SHA-1 size), but pcr_bank defaults to sha256 (32 bytes)
        let config_str = r#"{"pcr_ids": [23], "pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not match expected"));
    }

    #[test]
    fn test_pcr_digest_correct_length_accepted() {
        // 43 A's = 32 bytes, matching 1 PCR with default sha256 bank
        let config_str =
            r#"{"pcr_ids": [23], "pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_pcr_digest_unsupported_bank_rejected() {
        let config_str =
            r#"{"pcr_ids": [23], "pcr_bank": "md5", "pcr_digest": "AAAAAAAAAAAAAAAA"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported"));
    }

    #[test]
    fn test_unsupported_hash_rejected() {
        let config_str = r#"{"hash": "md5"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported"));
    }

    #[test]
    fn test_pcr_id_out_of_range_rejected() {
        let config_str = r#"{"pcr_ids": [24]}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("out of valid range"));
    }

    #[test]
    fn test_pcr_id_large_value_rejected() {
        let config_str = r#"{"pcr_ids": [4294967296]}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("out of valid range"));
    }

    #[test]
    fn test_pcr_digest_without_pcr_ids_rejected() {
        let config_str = r#"{"pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("pcr_digest requires pcr_ids"));
    }

    #[test]
    fn test_non_sha256_hash_with_pcr_ids_rejected() {
        let config_str = r#"{"hash": "sha384", "pcr_ids": [7]}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-SHA-256 hash"));
    }

    #[test]
    fn test_non_sha256_hash_with_pcr_digest_rejected() {
        let config_str =
            r#"{"hash": "sha384", "pcr_ids": [7], "pcr_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-SHA-256 hash"));
    }

    #[test]
    fn test_non_sha256_hash_without_pcr_ids_accepted() {
        let config_str = r#"{"hash": "sha384"}"#;
        let result = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_pcr_ids_sorted_after_normalize() {
        let config_str = r#"{"pcr_ids": [23, 7, 0]}"#;
        let cfg = serde_json::from_str::<TPM2Config>(config_str)
            .unwrap()
            .normalize()
            .unwrap();
        let ids = cfg.get_pcr_ids().unwrap().unwrap();
        assert_eq!(ids, vec![0, 7, 23]);
    }
}
