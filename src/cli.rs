// SPDX-FileCopyrightText: 2021 Red Hat, Inc.
//
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;

use anyhow::{anyhow, bail, Error, Result};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use tpm2_policy::TPMPolicyStep;

use crate::utils::get_authorized_policy_step;

#[derive(Serialize, Deserialize, std::fmt::Debug)]
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
        if cfg.pcr_ids.is_some() && cfg.policy_pubkey_path.is_some() {
            Ok(TPMPolicyStep::Or([
                Box::new(TPMPolicyStep::PCRs(
                    cfg.get_pcr_hash_alg(),
                    cfg.get_pcr_ids().unwrap(),
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(get_authorized_policy_step(
                    cfg.policy_pubkey_path.as_ref().unwrap(),
                    &None,
                    &cfg.policy_ref,
                )?),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
            ]))
        } else if cfg.pcr_ids.is_some() {
            Ok(TPMPolicyStep::PCRs(
                cfg.get_pcr_hash_alg(),
                cfg.get_pcr_ids().unwrap(),
                Box::new(TPMPolicyStep::NoStep),
            ))
        } else if cfg.policy_pubkey_path.is_some() {
            get_authorized_policy_step(
                cfg.policy_pubkey_path.as_ref().unwrap(),
                &None,
                &cfg.policy_ref,
            )
        } else {
            Ok(TPMPolicyStep::NoStep)
        }
    }
}

pub(crate) const DEFAULT_POLICY_PATH: &str = "/boot/clevis_policy.json";
pub(crate) const DEFAULT_PUBKEY_PATH: &str = "/boot/clevis_pubkey.json";
pub(crate) const DEFAULT_POLICY_REF: &str = "";

impl TPM2Config {
    pub(super) fn get_pcr_hash_alg(
        &self,
    ) -> tss_esapi::interface_types::algorithm::HashingAlgorithm {
        crate::utils::get_hash_alg_from_name(self.pcr_bank.as_ref())
    }

    pub(super) fn get_name_hash_alg(
        &self,
    ) -> tss_esapi::interface_types::algorithm::HashingAlgorithm {
        crate::utils::get_hash_alg_from_name(self.hash.as_ref())
    }

    pub(super) fn get_pcr_ids(&self) -> Option<Vec<u64>> {
        match &self.pcr_ids {
            None => None,
            Some(serde_json::Value::Array(vals)) => {
                Some(vals.iter().map(|x| x.as_u64().unwrap()).collect())
            }
            _ => panic!("Unexpected type found for pcr_ids"),
        }
    }

    pub(super) fn get_pcr_ids_str(&self) -> Option<String> {
        match &self.pcr_ids {
            None => None,
            Some(serde_json::Value::Array(vals)) => Some(
                vals.iter()
                    .map(|x| x.as_u64().unwrap().to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            ),
            _ => panic!("Unexpected type found for pcr_ids"),
        }
    }

    fn normalize(mut self) -> Result<TPM2Config> {
        self.normalize_pcr_ids()?;
        if self.pcr_ids.is_some() && self.pcr_bank.is_none() {
            self.pcr_bank = Some("sha256".to_string());
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
                        Ok(new)
                    }
                    _ => Err(anyhow!("Invalid value in pcr_ids")),
                })
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newvals?));
        }

        match &self.pcr_ids {
            None => Ok(()),
            // The normalization above would've caught any non-ints
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
