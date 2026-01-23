// SPDX-FileCopyrightText: 2021 Red Hat, Inc.
//
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;

use anyhow::{anyhow, bail, Context, Result};
use tss_esapi::{
    attributes::object::ObjectAttributesBuilder,
    constants::tss as tss_constants,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    },
    structures::{Digest, Public, SymmetricDefinitionObject},
};

#[cfg(target_pointer_width = "64")]
type Sizedu = u64;
#[cfg(target_pointer_width = "32")]
type Sizedu = u32;

pub(super) fn get_key_public(key_type: &str, name_alg: HashingAlgorithm) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()?;

    let builder = tss_esapi::structures::PublicBuilder::new()
        .with_object_attributes(object_attributes)
        .with_name_hashing_algorithm(name_alg);

    match key_type {
        "ecc" => builder
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_ecc_parameters(
                tss_esapi::structures::PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    EccCurve::NistP256,
                )
                .build()?,
            )
            .with_ecc_unique_identifier(Default::default()),
        "rsa" => builder
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_rsa_parameters(
                tss_esapi::structures::PublicRsaParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
                    tss_esapi::structures::RsaExponent::ZERO_EXPONENT,
                )
                .build()?,
            )
            .with_rsa_unique_identifier(Default::default()),
        _ => return Err(anyhow!("Unsupported key type used")),
    }
    .build()
    .context("Error building public key")
}

pub(super) fn create_tpm2b_public_sealed_object(
    policy: Option<Digest>,
) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC> {
    let mut object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(true);

    if policy.is_none() {
        object_attributes = object_attributes.with_user_with_auth(true);
    }
    let policy = match policy {
        Some(p) => p,
        None => Digest::try_from(vec![])?,
    };

    let mut params: tss_esapi::tss2_esys::TPMU_PUBLIC_PARMS = Default::default();
    params.keyedHashDetail.scheme.scheme = tss_constants::TPM2_ALG_NULL;

    Ok(tss_esapi::tss2_esys::TPM2B_PUBLIC {
        size: std::mem::size_of::<tss_esapi::tss2_esys::TPMT_PUBLIC>() as u16,
        publicArea: tss_esapi::tss2_esys::TPMT_PUBLIC {
            type_: tss_constants::TPM2_ALG_KEYEDHASH,
            nameAlg: tss_constants::TPM2_ALG_SHA256,
            objectAttributes: object_attributes.build()?.0,
            authPolicy: tss_esapi::tss2_esys::TPM2B_DIGEST::from(policy),
            parameters: params,
            unique: Default::default(),
        },
    })
}

pub(super) fn get_tpm2b_public(val: tss_esapi::tss2_esys::TPM2B_PUBLIC) -> Result<Vec<u8>> {
    let mut offset = 0 as Sizedu;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as Sizedu,
            &mut offset,
        );
        if res != 0 {
            bail!("Marshalling tpm2b_public failed");
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

pub(super) fn get_tpm2b_private(val: tss_esapi::tss2_esys::TPM2B_PRIVATE) -> Result<Vec<u8>> {
    let mut offset = 0 as Sizedu;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as Sizedu,
            &mut offset,
        );
        if res != 0 {
            bail!("Marshalling tpm2b_private failed");
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

pub(super) fn build_tpm2b_private(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PRIVATE> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PRIVATE::default();
    let mut offset = 0 as Sizedu;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
            val[..].as_ptr(),
            val.len() as Sizedu,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            bail!("Unmarshalling tpm2b_private failed");
        }
    }

    Ok(resp)
}

pub(super) fn build_tpm2b_public(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PUBLIC::default();
    let mut offset = 0 as Sizedu;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            val[..].as_ptr(),
            val.len() as Sizedu,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            bail!("Unmarshalling tpm2b_public failed");
        }
    }

    Ok(resp)
}
