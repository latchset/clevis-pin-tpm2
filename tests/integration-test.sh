#!/bin/sh
# SPDX-FileCopyrightText: 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: MIT

die() {
    echo "ERROR: ${1}" >&2
    exit 1
}

PLAINTEXT=foobar
jwe="$(echo "${PLAINTEXT}" | ./target/debug/clevis-pin-tpm2 encrypt {})"

dec="$(echo "$jwe" | ./target/debug/clevis-pin-tpm2 decrypt)" \
    || die "Unable to decrypt JWE passed with newline added"

[ "${dec}" = "${PLAINTEXT}" ] \
    || die "Decrypted JWE (${dec}) does not match PLAINTEXT (${PLAINTEXT})"
