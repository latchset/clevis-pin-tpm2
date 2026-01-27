#!/bin/sh
# SPDX-FileCopyrightText: 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: MIT

die() {
    echo "ERROR: ${1}" >&2
    exit 1
}

# Default to debug, search for release
debug="./target/debug/clevis-pin-tpm2"
release="./target/release/clevis-pin-tpm2"
if [[ -f "${debug}" ]]; then
    bin="${debug}"
elif [[ -f "${release}" ]]; then
    bin="${release}"
else
    die "No binary found. Run cargo build first"
fi

PLAINTEXT=foobar
jwe="$(echo "${PLAINTEXT}" | "${bin}" encrypt {})"

dec="$(echo "$jwe" | "${bin}" decrypt)" \
    || die "Unable to decrypt JWE passed with newline added"

[ "${dec}" = "${PLAINTEXT}" ] \
    || die "Decrypted JWE (${dec}) does not match PLAINTEXT (${PLAINTEXT})"
