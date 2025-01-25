//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_yang::{ToYang, TryFromYang};
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum CryptoAlgo {
    Md5,
    Sha1,
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

// Cryptographic Protocol ID.
//
// Unique protocol-specific values for cryptographic applications, including but
// not limited to prevention of cross-protocol replay attacks.
//
// IANA registry:
// https://www.iana.org/assignments/authentication-cryptographic-protocol-id/authentication-cryptographic-protocol-id.xhtml
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum CryptoProtocolId {
    Ospfv3 = 0x01,
    Ldp = 0x02,
    Ospfv2 = 0x03,
}

// ===== impl CryptoAlgo =====

impl CryptoAlgo {
    pub fn digest_size(&self) -> u8 {
        match self {
            CryptoAlgo::Md5 => 16,
            CryptoAlgo::Sha1 => 20,
            CryptoAlgo::HmacMd5 => 16,
            CryptoAlgo::HmacSha1 => 20,
            CryptoAlgo::HmacSha256 => 32,
            CryptoAlgo::HmacSha384 => 48,
            CryptoAlgo::HmacSha512 => 64,
        }
    }
}

impl ToYang for CryptoAlgo {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            CryptoAlgo::Md5 => "ietf-key-chain:md5".into(),
            CryptoAlgo::Sha1 => "ietf-key-chain:sha-1".into(),
            CryptoAlgo::HmacMd5 => "holo-key-chain:hmac-md5".into(),
            CryptoAlgo::HmacSha1 => "ietf-key-chain:hmac-sha-1".into(),
            CryptoAlgo::HmacSha256 => "ietf-key-chain:hmac-sha-256".into(),
            CryptoAlgo::HmacSha384 => "ietf-key-chain:hmac-sha-384".into(),
            CryptoAlgo::HmacSha512 => "ietf-key-chain:hmac-sha-512".into(),
        }
    }
}

impl TryFromYang for CryptoAlgo {
    fn try_from_yang(identity: &str) -> Option<CryptoAlgo> {
        match identity {
            "ietf-key-chain:md5" => Some(CryptoAlgo::Md5),
            "ietf-key-chain:sha-1" => Some(CryptoAlgo::Sha1),
            "holo-key-chain:hmac-md5" => Some(CryptoAlgo::HmacMd5),
            "ietf-key-chain:hmac-sha-1" => Some(CryptoAlgo::HmacSha1),
            "ietf-key-chain:hmac-sha-256" => Some(CryptoAlgo::HmacSha256),
            "ietf-key-chain:hmac-sha-384" => Some(CryptoAlgo::HmacSha384),
            "ietf-key-chain:hmac-sha-512" => Some(CryptoAlgo::HmacSha512),
            _ => None,
        }
    }
}
