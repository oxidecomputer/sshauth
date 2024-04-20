/*
 * Copyright 2024 Oxide Computer Company
 */

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{Fingerprint, Signature};

/**
 * This structure is used to assemble the blob of bytes that we use to produce
 * the signature that is included in the token.  To reduce the size of the
 * token, we want to omit any fields that we can correctly construct on the
 * receiving side.  In particular, the action list is not transmitted in the
 * actual token, as it should refer to values that are sent in the actual
 * request, using a pattern established at the level of the consuming system.
 *
 * Because of this design, the size of the blob is not especially relevant;
 * first, because it is not transmitted, as described above; second, because the
 * blob is turned into a fixed length digest prior to passing it to the SSH
 * agent, which may itself be remote from the system that is generating the
 * token.
 *
 * NOTE: The format of this blob is committed, as both sides need to agree on
 * its shape for signature construction to work!
 */
#[derive(Serialize, PartialEq, Eq, Debug, Clone)]
pub(crate) struct TokenSigningBlobV1 {
    pub(crate) transmitted: TokenV1,

    /**
     * The action list describes the act that this token is intended to
     * authenticate.  In order to reduce the scope of replay attacks, the action
     * should be as specific as is practical for your application; e.g., for a
     * REST API it could include various request headers, the HTTP method, URL,
     * server hostname, and query parameters.  In the limit, including a
     * previously negotiated nonce in the action would be ideal where your
     * protocol allows it.
     */
    pub(crate) action: Vec<TokenAction>,
}

impl TokenSigningBlobV1 {
    /**
     * Produce the raw bytes for this signing blob.  The blob is assembled using
     * postcard, to be fed into a SHA-256 digest.  The input value to the digest
     * has a static prefix and suffix (partially controlled by the consuming
     * system) to reduce the likelihood of cross-protocol attacks.  The output
     * SHA-256 hash value is then itself wrapped in the same prefix and suffix,
     * ready to be fed to the SSH agent for signing.
     *
     *       Digest Input:
     *     / +----------+
     *     | | oxauth   | (magic super prefix; 6 bytes)
     *     | +----------+
     *     | | byo.e.m. | (magic per-system prefix; 8 bytes)
     *    -+ +----------+
     *   / | | <blob>   | (postcard-encoded TokenSigningBlobV1; variable len.)
     *   | | +----------+
     *   | | | htuaxo   | (magic super suffix; 6 bytes)
     *   | \ +----------+
     *   |
     *   |                             Packed Output
     *   |                             for Signing:
     *   |                             +----------+
     *   |                             | oxauth   |
     *   |                             +----------+
     *   |                             | byo.e.m. |
     *   |                             +----------+
     *   \_-- SHA-256 Digest --------> | digest   |
     *                                 +----------+
     *                                 | htuaxo   |
     *                                 +----------+
     */
    pub(crate) fn pack(&self, magic_prefix: [u8; 8]) -> Vec<u8> {
        /*
         * Take the SHA-256 hash of the blob data to sign, with a static prefix
         * and suffix common to all consuming systems, and a system-specific
         * magic prefix provided when signing tokens.
         */
        let mut digest = Sha256::new();
        digest.update(crate::MAGIC_SUPER_PREFIX);
        digest.update(magic_prefix);
        postcard::to_io(self, &mut digest).unwrap();
        digest.update(crate::MAGIC_SUPER_SUFFIX);

        /*
         * Attach the prefix and suffix again to the data to be signed before it
         * gets handed to the agent, to further reduce the likelihood of attacks
         * of cross-protocol confusion.
         */
        let res = digest.finalize();
        let mut out = Vec::with_capacity(
            crate::MAGIC_SUPER_PREFIX.len()
                + magic_prefix.len()
                + res.len()
                + crate::MAGIC_SUPER_SUFFIX.len(),
        );
        out.extend(crate::MAGIC_SUPER_PREFIX);
        out.extend(magic_prefix);
        out.extend(res);
        out.extend(crate::MAGIC_SUPER_SUFFIX);

        out
    }

    /**
     * Combine the transmitted portion of this token with a signature of the
     * bytes produced by pack() into the final token, which can then be encoded
     * and sent to the remote system.
     */
    pub(crate) fn into_token(&self, signature: TokenSignature) -> Token {
        Token::V1 { signed: self.transmitted.clone(), signature }
    }
}

/**
 * The Token type tree is laid out for use with postcard in two capacities: the
 * "signed" member represents the transmitted subset of the overall signing blob
 * (see TokenSigningBlobV1), and the overall structure includes the generated
 * signature and is encoded by the system and sent to the server for decoding
 * and verification.
 *
 * The final token is constructed by postcard-encoding this structure, and then
 * those bytes are further base64-encoded so that they can be included in HTTP
 * headers or username/password fields, which generally accept limited strings.
 *
 * NOTE: Only backwards-compatible changes can be made to this tree of types!
 * If you need to add another enum variant, it must be appended to the variant
 * list.  Existing variants must not be removed.  Members may not be added to
 * structs!  If you need a new struct member, a new variant must be added
 * somewhere in the type tree.  See the postcard documentation on backwards
 * compatibility for more exhaustive advice.
 */
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum Token {
    V1 {
        /**
         * This is the transmitted portion of the signed values making up the
         * token.  Values in this region can be trusted only after the signature
         * is verified.  Some of the information in this region (e.g., the
         * identity or the fingerprint) may need to be used in locating the
         * public key for verification of the signature; care must be taken not
         * to use those values for anything else until the signature is
         * confirmed!
         */
        signed: TokenV1,

        /**
         * The signature of the "signed" portion of the token.
         */
        signature: TokenSignature,
    },
}

impl Token {
    /**
     * Produce the base64-encoded representation of the token that should be
     * included in the system protocol; e.g., in the HTTP "Authorization"
     * header.
     */
    pub fn encode(&self) -> String {
        base64::encode_config(self.encode_raw(), base64::URL_SAFE_NO_PAD)
    }

    /**
     * Raw byte encoding of the token.  Not public; we expect consumers to use
     * the base64 encoded string.
     */
    fn encode_raw(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap()
    }

    /**
     * Decode the base64 encoded token bytes, producing a Token object.
     *
     * NOTE: This object has not been verified in any way and cannot be trusted!
     * This routine exists for use in UnverifiedToken, which is what we expect
     * consumers to use.
     */
    pub(crate) fn decode(token: &[u8]) -> Option<Self> {
        let t: Token = postcard::from_bytes(
            base64::decode_config(token, base64::URL_SAFE_NO_PAD)
                .ok()?
                .as_slice(),
        )
        .ok()?;

        /*
         * Validate any structural constraint that we are able to do quickly and
         * without depending on the wall time.
         */
        match &t {
            Token::V1 { signed, .. } => match &signed.identity {
                Some(TokenIdentity::FileName(name)) => {
                    if !crate::valid_identity(name.as_str()) {
                        return None;
                    }
                }
                None => (),
            },
        }

        Some(t)
    }

    pub fn identity_filename(&self) -> Option<&str> {
        match self {
            Token::V1 { signed, .. } => match signed.identity.as_ref() {
                Some(TokenIdentity::FileName(name)) => Some(name.as_str()),
                None => None,
            },
        }
    }

    pub fn identity(&self) -> Option<&TokenIdentity> {
        match self {
            Token::V1 { signed, .. } => signed.identity.as_ref(),
        }
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        match self {
            Token::V1 { signed, .. } => signed.fingerprint(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TokenV1 {
    /**
     * A description of the principal that this token identifies.  Generally
     * this is expected to be a username or some other system-specific unique
     * identifier.
     */
    pub(crate) identity: Option<TokenIdentity>,

    /**
     * A fingerprint of the SSH key used to sign this request, if one is
     * provided.  If not provided, the system is expected to attempt to choose
     * an SSH key based on some other means (e.g., inspecting the provided
     * identity) or to reject the request if unwilling to do so.
     */
    pub(crate) fingerprint: Option<TokenFingerprint>,

    /**
     * The UNIX timestamp in seconds at which this token was created.  This
     * timestamp is generally used to limit the window in which a token is
     * valid, to reduce the scope of replay attacks.
     */
    pub(crate) timestamp: u64,
}

impl TokenV1 {
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprint.as_ref().map(|tfp| match tfp {
            TokenFingerprint::Sha256(bytes) => {
                ssh_key::Fingerprint::Sha256(*bytes)
            }
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TokenAction {
    pub key: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
pub enum TokenFingerprint {
    /**
     * The SHA-256 fingerprint of the SSH key.
     */
    Sha256([u8; 32]),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TokenSignature {
    algorithm: TokenSignatureAlgorithm,

    /**
     * The OpenSSH encoding of the raw bytes of the signature.
     */
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
pub enum TokenSignatureAlgorithm {
    Ecdsa256,
    Ed25519,
}

impl TryFrom<Signature> for TokenSignature {
    type Error = anyhow::Error;

    fn try_from(s: Signature) -> Result<Self> {
        match s.algorithm() {
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            } => Ok(TokenSignature {
                algorithm: TokenSignatureAlgorithm::Ecdsa256,
                data: s.as_bytes().to_vec(),
            }),
            ssh_key::Algorithm::Ed25519 => Ok(TokenSignature {
                algorithm: TokenSignatureAlgorithm::Ed25519,
                data: s.as_bytes().to_vec(),
            }),
            _ => bail!("unsupported signature algorithm"),
        }
    }
}

impl TryFrom<&TokenSignature> for Signature {
    type Error = anyhow::Error;

    fn try_from(ts: &TokenSignature) -> Result<Self> {
        Ok(match ts.algorithm {
            TokenSignatureAlgorithm::Ecdsa256 => Signature::new(
                ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256,
                },
                ts.data.clone(),
            )?,
            TokenSignatureAlgorithm::Ed25519 => {
                Signature::new(ssh_key::Algorithm::Ed25519, ts.data.clone())?
            }
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum TokenIdentity {
    /**
     * A constrained string that is definitely safe to use as a file name on
     * modern operating systems.
     *
     * May only contain the following characters:
     *
     *   - 'A' through 'Z' (upper case alphabetic)
     *   - 'a' through 'z' (lower case alphabetic)
     *   - '0' through '9' (numeric)
     *   - '-' (hyphen)
     *   - '_' (underscore)
     *
     * This string must be at least two characters long.
     */
    FileName(String),
}

#[cfg(test)]
mod test {
    use super::*;

    fn dump(v: &[u8]) {
        println!();
        let mut s = String::from("        ");
        while s.len() < 76 {
            s.push('-');
        }
        print!("{s}");

        let mut hex = String::new();
        let mut chr = String::new();
        for (i, b) in v.into_iter().enumerate() {
            if i % 16 == 0 {
                if i > 0 {
                    println!("{hex} | {chr} |");
                    hex.clear();
                    chr.clear();
                } else {
                    println!();
                }
                print!("  {i:<04x} |");
            }

            hex += &format!(" {b:<02x}");
            if b.is_ascii_graphic() {
                chr += &format!("{}", *b as char);
            } else {
                chr += "᛫";
            }
        }

        if !hex.is_empty() {
            while hex.len() < 16 * 3 {
                hex.push_str("   ");
                chr.push(' ');
            }
            println!("{hex} | {chr} |");
        }

        println!("        [{} bytes total]", v.len());
        println!();

        print!("let bytes = [");
        for b in v {
            print!("0x{b:02x},");
        }
        println!("];");
    }

    struct Sample {
        name: &'static str,
        o: TokenSigningBlobV1,
        blob: Vec<u8>,
        token: &'static str,
    }

    fn make_samples() -> Vec<Sample> {
        let mut out = Vec::new();
        out.push(Sample {
            name: "sample ovpnms token (must be short)",
            o: TokenSigningBlobV1 {
                transmitted: TokenV1 {
                    identity: None,
                    fingerprint: None,
                    timestamp: 1830297600,
                },
                action: vec![
                    TokenAction {
                        key: "app".to_string(),
                        value: "openvpn".to_string(),
                    },
                    /*
                     * In this use case we are trying to produce a token that
                     * fits in under 128 bytes, because that's how long an
                     * OpenVPN password can be.  The username is in a separate
                     * field, which we include in the action list for
                     * verification without increasing the size of the token
                     * itself.
                     */
                    TokenAction {
                        key: "username".to_string(),
                        value: "waldorf".to_string(),
                    },
                ],
            },
            blob: vec![
                0x6f, 0x78, 0x61, 0x75, 0x74, 0x68, 0x62, 0x79, 0x6f, 0x2e,
                0x65, 0x2e, 0x6d, 0x2e, 0x60, 0x04, 0xc3, 0xa6, 0xc9, 0x9d,
                0x86, 0xa7, 0xf8, 0xda, 0x76, 0xb9, 0xec, 0x98, 0x6c, 0xbc,
                0xd5, 0x10, 0xb7, 0x7e, 0xa9, 0x07, 0x82, 0x53, 0xcc, 0x77,
                0x88, 0xa4, 0x45, 0x55, 0x0d, 0xd2, 0x68, 0x74, 0x75, 0x61,
                0x78, 0x6f,
            ],
            token: "AAAAgMDg6AYASQAAAACgNWsplpL5b-ywIeYnt_SM91SS-lM-t_9tTqOcH\
                tHe-gAAAABy3rR99CgKGT3Qtmd3RORctkc3Wc1fgpPAzQPYHln3tP8",
        });
        out.push(Sample {
            name: "sample token with identity",
            o: TokenSigningBlobV1 {
                transmitted: TokenV1 {
                    identity: Some(TokenIdentity::FileName(
                        "about-twelve".into(),
                    )),
                    fingerprint: None,
                    timestamp: 1830297600,
                },
                action: vec![
                    TokenAction {
                        key: "app".to_string(),
                        value: "doorbell".to_string(),
                    },
                    TokenAction {
                        key: "door".to_string(),
                        value: "rear".to_string(),
                    },
                ],
            },
            blob: vec![
                0x6f, 0x78, 0x61, 0x75, 0x74, 0x68, 0x62, 0x79, 0x6f, 0x2e,
                0x65, 0x2e, 0x6d, 0x2e, 0xa2, 0xe4, 0xee, 0x87, 0xb1, 0xc6,
                0xb1, 0x96, 0xbf, 0x18, 0x4b, 0x65, 0xbd, 0x8a, 0xd4, 0x08,
                0x55, 0x09, 0x3c, 0xa4, 0xca, 0xbe, 0x59, 0x15, 0x81, 0xdb,
                0x50, 0xac, 0x62, 0x73, 0x2e, 0x72, 0x68, 0x74, 0x75, 0x61,
                0x78, 0x6f,
            ],
            token: "AAEADGFib3V0LXR3ZWx2ZQCAwODoBgBJAAAAAKA1aymWkvlv7LAh5ie3\
                9Iz3VJL6Uz63_21Oo5we0d76AAAAAHLetH30KAoZPdC2Z3dE5Fy2RzdZzV-C\
                k8DNA9geWfe0_w",
        });
        out.push(Sample {
            name: "REST endpoint login",
            o: TokenSigningBlobV1 {
                transmitted: TokenV1 {
                    identity: None,
                    fingerprint: Some(TokenFingerprint::Sha256([
                        0x67, 0xfb, 0x0e, 0xbf, 0x07, 0x68, 0x21, 0x59, 0xf8,
                        0x17, 0x87, 0xe0, 0x94, 0x5a, 0x75, 0x40, 0x70, 0x6c,
                        0xdb, 0x89, 0x54, 0x87, 0x21, 0xf7, 0xd1, 0x98, 0xfb,
                        0x97, 0x8e, 0x7e, 0x7b, 0xac,
                    ])),
                    timestamp: 1707855530,
                },
                action: vec![
                    TokenAction {
                        key: "method".to_string(),
                        value: "PUT".to_string(),
                    },
                    TokenAction {
                        key: "url".to_string(),
                        value: "/log/me/in".to_string(),
                    },
                ],
            },
            blob: vec![
                0x6f, 0x78, 0x61, 0x75, 0x74, 0x68, 0x62, 0x79, 0x6f, 0x2e,
                0x65, 0x2e, 0x6d, 0x2e, 0x12, 0x89, 0xef, 0x33, 0x58, 0xca,
                0xea, 0xb7, 0x50, 0x29, 0x3f, 0xb0, 0xfb, 0x04, 0xac, 0xe6,
                0xe8, 0xfc, 0x40, 0xb6, 0x65, 0x51, 0xda, 0x91, 0xa5, 0x99,
                0xd7, 0xd6, 0x05, 0x8f, 0x30, 0x5b, 0x68, 0x74, 0x75, 0x61,
                0x78, 0x6f,
            ],
            token: "AAABAGf7Dr8HaCFZ-BeH4JRadUBwbNuJVIch99GY-5eOfnusqp2vrgY\
                ASQAAAACgNWsplpL5b-ywIeYnt_SM91SS-lM-t_9tTqOcHtHe-gAAAABy3r\
                R99CgKGT3Qtmd3RORctkc3Wc1fgpPAzQPYHln3tP8",
        });
        out.push(Sample {
            name: "REST endpoint login (identity _and_ key, more headers)",
            o: TokenSigningBlobV1 {
                transmitted: TokenV1 {
                    identity: Some(TokenIdentity::FileName(
                        "mrstephens".into(),
                    )),
                    fingerprint: Some(TokenFingerprint::Sha256([
                        0x67, 0xfb, 0x0e, 0xbf, 0x07, 0x68, 0x21, 0x59, 0xf8,
                        0x17, 0x87, 0xe0, 0x94, 0x5a, 0x75, 0x40, 0x70, 0x6c,
                        0xdb, 0x89, 0x54, 0x87, 0x21, 0xf7, 0xd1, 0x98, 0xfb,
                        0x97, 0x8e, 0x7e, 0x7b, 0xac,
                    ])),
                    timestamp: 1707855530,
                },
                action: vec![
                    TokenAction {
                        key: "method".to_string(),
                        value: "PUT".to_string(),
                    },
                    TokenAction {
                        key: "url".to_string(),
                        value: "/log/me/in".to_string(),
                    },
                    TokenAction {
                        key: "content-md5".to_string(),
                        value: "/Gx4aOgplRXMRI2qXXqXiQ==".to_string(),
                    },
                    TokenAction {
                        key: "lines".to_string(),
                        value: "blah\nblah\nblah!".to_string(),
                    },
                    TokenAction {
                        key: "synonym".to_string(),
                        value: "once".to_string(),
                    },
                    TokenAction {
                        key: "synonym".to_string(),
                        value: "twice".to_string(),
                    },
                    TokenAction {
                        key: "synonym".to_string(),
                        value: "thrice".to_string(),
                    },
                ],
            },
            blob: vec![
                0x6f, 0x78, 0x61, 0x75, 0x74, 0x68, 0x62, 0x79, 0x6f, 0x2e,
                0x65, 0x2e, 0x6d, 0x2e, 0x9a, 0x6d, 0xcf, 0xdb, 0x6a, 0xa8,
                0xfa, 0x70, 0x06, 0x73, 0x21, 0x1a, 0xfb, 0xa9, 0x8f, 0x44,
                0xa0, 0xe1, 0x6d, 0xbb, 0x34, 0x9c, 0x19, 0xe4, 0x09, 0x99,
                0x9b, 0xc3, 0x5a, 0x03, 0xa5, 0x74, 0x68, 0x74, 0x75, 0x61,
                0x78, 0x6f,
            ],
            token: "AAEACm1yc3RlcGhlbnMBAGf7Dr8HaCFZ-BeH4JRadUBwbNuJVIch99G\
                Y-5eOfnusqp2vrgYASQAAAACgNWsplpL5b-ywIeYnt_SM91SS-lM-t_9tTq\
                OcHtHe-gAAAABy3rR99CgKGT3Qtmd3RORctkc3Wc1fgpPAzQPYHln3tP8",
        });
        out
    }

    fn make_signature() -> TokenSignature {
        TokenSignature {
            algorithm: TokenSignatureAlgorithm::Ecdsa256,
            /*
             * Random (but constant) bytes used for signature here, to make
             * for easy tests against preserved encoded bytes from previous
             * software versions.
             */
            data: vec![
                0x00, 0x00, 0x00, 0x00, 0xa0, 0x35, 0x6b, 0x29, 0x96, 0x92,
                0xf9, 0x6f, 0xec, 0xb0, 0x21, 0xe6, 0x27, 0xb7, 0xf4, 0x8c,
                0xf7, 0x54, 0x92, 0xfa, 0x53, 0x3e, 0xb7, 0xff, 0x6d, 0x4e,
                0xa3, 0x9c, 0x1e, 0xd1, 0xde, 0xfa, 0x00, 0x00, 0x00, 0x00,
                0x72, 0xde, 0xb4, 0x7d, 0xf4, 0x28, 0x0a, 0x19, 0x3d, 0xd0,
                0xb6, 0x67, 0x77, 0x44, 0xe4, 0x5c, 0xb6, 0x47, 0x37, 0x59,
                0xcd, 0x5f, 0x82, 0x93, 0xc0, 0xcd, 0x03, 0xd8, 0x1e, 0x59,
                0xf7, 0xb4, 0xff,
            ],
        }
    }

    #[test]
    fn encode() {
        for (i, s) in make_samples().into_iter().enumerate() {
            println!();
            println!("----- SAMPLE {i}: {} ------", s.name);
            println!();

            println!("{:?}", s.o);
            println!();

            println!("signing blob:");
            let blob = s.o.pack(crate::MAGIC_PREFIX_DEFAULT);
            dump(&blob);
            println!();

            let t = s.o.into_token(make_signature());

            println!("raw token:");
            let enc = t.encode_raw();
            dump(&enc);
            println!();

            println!("base64 token:");
            let b = t.encode();
            println!("    b = {b}\n    len = {}", b.len());

            if i == 0 {
                assert!(b.len() < 127);
            }

            println!();
        }
    }

    #[test]
    fn round_trip() {
        for (i, s) in make_samples().into_iter().enumerate() {
            let t = s.o.into_token(make_signature());

            let enc = t.encode_raw();
            let dec: Token = postcard::from_bytes(&enc)
                .expect(&format!("decoded {i} {:?}", s.name));

            assert_eq!(t, dec, "roundtrip mismatch on {i} {:?}", s.name);
        }
    }

    #[test]
    fn old_encoding() {
        for (i, s) in make_samples().into_iter().enumerate() {
            /*
             * Confirm that the signing blob still looks the same as it
             * used to look in prior software versions:
             */
            assert_eq!(
                s.o.pack(crate::MAGIC_PREFIX_DEFAULT),
                s.blob,
                "checking signing blob {i} {:?}",
                s.name
            );

            /*
             * Confirm that the encoded token still works as expected:
             */
            let old = Token::decode(s.token.as_bytes())
                .expect(&format!("decode old base64 {i} {:?}", s.name));
            let t = s.o.into_token(make_signature());

            assert_eq!(old, t, "checking token {i} {:?}", s.name);
        }
    }
}
