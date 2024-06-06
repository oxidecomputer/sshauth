/*
 * Copyright 2024 Oxide Computer Company
 */

use std::borrow::Borrow;

use anyhow::{bail, Result};
use ecdsa::signature::Verifier;
use ssh_key::{Fingerprint, PublicKey, Signature};

use crate::token::{
    Token, TokenAction, TokenIdentity, TokenSignature, TokenSigningBlobV1,
};
use crate::{now_secs, VerifiedToken};

/**
 * A token that has been decoded correctly, but neither the timestamp nor the
 * signature has been verified.  It is critical for security that we not allow
 * consumers to accidentally trust the unverified contents.
 */
#[derive(Debug)]
pub struct UnverifiedToken(Token);

impl TryFrom<&str> for UnverifiedToken {
    type Error = anyhow::Error;

    fn try_from(token: &str) -> Result<Self> {
        match Token::decode(token.as_bytes()) {
            Some(t) => Ok(UnverifiedToken(t)),
            None => bail!("invalid token"),
        }
    }
}

impl UnverifiedToken {
    /**
     * Begin verifying the signature on this token.  A builder is returned that
     * should be used to furnish the same action list that was provided by the
     * client when they generated the signature.  In order for the signature to
     * be verified correctly, action list entries must be provided in the exact
     * same order, with the same key and value strings.  Action list entries
     * with duplicate keys are allowed.
     */
    #[must_use]
    pub fn verify_for(&self) -> UnverifiedTokenVerification {
        match &self.0 {
            Token::V1 { signed, signature } => UnverifiedTokenVerification {
                blob: TokenSigningBlobV1 {
                    transmitted: signed.clone(),
                    action: Default::default(),
                },
                signature: signature.clone(),
                /*
                 * By default, we allow the client and server clock to be out of
                 * sync by up to a minute in either direction.
                 */
                max_skew_seconds: 60,
                magic_prefix: crate::MAGIC_PREFIX_DEFAULT,
            },
        }
    }

    /**
     * Return the fingerprint of the SSH key that was used to sign this token,
     * if it was provided.
     *
     * NOTE: This fingerprint has NOT been validated!  It may be used to locate
     * keys for signature verification purposes, but CANNOT be used for
     * authentication.
     */
    pub fn untrusted_fingerprint(&self) -> Option<Fingerprint> {
        self.0.fingerprint()
    }

    /**
     * Return the identity file name of the principal for whom this request was
     * signed, if it was provided.
     *
     * NOTE: This identity has NOT been validated!  It may be used to locate
     * keys for signature verification purposes, but CANNOT be used for
     * authentication.
     */
    pub fn untrusted_identity_filename(&self) -> Option<&str> {
        self.0.identity_filename()
    }

    pub fn untrusted_identity(&self) -> Option<&TokenIdentity> {
        self.0.identity()
    }
}

pub struct UnverifiedTokenVerification {
    blob: TokenSigningBlobV1,
    signature: TokenSignature,
    max_skew_seconds: u64,
    magic_prefix: [u8; 8],
}

impl UnverifiedTokenVerification {
    pub fn magic_prefix(&mut self, pfx: [u8; 8]) -> &mut Self {
        self.magic_prefix = pfx;
        self
    }

    pub fn max_skew_seconds(&mut self, seconds: u64) -> &mut Self {
        self.max_skew_seconds = seconds;
        self
    }

    pub fn action_clear(&mut self) {
        self.blob.action.clear();
    }

    pub fn action<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.blob.action.push(TokenAction {
            key: key.as_ref().to_string(),
            value: value.as_ref().to_string(),
        });
        self
    }

    pub fn actions<I, K, V>(&mut self, actions: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in actions.into_iter() {
            self.action(key, value);
        }
        self
    }

    pub fn action_opt<K, V>(&mut self, action: Option<(K, V)>) -> &mut Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        if let Some((key, value)) = action {
            self.action(key, value);
        }
        self
    }

    /**
     * Given a list of SSH public keys, attempt to verify the signature on this
     * token.  If at least one of the keys matches the signature, return the
     * now-trusted token so that the signed contents can be accessed and used
     * for authentication purposes.
     */
    pub fn with_keys<I, K>(&mut self, keys: I) -> Result<VerifiedToken>
    where
        I: IntoIterator<Item = K>,
        K: Borrow<PublicKey>,
    {
        /*
         * Encode the signing blob as raw bytes, using the same layout as the
         * client used, for verification:
         */
        let blob = self.blob.pack(self.magic_prefix);

        let sig = Signature::try_from(&self.signature)?;

        for key in keys.into_iter() {
            let key = key.borrow();

            if key.algorithm() != sig.algorithm() {
                /*
                 * Make sure we are not accidentally trying to use a key of the
                 * wrong type to verify this signature.
                 */
                continue;
            }

            let verified = match key.key_data() {
                ssh_key::public::KeyData::Ecdsa(
                    pk @ ssh_key::public::EcdsaPublicKey::NistP256(..),
                ) => pk.verify(&blob, &sig).is_ok(),
                ssh_key::public::KeyData::Ed25519(pk) => {
                    pk.verify(&blob, &sig).is_ok()
                }
                _ => bail!("unsupported key type"),
            };

            if !verified {
                /*
                 * Try the next key.
                 */
                continue;
            }

            let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256);
            if let Some(received_fp) = self.blob.transmitted.fingerprint() {
                /*
                 * Confirm that the fingerprint that was included in the request
                 * is the same as the fingerprint of the key that we used to
                 * validate the request.
                 */
                if fingerprint != received_fp {
                    bail!("fingerprint mismatch");
                }
            }

            /*
             * Confirm that the timestamp is within the window we are
             * prepared to accept.
             */
            let delta = now_secs().abs_diff(self.blob.transmitted.timestamp);
            if delta > self.max_skew_seconds {
                bail!("delta of {} seconds is too great", delta);
            }

            return Ok(VerifiedToken {
                fingerprint,
                identity: self.blob.transmitted.identity.clone(),
            });
        }

        bail!("signature could not be verified");
    }

    pub fn with_key<K>(&mut self, key: K) -> Result<VerifiedToken>
    where
        K: Borrow<PublicKey>,
    {
        self.with_keys([key])
    }
}
