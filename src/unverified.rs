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
                require_user_presence: true,
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
    require_user_presence: bool,
}

impl UnverifiedTokenVerification {
    pub fn magic_prefix(&mut self, pfx: [u8; 8]) -> &mut Self {
        self.magic_prefix = pfx;
        self
    }

    /**
     * By default, a signature from a security key must attest that the
     * authenticator verified user presence; i.e., that someone touched the
     * key.  Verifiers that accept keys enrolled with no-touch-required, as
     * sshd can be configured to, may relax that requirement here.
     */
    pub fn require_user_presence(&mut self, req: bool) -> &mut Self {
        self.require_user_presence = req;
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
                ssh_key::public::KeyData::SkEd25519(pk) => {
                    if self.require_user_presence {
                        sk_user_presence(&sig)?;
                    }
                    pk.verify(&blob, &sig).is_ok()
                }
                ssh_key::public::KeyData::SkEcdsaSha2NistP256(pk) => {
                    if self.require_user_presence {
                        sk_user_presence(&sig)?;
                    }
                    pk.verify(&blob, &sig).is_ok()
                }
                _ => bail!("unsupported key type: {}", key.algorithm()),
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

/**
 * Security key signatures carry a trailer after the raw signature bytes:
 * flags (1 byte) and the authenticator's signature counter (4 bytes, big
 * endian).  Bit 0 of the flags is set only if the authenticator verified
 * user presence.  Refuse signatures made without a touch, as sshd does by
 * default for keys enrolled without the no-touch-required option.
 */
fn sk_user_presence(sig: &Signature) -> Result<()> {
    const SK_TRAILER_SIZE: usize = 5;
    const SK_FLAG_USER_PRESENCE: u8 = 0x01;

    let data = sig.as_bytes();
    let Some(i) = data.len().checked_sub(SK_TRAILER_SIZE) else {
        bail!("security key signature is missing its trailer");
    };
    if data[i] & SK_FLAG_USER_PRESENCE == 0 {
        bail!("security key signature was made without user presence");
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use ecdsa::signature::Signer;
    use sha2::{Digest, Sha256};
    use ssh_key::{Algorithm, PrivateKey};

    use crate::token::TokenV1;

    const APPLICATION: &str = "ssh:";

    /**
     * Emulate a security key authenticator in software.  An sk signature is
     * an ordinary signature over SHA256(application) || flags || counter ||
     * SHA256(message), with the flags and counter then appended to the raw
     * signature bytes so that the verifier can reconstruct the signed data.
     */
    fn sk_sign(flags: u8, counter: u32) -> Result<(PublicKey, String)> {
        let privkey = PrivateKey::from_openssh(include_str!(
            "../testdata/keys/ed25519/test-1"
        ))?;

        let sk = match privkey.public_key().key_data() {
            ssh_key::public::KeyData::Ed25519(pk) => {
                ssh_key::public::SkEd25519::new(*pk, APPLICATION)
            }
            _ => bail!("expected an ed25519 test key"),
        };
        let pubkey =
            PublicKey::new(ssh_key::public::KeyData::SkEd25519(sk), "sk-test");

        let blob = TokenSigningBlobV1 {
            transmitted: TokenV1 {
                identity: None,
                fingerprint: None,
                timestamp: now_secs(),
            },
            action: Default::default(),
        };
        let message = blob.pack(crate::MAGIC_PREFIX_DEFAULT);

        let mut signed_data = Vec::new();
        signed_data.extend(Sha256::digest(APPLICATION));
        signed_data.push(flags);
        signed_data.extend(counter.to_be_bytes());
        signed_data.extend(Sha256::digest(&message));

        let raw = privkey.key_data().try_sign(&signed_data)?;
        let mut data = raw.as_bytes().to_vec();
        data.push(flags);
        data.extend(counter.to_be_bytes());
        let sig = Signature::new(Algorithm::SkEd25519, data)?;

        Ok((pubkey, blob.into_token(sig.try_into()?).encode()))
    }

    #[test]
    fn sk_with_user_presence_verifies() -> Result<()> {
        let (pubkey, token) = sk_sign(0x01, 7)?;
        let verified = UnverifiedToken::try_from(token.as_str())?
            .verify_for()
            .with_key(&pubkey)?;
        assert_eq!(
            verified.fingerprint(),
            pubkey.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        );
        Ok(())
    }

    /**
     * Verify a token signed by a real security key through the SSH agent.
     * This requires enrolled hardware and a touch, so it is ignored by
     * default; run it with:
     *
     *   SSHAUTH_TEST_SK_KEY=<comment or SHA256 fingerprint> \
     *       cargo test -- --ignored sk_hardware
     */
    #[tokio::test]
    #[ignore = "requires an SSH agent with a security key, and a touch"]
    async fn sk_hardware_user_presence() -> Result<()> {
        let authsock = std::env::var("SSH_AUTH_SOCK")?;
        let want = match std::env::var("SSHAUTH_TEST_SK_KEY") {
            Ok(want) => want,
            _ => bail!(
                "set SSHAUTH_TEST_SK_KEY to a key comment or \
                SHA256 fingerprint"
            ),
        };

        let keys = crate::agent::list_keys(&authsock).await?;
        let key = match keys.iter().find(|k| {
            matches!(
                k.key_data(),
                ssh_key::public::KeyData::SkEd25519(..)
                    | ssh_key::public::KeyData::SkEcdsaSha2NistP256(..),
            ) && (k.comment() == want
                || k.fingerprint(ssh_key::HashAlg::Sha256).to_string() == want)
        }) {
            Some(key) => key,
            None => bail!("no security key matching {want:?} in the agent"),
        };

        let fp = key.fingerprint(ssh_key::HashAlg::Sha256);
        eprintln!("signing with {:?} ({fp}); touch the key...", key.comment());

        let signer = crate::TokenSigner::using_authsock(&authsock)?
            .key(key.clone())
            .require_identity(false)
            .build()?;
        let token = signer.sign_for().sign().await?;

        /*
         * Surface what the authenticator actually put in the flags byte,
         * before verification enforces it:
         */
        let Token::V1 { signature, .. } = &token;
        let sig = Signature::try_from(signature)?;
        let flags = sig.as_bytes()[sig.as_bytes().len() - 5];
        eprintln!("flags = {flags:#04x}");

        let verified = UnverifiedToken::try_from(token.encode().as_str())?
            .verify_for()
            .with_key(key)?;
        eprintln!("verified: {verified}");
        assert_eq!(verified.fingerprint(), fp.to_string());
        Ok(())
    }

    #[test]
    fn sk_without_user_presence_is_refused() -> Result<()> {
        for flags in [0x00, /* user verification alone: */ 0x04] {
            let (pubkey, token) = sk_sign(flags, 7)?;
            let err = UnverifiedToken::try_from(token.as_str())?
                .verify_for()
                .with_key(&pubkey)
                .unwrap_err();
            assert!(
                err.to_string().contains("user presence"),
                "unexpected error: {err}",
            );

            /*
             * The same signature must verify for a caller that has opted
             * out of the user presence requirement:
             */
            UnverifiedToken::try_from(token.as_str())?
                .verify_for()
                .require_user_presence(false)
                .with_key(&pubkey)?;
        }
        Ok(())
    }
}
