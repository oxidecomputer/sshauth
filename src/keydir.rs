/*
 * Copyright 2024 Oxide Computer Company
 */

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use ssh_key::PublicKey;

use crate::token::TokenIdentity;

pub struct KeyDirectory {
    dir: PathBuf,
}

impl KeyDirectory {
    pub fn new<P>(dir: P) -> Result<KeyDirectory>
    where
        P: AsRef<Path>,
    {
        Ok(KeyDirectory { dir: dir.as_ref().to_path_buf() })
    }

    pub fn keys_for(&self, id: &TokenIdentity) -> Result<Vec<PublicKey>> {
        match id {
            TokenIdentity::FileName(name) => {
                let pc = PathBuf::from(name);
                if pc.components().collect::<Vec<_>>().len() != 1 {
                    bail!("odd path");
                }

                let file = self.dir.join(pc);

                let s = std::fs::read_to_string(&file)
                    .map_err(|e| anyhow!("reading {file:?}: {e:?}"))?;
                let keys = s
                    .lines()
                    .enumerate()
                    .filter_map(|(n, l)| {
                        let l = l.trim();
                        if l.is_empty() {
                            None
                        } else {
                            Some((n + 1, l))
                        }
                    })
                    .map(|(n, l)| {
                        /*
                         * PublicKey::from_openssh() only accepts a single
                         * space between fields, but OpenSSH accepts any run
                         * of spaces and tabs.
                         */
                        let l = l.split_whitespace().collect::<Vec<_>>();
                        let key = PublicKey::from_openssh(&l.join(" "))
                            .map_err(|e| {
                                anyhow!("line {n}: parsing key: {e}")
                            })?;
                        if !crate::is_supported_algorithm(&key.algorithm()) {
                            bail!(
                                "line {n}: unsupported key algorithm: {}",
                                key.algorithm()
                            );
                        }
                        Ok(key)
                    })
                    .collect::<Result<Vec<_>>>()
                    .map_err(|e| anyhow!("reading key file {file:?}: {}", e))?;
                if keys.is_empty() {
                    bail!("no keys in file {file:?}?");
                }

                if keys.is_empty() {
                    bail!("no keys in key file {file:?}");
                }

                Ok(keys)
            }
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn key_algorithms() {
        /*
         * keys_for() must only return keys that tokens can be verified with,
         * and the key type at the start of a line must match the key.  Load
         * an Ed25519 key, the same key with tabs and runs of spaces between
         * the fields, an RSA key, and an ECDSA key whose line names
         * ssh-ed25519.  Check that only the Ed25519 keys load.
         */
        let kd = KeyDirectory::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/keydir"
        ))
        .unwrap();
        let keys_for = |name: &str| {
            kd.keys_for(&TokenIdentity::FileName(name.into()))
                .map_err(|e| e.to_string())
        };

        let keys = keys_for("ed25519").unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].algorithm(), ssh_key::Algorithm::Ed25519);
        assert_eq!(keys[0].comment(), "sshauth-test-1");

        let keys = keys_for("whitespace").unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].algorithm(), ssh_key::Algorithm::Ed25519);
        assert_eq!(keys[0].comment(), "sshauth test");

        for (name, expected) in [
            ("rsa", "line 1: unsupported key algorithm: ssh-rsa"),
            ("mismatch", "line 1: parsing key: unknown algorithm"),
        ] {
            let err = keys_for(name).unwrap_err();
            assert!(err.contains(expected), "{name}: {err}");
        }
    }
}
