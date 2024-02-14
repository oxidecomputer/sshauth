use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use ssh_key::{AuthorizedKeys, PublicKey};

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
                        let t = l.split_whitespace().collect::<Vec<_>>();
                        if t.len() < 2
                            || (t[0] != "ecdsa-sha2-nistp256"
                                && t[0] != "ssh-ed25519")
                        {
                            bail!("line {n}: invalid key format");
                        }
                        let buf = base64::decode(&t[1]).map_err(|e| {
                            anyhow!("line {n}: decoding key: {e}")
                        })?;
                        let mut key = PublicKey::from_bytes(buf.as_slice())
                            .map_err(|e| {
                                anyhow!("line {n}: parsing key: {e}")
                            })?;
                        if t.len() > 2 {
                            key.set_comment(t[2..].join(" "));
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
