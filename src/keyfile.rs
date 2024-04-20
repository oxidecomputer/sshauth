/*
 * Copyright 2024 Oxide Computer Company
 */

use std::{
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{anyhow, bail, Result};
use ssh_key::PublicKey;

pub fn parse_authorized_keys<P>(
    path: P,
    ignore_invalid: bool,
) -> Result<Vec<PublicKey>>
where
    P: AsRef<Path>,
{
    let p = path.as_ref();

    let f =
        std::fs::File::open(p).map_err(|e| anyhow!("opening {p:?}: {e}"))?;
    let br = BufReader::new(f);
    let mut lines = br.lines();
    let mut lc = 0;

    let mut keys = Vec::new();

    while let Some(l) =
        lines.next().transpose().map_err(|e| anyhow!("reading {p:?}: {e}"))?
    {
        lc += 1;

        /*
         * Check for a comment-only or blank line.
         */
        let l = l.trim();
        if l.starts_with("#") || l.is_empty() {
            continue;
        }

        match PublicKey::from_openssh(l) {
            Ok(pk) => keys.push(pk),
            Err(e) => {
                if ignore_invalid {
                    continue;
                }

                bail!("reading {p:?}: line {lc}: {e}");
            }
        }
    }

    Ok(keys)
}
