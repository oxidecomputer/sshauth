/*
 * Copyright 2024 Oxide Computer Company
 */

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, BytesMut};
use ssh_encoding::Decode;
use ssh_key::{PublicKey, Signature};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

#[derive(Debug, Clone)]
enum Message {
    AgentFailure,
    AgentSuccess,
    AgentCRequestIdentities,
    AgentIdentitiesAnswer(Vec<PublicKey>),
    AgentCSignRequest(PublicKey, Vec<u8>),
    AgentSignResponse(Signature),
}

impl Message {
    fn pack(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        match self {
            Message::AgentCRequestIdentities => {
                buf.put_u32(1);
                buf.put_u8(11);
            }
            Message::AgentCSignRequest(key, data) => {
                /*
                 * Generate key blob...
                 */
                let blob = key.to_bytes().unwrap();
                let len = 1 + 4 + blob.len() + 4 + data.len() + 4;
                buf.put_u32(len.try_into().unwrap());
                buf.put_u8(13);
                buf.put_u32(blob.len().try_into().unwrap());
                for b in blob {
                    buf.put_u8(b);
                }
                buf.put_u32(data.len().try_into().unwrap());
                for b in data {
                    buf.put_u8(*b);
                }
                buf.put_u32(0);
            }
            _ => panic!("cannot pack {:?}", self),
        }
        buf
    }
}

enum State {
    Rest,
    Len(usize),
    Message(Message),
    Error,
}

struct PartialMessage {
    state: State,
    buf: BytesMut,
}

impl PartialMessage {
    fn new() -> PartialMessage {
        PartialMessage { buf: Default::default(), state: State::Rest }
    }

    fn add(&mut self, byt: u8) -> Result<()> {
        self.buf.put_u8(byt);

        match self.state {
            State::Error => {
                bail!("protocol error");
            }
            State::Rest => {
                if self.buf.len() > 4 {
                    self.state =
                        State::Len(self.buf.get_u32().try_into().unwrap());
                }
            }
            State::Len(len) => {
                if self.buf.len() == len {
                    /*
                     * We have the whole message.
                     */
                    if len == 0 {
                        self.state = State::Error;
                        bail!("zero-length message");
                    }
                    match self.buf.get_u8() {
                        5 => {
                            self.state = State::Message(Message::AgentFailure);
                        }
                        6 => {
                            self.state = State::Message(Message::AgentSuccess);
                        }
                        12 => {
                            if self.buf.remaining() < 4 {
                                self.state = State::Error;
                                bail!("identities answer too short");
                            }
                            let nkeys = self.buf.get_u32();
                            let mut keys = Vec::new();
                            for _ in 0..nkeys {
                                /*
                                 * Read the key blob length (u32):
                                 */
                                if self.buf.remaining() < 4 {
                                    self.state = State::Error;
                                    bail!("identities answer too short 2");
                                }
                                let keybloblen =
                                    self.buf.get_u32().try_into().unwrap();

                                /*
                                 * Read the key blob itself, and parse it as a
                                 * public key:
                                 */
                                if self.buf.remaining() < keybloblen {
                                    self.state = State::Error;
                                    bail!("identities answer too short 3");
                                }
                                let mut key = ssh_key::PublicKey::from_bytes(
                                    self.buf.get(0..keybloblen).unwrap(),
                                )
                                .unwrap();
                                self.buf.advance(keybloblen);

                                /*
                                 * Read the length of the comment string (u32):
                                 */
                                if self.buf.remaining() < 4 {
                                    self.state = State::Error;
                                    bail!("identities answer too short 4");
                                }
                                let commlen =
                                    self.buf.get_u32().try_into().unwrap();

                                /*
                                 * Read the comment itself:
                                 */
                                if self.buf.remaining() < commlen {
                                    self.state = State::Error;
                                    bail!("identities answer too short 5");
                                }
                                let s = String::from_utf8(
                                    self.buf.get(0..commlen).unwrap().to_vec(),
                                );
                                self.buf.advance(commlen);

                                if let Ok(s) = s {
                                    /*
                                     * Apply the comment to the key data we
                                     * already parsed, and add it to the
                                     * response list.
                                     */
                                    key.set_comment(s);
                                    keys.push(key);
                                } else {
                                    self.state = State::Error;
                                    bail!("comment string format wrong");
                                }
                            }
                            self.state = State::Message(
                                Message::AgentIdentitiesAnswer(keys),
                            );
                        }
                        14 => {
                            if self.buf.remaining() < 4 {
                                self.state = State::Error;
                                bail!("signature answer too short");
                            }
                            let len = self.buf.get_u32().try_into().unwrap();
                            if self.buf.remaining() != len {
                                self.state = State::Error;
                                bail!(
                                    "wanted {} got {}",
                                    len,
                                    self.buf.remaining()
                                );
                            }

                            let sig = Signature::decode(
                                &mut self.buf.get(0..len).unwrap(),
                            )?;
                            self.buf.advance(len);

                            self.state =
                                State::Message(Message::AgentSignResponse(sig));
                        }
                        n => {
                            self.state = State::Error;
                            bail!("unhandled message type {}", n);
                        }
                    }
                } else if self.buf.len() > len {
                    /*
                     * We have too much message!
                     */
                    self.state = State::Error;
                    bail!("too much message (wanted {} bytes)", len);
                }
            }
            State::Message(_) => {
                bail!("message without take()");
            }
        }

        Ok(())
    }

    fn take(&mut self) -> Option<Message> {
        let m = match &self.state {
            State::Message(m) => m.clone(),
            _ => return None,
        };
        self.state = State::Rest;
        self.buf.clear();
        Some(m)
    }
}

async fn connect(authsock: &str) -> Result<UnixStream> {
    Ok(UnixStream::connect(authsock).await?)
}

pub async fn list_keys(authsock: &str) -> Result<Vec<PublicKey>> {
    let mut uds = connect(authsock).await?;

    let buf = Message::AgentCRequestIdentities.pack();
    uds.write_all(&buf).await?;

    let mut par = PartialMessage::new();
    loop {
        par.add(uds.read_u8().await?)?;
        if let Some(m) = par.take() {
            match m {
                Message::AgentIdentitiesAnswer(keys) => return Ok(keys),
                o => bail!("WRONG MSG: {:?}", o),
            }
        }
    }
}

pub async fn sign(
    authsock: &str,
    key: &PublicKey,
    data: &[u8],
) -> Result<Signature> {
    let mut uds = connect(authsock).await?;

    let buf = Message::AgentCSignRequest(key.clone(), data.to_vec()).pack();
    uds.write_all(&buf).await?;

    let mut par = PartialMessage::new();
    loop {
        par.add(uds.read_u8().await?)?;
        if let Some(m) = par.take() {
            match m {
                Message::AgentSignResponse(sig) => {
                    return Ok(sig);
                }
                o => {
                    bail!("WRONG MSG: {:?}", o);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn listing_keys() {
        let authsock = std::env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK");

        let keys = list_keys(&authsock).await.unwrap();

        println!("keys = {keys:#?}");

        if let Some(pk) =
            keys.iter().find(|key| key.comment().starts_with("PIV_slot_9A"))
        {
            println!(
                "fp = {}",
                pk.fingerprint(ssh_key::HashAlg::Sha256).to_string()
            );
            println!("ossh -> {}", pk.to_openssh().unwrap());
        }
    }

    #[tokio::test]
    async fn signing_something() {
        let authsock = std::env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK");

        let keys = list_keys(&authsock).await.unwrap();

        let pk = if let Some(pk) =
            keys.iter().find(|key| key.comment().starts_with("PIV_slot_9A"))
        {
            println!(
                "fp = {}",
                pk.fingerprint(ssh_key::HashAlg::Sha256).to_string()
            );
            println!("ossh -> {}", pk.to_openssh().unwrap());
            pk
        } else {
            println!("keys = {keys:#?}");
            panic!("could not find PIV_slot_9A key");
        };

        let sig = sign(&authsock, pk, b"abcdef").await.unwrap();

        println!("sig = {sig:?}");

        let tsig = crate::token::TokenSignature::try_from(sig.clone()).unwrap();

        println!("tsig = {tsig:?}");

        let bsig = Signature::try_from(&tsig).unwrap();

        println!("and back = {bsig:?}");

        assert_eq!(sig, bsig);
    }
}
