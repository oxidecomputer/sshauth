# sshauth: a library for SSH key based authentication tokens

The **sshauth** library produces and verifies ephemeral bearer tokens signed by
an SSH private key, either directly or via the SSH agent.  These tokens are
suitable for authentication of a client to a server; e.g., using the HTTP
**Authorization** header.

## Example

In the client, choose an [SSH key](https://docs.rs/ssh-key/latest/ssh_key/) (an
"identity" in SSH parlance), either by reading a key file or querying the agent
(see [ssh-agent(1)](https://man.openbsd.org/ssh-agent.1) and
[ssh-add(1)](https://man.openbsd.org/ssh-add.1) for more on key management):

```rust
let authsock = env::var("SSH_AUTH_SOCK")
    .expect("SSH_AUTH_SOCK is unset or invalid");
let public_key: ssh_key::public::PublicKey =
    sshauth::agent::list_keys(&authsock)
    .await?
    .into_iter()
    .find(|key| {
        /*
         * Choose key of interest by type, fingerprint, comment, etc.
         */
        ...
    })
    .expect("can't find a suitable SSH identity");
```

With the key in hand, the client can generate, sign, and encode a token:

```rust
let signer = sshauth::TokenSigner::using_authsock(authsock)?
    .key(key)
    .include_fingerprint(true)
    .build()?;
let token: String = signer
    .sign_for()
    .sign()
    .await?
    .encode();
```

Then, assuming that the public key has been previously registered and stored
on the server (e.g., in a database or file system), authentication code in
the server can look at the fingerprint in the unverified token, fetch the
corresponding public key, and verify the token's signature:

```rust
/*
 * Get the token; e.g., from the "Authorization" header of a HTTP request:
 */
let raw_token: String = "...";
let unverified_token = sshauth::UnverifiedToken::try_from(raw_token.as_str())?;
let fingerprint = unverified_token
    .untrusted_fingerprint()
    .expect("token must include fingerprint");
/*
 * Fetch the registered public key matching the fingerprint and verify the
 * signature:
 */
let public_key = your_database.key_for_fingerprint(&fingerprint)?;
let verified_token = unverified_token.verify_for().with_key(&public_key)?;
```

## Clock Requirements

In order to limit the useful lifetime of a token, the current time of day
is included in the signed blob so that it can be verified on the server.
By default, the client and the server clock must agree on time to within
a delta of 60 seconds.  It is recommended that both clients and servers
be configured with NTP to avoid issues.

If your system provides looser guarantees about time, or you want to be able to
reuse tokens for a longer period, you can relax this requirement -- with the
concomitant reduction in security in the face of leaked or intercepted tokens.
Use `.max_skew_seconds(seconds)` with a wider range when verifying a token.
There is presently no way to completely disable time stamp generation or
validation.

Note that while the client is signing a time stamp, that does not mean that the
client produced the signature at the actual nominated time.  Client clocks are
under client control, and could be wound or backwards arbitrarily while
producing signatures.  If you need a verifiable time stamp, you would need some
other mechanism to achieve that; e.g., a quorum of independent time stamp
signing servers, which could _themselves_ use SSH tokens for authentication.

## Actions

To reduce the scope of replay attacks the signed blob can include an arbitrary
list of actions, described as string key-value pairs.  Applications are
expected to include in the action list anything that they would like to verify
about the request to which the token is attached; e.g., the HTTP method,
authority, query string, and the digest of a POST body would make it more
difficult for an attacker to re-use an intercepted token to make different
requests.

To keep token size manageable, the action list is not included in the token
itself.  The token signer and the token verifier must agree in advance on the
order and precise contents of the action list.  Any mismatch will lead to a
verification failure.

## Magic Prefix

To make cross-protocol attacks more difficult, the library supports a
fixed-length prefix for the signed blob that the consuming system using the
`.magic_prefix([u8; 8])` routine on signers and verifiers.   Two systems using
different magic prefixes will produce signatures that are mutually
unverifiable.  The client and the server must agree, at the level of their
mutually agreed application protocol, on a constant prefix value.

## Identity

As an alternative to using fingerprints to identify keys, the library also
supports using (restricted) file names; this can be handy if you're using a
file system as your key store, or if you want to look up keys by a synthetic
identifier like a login name.  Just replace `.include_fingerprint(true)` with
`.identity_filename(path)` on the client side, and instead of
`.untrusted_fingerprint()` on the server, use `.untrusted_identity_filename()`.

It is also possible to combine the use of an identity file name and an included
fingerprint within the same token if desired.

## Public Key Sources

The library provides two basic helper modules for getting started with a public
key source in small applications that operate chiefly out of the local file
system:

* The `keyfile::parse_authorized_keys()` routine will parse an OpenSSH
  `authorized_keys` file and return a list of public keys from that file.
* The `keydir::KeyDirectory` object builds on this to perform a lookup in
  a nominated directory, using the _identity file name_ that may be provided
  in a token.  That file name will be used to load a file from the key
  directory, and the token is considered valid if any of the public keys
  in that file allow a successful verification.

The system presently supports the following key types:

- ECDSA keys using the NIST P-256 curve
- Ed25519 keys

## Tuneables

There are many other tunable token parameters (expiration, signing strategy,
etc.), but the defaults should be reasonable for many applications.

The library is intended to be difficult to misuse.  If you find a way of
"holding it wrong" (e.g., trusting data before verification, constructing
unsafe or unsigned tokens, skipping or improperly verifying signatures, etc.),
please [let us know](#contributions).

## Limitations

This library is limited in scope to public key authentication.  It is not
intended to be a general-purpose identity provider or authorization system.
There is no web component or integration with any third-party services.  It
does not directly support any kind of challenge/response protocol (although one
can be layered on top through the use of **action** key-value pairs), and so in
principle is vulnerable to certain kinds of replay attacks.  If you need any of
those features, you might be better served by other protocols such as SAML,
OAuth, OIDC, etc.

If this library is able to verify a token, you may assume that the producer
of that token had access to the corresponding private key at the time of
generation, which was within the allowed window.  In the absence of other
information, you may not generally assume anything else about the signing
system, user, or owner of that private key.

## Contributions

Helpful contributions of any kind are welcome; please submit
an [issue](https://github.com/oxidecomputer/sshauth/issues)
or open a [pull request](https://github.com/oxidecomputer/sshauth/pulls)
on our [GitHub repository](https://github.com/oxidecomputer/sshauth).
