# sshauth: a library for SSH key based authentication tokens

The `sshauth` library produces and verifies ephemeral bearer tokens
signed by an SSH private key, either directly or via the SSH agent.
These tokens are suitable for authentication of a client to a server,
e.g., using the HTTP `Authorization` header.

## Example

In the client, choose an [SSH key](https://docs.rs/ssh-key/latest/ssh_key/)
(an "identity" in SSH parlance), either by reading a key file or querying
the agent (see `ssh-agent(1)` and `ssh-add(1)` for more on key management):

```
let authsock = env::var("SSH_AUTH_SOCK")
    .expect("SSH_AUTH_SOCK is unset or invalid")?;
let public_key: ssh_key::public::PublicKey =
    sshauth::agent::list_keys(&authsock)
    .await?
    .into_iter()
    .find(|key| {
        // choose key of interest by type, fingerprint, comment, etc.
        ...
    })
    .expect("can't find a suitable SSH identity");
```

With the key in hand, the client can generate, sign, and encode a token:

```
let token: String = sshauth::TokenSigner::using_authsock(authsock)?
    .key(key)
    .include_fingerprint(true)
    .build()?
    .sign_for()
    .sign()
    .await?
    .encode()
```

Then, assuming that the public key has been previously registered and stored
on the server (e.g., in a database or filesystem), authentication code in
the server can look at the fingerprint in the unverified token, fetch the
corresponding public key, and verify the token's signature:

```
let raw_token: String = ...; // get the token, e.g. from the "Authorization" header of an HTTP request
let unverified_token = sshauth::UnverifiedToken::try_from(raw_token.as_str())?;
let fingerprint = unverified_token.untrusted_fingerprint().expect("token must include fingerprint");
let public_key = ...; // fetch the registered public key matching `fingerprint`
let verified_token = unverified_token.verify_for().with_key(&public_key)?;
```

## Tunables

Along with signature checking, token verification also includes checking an
embedded timestamp. Tokens are valid by default for 60 seconds.

As an alternative to using fingerprints to identify keys, the library also
supports using (restricted) file names; this can be handy if you're using
a filesystem as your key store. Just replace `.include_fingerprint(true)`
with `.identity_filename(path)` on the client side, and instead of
`.untrusted_fingerprint()` on the server, use `.untrusted_identity_filename()`.

There are many other tunable token parameters (expiration, signing strategy,
action key/value pairs, etc.), but the defaults should be reasonable for
many applications.

The library should be hard to misuse. If you find a way of "holding it wrong"
(e.g., trusting data before verification, constructing unsafe or unsigned
tokens, skipping or improperly verifying signatures, etc.), please [let us
know](#contributions).

## Limitations

This library is limited in scope to public key authentication. It is not
intended to be a general-purpose identity provider or authorization system.
There is no web component or integration with any third-party services.
It does not (currently) support any kind of challenge/response protocol,
and so in principle is vulnerable to certain kinds of replay attacks
(although it does have several features to help mitigate those risks).
If you need any of those features, you might be better served by other
protocols such as SAML, OAuth, OIDC, etc.

If this library is able to verify a token, you may assume that the producer
of that token had access to the corresponding private key at the time of
generation, which was within the allowed window. In the absence of other
information, you may not generally assume anything else about the signing
system, user, or owner of that private key.

## Contributions

Helpful contributions of any kind are welcome; please submit
an [issue](https://github.com/oxidecomputer/sshauth/issues)
or open a [pull request](https://github.com/oxidecomputer/sshauth/pulls)
on our [GitHub repository](https://github.com/oxidecomputer/sshauth).
