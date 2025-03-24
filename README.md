## Prerequisites

script includes auto-generation of signing keys. So make sure OpenSSL is available on your machine.

Install oenssl:
For mac,

```

# Install OpenSSL development libraries

brew install openssl



# Set the PKG_CONFIG_PATH environment variable to point to the OpenSSL pkg-config directory

export PKG_CONFIG_PATH="$(brew --prefix openssl)/lib/pkgconfig"



# Optionally, set the OPENSSL_DIR environment variable

export OPENSSL_DIR="$(brew --prefix openssl)"



# Verify the configuration

PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags openssl

```

## component:

script: rust script that generates jwt and request server to verify
server: actix_server, a web server that supports the following endpoints:
/verify
/nonce

# Running

### **Terminal 1**

This terminal will run the server that generates and verifies nonces and JWTs.

```
cargo run -p vc-verifier-server
```

### **Terminal 2**

This script will generate the credential and send a request to the server.

```
cargo run -p vc-holder-script -- --credential-file ./sample/credential.json
```

## TODO

Public key retrieval is TBD. For now, it assumes the key resides in the server's root path.

## Point of improvement for the future.

- Application attestation support
- https support ( probably done by cloud system )
- Dockernize support so system requirement is contained.
- Nounce is simple storage assuming that this test case is limited.
- Holder's public key verification is still missing.
  X.509 certificates is support to check holder's public key could be implemented in the verificatio platform as a job.
- nounce implementation could be limted.
  just to demostrate nounce is used to verify the request's attestation, I included in the request header. But it could be other format.
- nounce store is HashMap. Could use other standalone cache.
