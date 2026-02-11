# Lightning Onion Builder Playground

An interactive web-based playground for learning and experimenting with BOLT#04 Onion Routing packet construction in the Lightning Network.

## Overview

This project provides a visual, interactive interface for understanding how Lightning Network onion packets are built according to [BOLT#04](https://github.com/lightning/bolts/blob/master/04-onion-routing.md). It implements the cryptographic operations involved in creating onion routing packets, including:

- **Key Derivation**: ECDH shared secret computation and key derivation (pad, rho, mu)
- **Mix Header Construction**: Building the encrypted payload structure
- **Filler Construction**: Creating obfuscation fillers for intermediate hops
- **HMAC Computation**: Computing integrity checks for each hop
- **Onion Wrapping**: Assembling the final packet with version, ephemeral key, mix header, and HMAC

## Usage

### Running Locally

Simply open `index.html` in a modern web browser. No build step or server required.

```bash
# Using a simple HTTP server (recommended)
python3 -m http.server 8000
# Then open http://localhost:8000
```

### Using Default Values

The playground pre-loads with example values from the Lightning Network specification test vectors:
- Session Key: 32-byte hex value
- Associated Data: Variable-length hex value
- 5 Example Hops with realistic payloads

### Building an Onion

1. **Session Setup**: Enter your session key (32 bytes hex) and associated data
2. **Configure Hops**: Add intermediate hops with public keys and payloads
3. **Build**: Click "Build Onion" to generate the packet
4. **Visualize**: Explore the step-by-step construction process

## Technical Details

### Cryptographic Primitives

| Primitive | Implementation |
|-----------|---------------|
| Elliptic Curve | secp256k1 (via @noble/secp256k1) |
| Hash Function | SHA256 (via @noble/hashes) |
| HMAC | HMAC-SHA256 |
| Encryption | ChaCha20 |

### Key Derivation

The playground implements the following key derivation per [BOLT#04](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#key-derivation):

```
shared_secret = SHA256(ECDH(ephem_priv, hop_pub))
rho = HMAC("rho", shared_secret)
mu = HMAC("mu", shared_secret)
pad = HMAC("pad", ephem_priv)
```

### Packet Structure

The final onion packet consists of:
1. **Version** (1 byte): Currently always 0x00
2. **Ephemeral Public Key** (33 bytes): First ephemeral key for ECDH
3. **Mix Header** (1300 bytes): Encrypted payload with filler
4. **HMAC** (32 bytes): Integrity check for the first hop

## Dependencies

- [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) - Elliptic curve cryptography
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) - Hash functions and HMAC
- [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) - ChaCha20 cipher

## References

- [BOLT#04: Onion Routing Message Format](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [Lightning Network Specification](https://github.com/lightning/bolts)
- [Routing Hypothesis](https://github.com/rustyrussell/lightning-rfcs/blob/master/lightning-rfc.md)

## License

MIT License
