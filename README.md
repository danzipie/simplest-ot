# simplest-ot
Implementation of Chou-Orlandi Oblivious Transfer (OT) protocol

## Work in progress

A n-out-of-1 OT protocol practical implementation in Rust, as thin as possible.
The purpose is to learn how to use Rust crypto libraries.

## Quickstart

```
cargo build
./target/debug/simplest-ot
```

## Design

It uses Chou-Orlandi "Simplest OT" protocol to establish key exchange, and AES encryption for the actual information.

## References

OT protocol article:
- https://eprint.iacr.org/eprint-bin/getfile.pl?entry=2015/267&version=20180529:135402&file=267.pdf

Another implemenration of the Simplest OT is here:
- https://github.com/GaloisInc/ocelot/