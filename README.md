# simplest-ot
Implementation of Chou-Orlandi Oblivious Transfer (OT) protocol

## Work in progress

A n-out-of-1 OT protocol practical implementation in Rust, as thin as possible.
The implementation is a work in progress and incomplete, not to be used in production environments. The sole purpose is to learn how to use Rust crypto libraries.

## Quickstart

This command will run an example:

```
cargo run
```

The example reads `example_input.txt` and creates a sender and receiver.
Receiver is expected to only succeed in decrypting one message, while the rest are "Impossible to decrypt".

```
Initiating protocol
n: 2
Receiver choosing a random index
Receiver decypting
Success [111, 110, 101]
Impossible to decrypt
```

## References

OT protocol article:
- https://eprint.iacr.org/eprint-bin/getfile.pl?entry=2015/267&version=20180529:135402&file=267.pdf

Another implemenration of the Simplest OT is here:
- https://github.com/GaloisInc/ocelot/