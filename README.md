# tss-ecdsa

This repo is a work-in-progress implementation of Canetti et al.'s threshold ECDSA protocol described in

[CGGMP20] R. Canetti, R. Gennaro, S. Goldfeder, N. Makriyannis, and U. Peled. UC non-interactive, proactive,  threshold ECDSA with identifiable aborts. In  ACM CCS 2020, pp. 1769–1787. ACM Press, 2020.

For details, see the [paper](https://eprint.iacr.org/archive/2021/060/1634824619.pdf).

Specifically, we are targeting the three-round presigning protocol of the original paper (with quadratic overhead for identifying faulty actors).

This codebase is generally intended to be network-agnostic. Programs take messages as input and potentially output some outgoing messages in response. The relaying of these messages is assumed to happen externally. However, a proof-of-concept example of such networking code can be found in examples/network.

## Project Dependencies
This project relies on the `libpaillier` Rust crate using the GMP backend. GMP should be available during build-time.  

### Rust Dependencies and Versions

This library currently works with Rust compiler 1.76.

This library has been tested with GMP version 6.2.1.

You can build GMP from [source](https://gmplib.org/manual/Installing-GMP) or using a [package manager on linux](http://www.mathemagix.org/www/mmdoc/doc/html/external/gmp.en.html) or [OSX](https://formulae.brew.sh/formula/gmp). The GMP website has [additional notes for other systems](https://gmplib.org/manual/Notes-for-Particular-Systems).


##  What's Implemented

### Key Generation - n out of n (Figure 5 of CGGMP20)

KeyGen generates a threshold signing key, shares of which are distributed to each node. Every node outputs a private key along with the public keys of all other nodes. This only needs to be run once for a given set of nodes. 

### Auxinfo (CGGMP20 Figure 6, minus the key refreshing)

Auxinfo generates the auxiliary information (Paillier keys and ring-Pedersen parameters) needed in order to compute presignatures. In CGGMP20, this is done in parallel with key refreshing, however this codebase currently only implements the generation of auxiliary information. This is run after KeyGen and only needs to be run once.

### Three Round Pre-signing (Figure 7 of CGGMP20)

Presign is a protocol to calculate pre-signatures, which can be computed before the message to be signed is known. Once a pre-signature is computed, a threshold signature can be easily calculated in one round of interaction. This protocol must be run for every message which is to be signed.

### Key Refresh - n out of n (CGGMP20 Figure 6, minus aux info)

Key refresh is a protocol to re-randomize each parties share of the ECDSA public key. This helps with recovery from compromised parties. In cryptographic literature, this method is used to provide security against a mobile adversary who corrupts up to n-1 parties at any given time but in any given epoch may choose to corrupt different parties. This should be run *after* getting new parameters from Auxinfo upon suspected corruption.

### Key Generation - t out of n ([from extrapolating the paper](ThresholdCGGMP.pdf))

This version of KeyGen generates a threshold key based on Section 1.2.8 **Extension to t-out-of-n Access Structure**. Like the original 
key generation algorithm, each node gets a private key along with public keys for all other nodes. However, only t nodes are needed to recover the whole private key where t is a movable parameter. While not currently having a public facing api, this can be done by 
using the Tshare protocol without providing an input share. An example of this type of key generation can be seen in some of the 
test cases in protocol.rs. 

### HD Wallet support 

The library currently supports creating hierarichical deterministic wallets as specified in SLIP-0010. To be very specific, for threshold ECDSA only non-hardened child keys are supported and the master key cannot be generated from a passphrase. 


### Other

KeyGen, Auxinfo, and Presign are the three protocols needed in order to do threshold signing. All of the zero-knowledge proofs that underpin these protocols have been implemented, as has an echo-broadcast protocol which is needed in order to enforce non-equivocation of message contents.

protocol.rs contains a test program for running a full protocol instance, which includes the KeyGen, Auxinfo, and Presign stages. Each of these protocols can also be run independently with their own tests.

## What's Not Implemented

Currently, the codebase only fully supports n-out-of-n sharing. Partial support for t-out-of-n sharing exists, but key refresh is not yet 
fully supported and t-out-of-n key generation does not have a clean, public-facing API. 

Additionally, Identifiable Aborts is not fully implemented.  We sometimes report blame when it is easily attributable but we miss many cases and users should not rely on that field to be complete at this point. If a node crashes, the protocol will halt until that node comes back online. In addition to implementing the necessary cryptographic checks to identify and attribute malicious behavior, some notion of synchronous timeouts is also required.

While some thought has been put into handling invalid messages (duplicate messages are ignored, as are some malformed ones), this has not been evaluated fully. Additionally, message authenticity (i.e. that a given message is actually coming from the sender in the "sender" field) is currently assumed to be handled outside of the protocol, by whatever networking code is shuttling messages around.

### Update to CGGMP 

The reader may notice that the most recent version of the [CGGMP paper](https://eprint.iacr.org/2021/060.pdf) on Eprint has been significantly revamped. The new result is a protocol that simultaneously achieves good round complexity and accountability properties.
In the future it may make sense to change this implementation to more closely match what is specified there for efficiency reasons. 

## How to Build and Run

The library requires a recent, stable version of Rust. You can switch to stable releases and update to the latest version using the following:

`rustup default stable` 
`<br>`
`rustup update`

This library also includes a Makefile with our full set of continuous integration checks, including formatting, linting, building, building docs, and running tests. You can run it locally with:

`cargo make ci`

## Benchmarks

The benchmarks are found in the benches folder. Please refer to the benches/README.md file for information on how to run and obtain the benchmarks, as well as how to generate a flame graph showing relative costs of some function calls.

## Examples

This library contains a CLI example you can use to test out the complete tss-ecdsa workflow: key generation, aux-info generation, pre-sign record generation, and signing.
From the root directory, you can run: `cargo run --example threaded_example -- --help`. This command will print the CLI interface:
```
Multi-party ECDSA signing

Usage: threaded_example --number-of-workers <NUMBER_OF_WORKERS>

Options:
-n, --number-of-workers <NUMBER_OF_WORKERS>
Number of participant worker threads to use. Default: 3.
-h, --help
Print help
-V, --version
Print version
```
For example, `cargo run --example threaded_example -- --number-of-workers 3` will execute this example using three workers (participants).
**Note** please pay attention to the `--` in the middle of the command. This is necessary to separate arguments to the `cargo run` command from arguments to this
CLI example.

This CLI example supports logging via the tracing crate. You can set the env var `RUST_LOG` to a verbosity level to execute with logging turned on:
For example:
```shell
RUST_LOG=info cargo run --example threaded_example -- --number-of-workers 2
```