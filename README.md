# tss-ecdsa 
This repo is a work-in-progress implementation of the UC-Secure threshold ECDSA signing protocol described in https://eprint.iacr.org/2021/060.pdf
Specifically, we are targeting the three-round presigning protocol (with quadratic overhead for identifying faulty actors).

This codebase is generally intended to be network-agnostic. Programs take messages as input and potentially output some outgoing messages in response. The relaying of these messages is assumed to happen externally. However, a proof-of-concept example of such networking code can be found in examples/network.

## Current State
### What's Implemented
Currently, the KeyGen protocol (Figure 5), Auxinfo (Figure 6, minus the key refreshing), and 3 round Presign (Figure 7) are implemented, along with the requisite zero-knowledge proofs. These protocols make use of (where appropriate) an echo-broadcast subprotocol in order to enforce non-equivocation of message contents

protocol.rs contains a test program for running a full protocol instance, which includes the KeyGen, Auxinfo, and Presign stages. Each of these protocols can also be run independently with their own tests. 

### What's Not Implemented
Currently, the codebase only implements n-out-of-n sharing. While t-out-of-n sharing is not formally specified in the paper, we expect the transformation to be relatively straightforward.

Additionally, no notions of Identifiable Aborts are implemented. If a node crashes, the protocol will halt until that node comes back online. In addition to implementing the necessary cryptographic checks to identify and attribute malicious behavior, some notion of synchronous timeouts is also required.

While some thought has been put into handling invalid messages (duplicate messages are ignored, as are some malformed ones), this has not been evaluated fully. Additionally, message authenticity (i.e. that a given message is actually coming from the sender in the "sender" field) is currently assumed to be handled outside of the protocol, by whatever networking code is shuttling messages around.