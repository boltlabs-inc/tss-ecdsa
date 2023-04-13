## Context

The threshold ECDSA library breaks down the tss-ecdsa protocol by Canetti et. al into its constituent sub-protocols, namely keygen, auxinfo, pre-sign and sign, and benchmarks their running times for each party. 

## Benchmarks

These benchmarks evaluate the keygen, aux-info, and pre-signing  protocols. We did not evaluate the signing step because it’s virtually instantaneous. Each protocol was run 100 times using the criterion Rust package.

The benchmarking software runs all parties serially; it randomly selects a party, processes any messages it has waiting, and repeats until the protocol is complete. The results reported try to capture per-party runtime: the total benchmark time divided by the number of parties.

The threshold ECDSA library does not include any networking software. To run these benchmarks, we handled all message passing locally in memory. All participants ran on the same machine, with an AMD Ryzen 9 3900X 12-Core Processor, 32GB of RAM.

In a deployed protocol, we would also need to account for time spent sending messages over the network, “downtime” spent waiting to receive messages, and storing / retrieving outputs from each subprotocol.

## How to run benchmarks

For running the bignumber benchmarks:

`cargo bench --bench bignumber_benchmark`

For running the end to end benchmarks:

`cargo bench --bench e2e_benchmark`


## Bignumber Benchmarks

The big-number crate we use is `unknown_order`, and it has a single interface that supports three different big-number backends: the pure-Rust `num_bigint` crate, `OpenSSL`, and `GMP`. We did some benchmarks on our highest-cost operations and found that GMP was the best option for us. The table below compares the two operations of safe prime generation and modular exponentiation for the 3 different big-number backends:

| lib | prime gen | modpow |
| :---   | :--- | :--- |
| openssl    | 1 s   | 5.46 ms   |
| bigint   |  52 s   | 185 ms   |
| gmp    | 15 s   | 10.5 ms   |

## End to end benchmarks

The table below measures the per-party time for the different sub-parts of the tss-ecdsa protocol:

| tss-ecdsa protocol | 3 nodes    | 6 nodes    | 9 nodes    |
| :--- | :--- | :--- | :--- |
| keygen  | 0.76 ms    | 1.7 ms    | 2.8 ms    |
| aux-info   | 6650 ms    | 6858 ms    | 7061 ms    |
| presign   | 289 ms    | 700 ms    | 1145 ms    |
| sign   | not evaluated (fast)    | not evaluated (fast)    | not evaluated (fast)    |

It takes < #nodes > * < reported value > seconds for all the nodes to run in series on a single machine. We performed division to get the reported numbers, but there might be a little extra overhead for sending and buffering and so on.

The above benchmarks were measured on December 2022. 


