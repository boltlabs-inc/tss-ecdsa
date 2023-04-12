## How to run benchmarks

For running the bignumber benchmarks:

`cargo bench --bench bignumber_benchmark`

For running the end to end benchmarks:

`cargo bench --bench e2e_benchmark`


## Bignumber Benchmarks

| lib | prime gen | modpow |
| :---   | :--- | :--- |
| openssl    | 1 s   | 5.46 ms   |
| bigint   |  52 s   | 185 ms   |
| gmp    | 15 s   | 10.5 ms   |

## End to end benchmarks

| lock-keeper flow | tss-ecdsa protocol | 3 nodes    | 6 nodes    | 9 nodes    |
| :---   | :--- | :--- | :--- | :--- |
| key generation    | keygen  | 0.76 ms    | 1.7 ms    | 2.8 ms    |
|                   | aux-info   | 6650 ms    | 6858 ms    | 7061 ms    |
| signing    | presign   | 289 ms    | 700 ms    | 1145 ms    |
|            | sign   | not evaluated (fast)    | not evaluated (fast)    | not evaluated (fast)    |
[Per Party Time]

### Macbook Pro

| tss-ecdsa protocol | keygen   | aux-info   | presign   | sign   |
| :---   | :--- | :--- | :--- | :--- |
| 3 nodes    | 1.3259 µs    | 1.7117 µs    | 32.441 ns    | not evaluated (fast)    |
