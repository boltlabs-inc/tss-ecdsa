## How to run benchmarks

cargo bench e2e_benchmark
cargo bench bignumber_benchmark

## Bignumber Benchmarks

| lib | openssl    | bigint    | gmp    | 
| :---   | :--- | :--- |
| prime gen | 1 s   | 52 s   | 15 s   |
| :---   | :--- | :--- |
| modpow | 5.46 ms    | 185 ms    | 10.5 ms    |

## End to end benchmarks

| lock-keeper flow | key generation    | signing    | 
| :---   | :--- | :--- |
| tss-ecdsa protocol | keygen   | aux-info   | presign   | sign   |
| :---   | :--- | :--- | :--- | :--- |
| per-party time |
| :---   | 
| 3 nodes    | 0.76 ms    | 6650 ms    | 289 ms    | not evaluated (fast)    |
| :---   | :--- | :--- | :--- | :--- |
| 6 nodes    | 1.7 ms    | 6858 ms    | 700 ms    | not evaluated (fast)    |
| :---   | :--- | :--- | :--- | :--- |
| 9 nodes    | 2.8 ms    | 7061 ms    | 1145 ms    | not evaluated (fast)    |

### Macbook Pro

| tss-ecdsa protocol | keygen   | aux-info   | presign   | sign   |
| :---   | :--- | :--- | :--- | :--- |
| 3 nodes    | 1.3259 µs    | 1.7117 µs    | 32.441 ns    | not evaluated (fast)    |