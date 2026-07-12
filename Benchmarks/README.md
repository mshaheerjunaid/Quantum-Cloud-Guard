# Benchmarks

Every number in the paper's evaluation section comes from a file in here. This is the map from paper table to raw data.

## Where the machines are

The measurements were taken on a few different machines, because the paper tests both a tiny microcontroller and normal computers:

- **The server**: a Hetzner CX22 (2 vCPU, ~3.7 GB RAM), Ubuntu, Python 3.14.4, behind Caddy 2.11.4. This ran the KEM, ML-DSA, AES, attack, and TLS measurements.
- **A microcontroller**: an STM32F407 (ARM Cortex-M4 at 24 MHz), for the embedded numbers.
- **Three laptops/desktops**: an i9-14900HX, a Ryzen 5 5600X, and an i5-8365U, for the client-side hardware comparison.

All software timings throw away a warm-up run and report medians over many iterations. Numbers on the shared server move around a little with load, which is normal.

## Table-by-table map

| Paper table | What it shows | Files |
|---|---|---|
| **VII** | ML-KEM-1024 on the STM32 microcontroller | `STM32F407 Microcontroller/` , the serial log (`STM32F407 Benchmarks.txt`) has all 20 runs, plus photos, a video, and the wiring diagram |
| **VIII-a** | End-to-end latency, localhost | `KEM-BM/kem_aes_liboqs.txt` (the envelope encrypt/decrypt timings per file size) |
| **VIII-b** | End-to-end latency, Karachi to the server | `Hardware Comparison Benchmarks/i9-14900HX/` , each file has the full Server-KEM / AES / Network / End-to-End breakdown |
| **VIII-c** | ML-KEM-1024 vs X25519 | `KEM-Comparison/mlkem_vs_x25519.txt` and `.csv` |
| **VIII-d** | AES-256-GCM throughput | `KEM-BM/kem_aes_liboqs.txt` (the envelope numbers give the throughput) |
| **VIII-e** | Client-side encryption across three machines | `Hardware Comparison Benchmarks/` , the `Enc_*`/`Dec_*` files for i9, Ryzen, and i5 |
| **VIII-f** | ML-DSA-87 signing cost | `ML-DSA/mldsa_benchmark.txt` |
| **IX** | Key service under attack (gateway on vs off) | `T9-Attack/` (the four attack runs) and `cpu-captures/` (server CPU during the runs) |
| **X** | Cost comparison | External pricing from AWS, Google, and Hetzner. Nothing to reproduce here; the Hetzner figure is just what the server actually costs |
| **VI** | Software versions | `Version-Info/pip-freeze-kms.txt` , the exact versions the live server ran |
| PQ-TLS (Sec. XI-F) | Server negotiates post-quantum TLS | `PQ-TLS/pq-tls-verification.txt` |

## The scripts

`Scripts/` has the four programs that produced the data:

- `benchmark_kem.py` , KEM operations plus AES envelope timings across file sizes.
- `compare_kem_classical.py` , ML-KEM-1024 against X25519.
- `bench_mldsa.py` , ML-DSA-87 keygen, sign, and verify.
- `attack_harness.py` , the flood generator used for the Table IX attack runs.

## A note on the hardware-comparison files

Those `.txt` files were saved on Windows, so they're UTF-16 encoded. If they look odd in a plain text tool, open them in something that reads UTF-16, or just note the numbers are the same either way. The original test payloads (the large `.bin` files) aren't included, they were just random data and would have made this repo several gigabytes for no reason. Regenerate them with any file of the right size if you want to re-run.
