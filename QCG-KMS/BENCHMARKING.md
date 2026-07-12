# Benchmarking QCG KMS (ML-KEM-1024)

This guide explains how to produce clean, defensible performance numbers for
the cryptography in QCG KMS, suitable for a research paper. It covers what to
measure, how to avoid the two common mistakes (network noise and pure-Python
numbers), and the exact commands.

## What to measure, and where

There are two very different questions, and they need different setups:

1. How fast is the post-quantum cryptography itself?
   Measure this with NO network and NO HTTP, directly on the machine, using the
   `scripts/benchmark_kem.py` tool. This isolates keygen, encapsulate, and
   decapsulate (plus AES-256-GCM for a range of payload sizes). These are the
   numbers that belong in an algorithm-comparison table.

2. What does a real client experience end to end?
   Measure this with the `qcg ... --bench` flag from a client machine. It breaks
   the time into Server KEM, Local File Crypto (AES), Network, and total. This
   shows the practical experience, including network latency.

Keep the two separate in the paper. Do not report end-to-end numbers as if they
were crypto numbers: if the client is in one country and the server in another,
the network can be 100 ms or more while the crypto is under 10 ms, so end-to-end
mostly measures distance, not the algorithm.

## Backend matters: liboqs vs kyber-py

ML-KEM-1024 is implemented by two interchangeable backends:

- liboqs: the Open Quantum Safe C library. Fast, side-channel hardened, and what
  a production system or a serious benchmark should use.
- kyber-py: a pure-Python implementation. Portable and the default, but much
  slower because Python is interpreted. Useful only as a portable reference or
  to show the contrast.

For paper-grade numbers, install liboqs (see HOSTING.md, "Installing liboqs")
and benchmark both. Reporting only the pure-Python numbers as headline figures
is not representative of real PQC performance and will not hold up under review.

Every encrypted file and every datakey response records which backend produced
it (`kem_backend`), so results are always attributable. Check any file with:

```bash
qcg info myfile.qcg
```

## Pure-crypto benchmark (the main paper data)

Run on the machine where the backend(s) are installed (ideally the server):

```bash
cd ~/qcg
. .venv/bin/activate
python scripts/benchmark_kem.py --iterations 100 --backends liboqs \
    --sizes 1MB 10MB 100MB --csv kem_results.csv
```

What it does:

- Runs the chosen backends (skips any that are not installed, with a clear
  message).
- Times keygen, encapsulate, and decapsulate separately, over `--iterations`
  repetitions (default 50).
- Times AES-256-GCM encrypt/decrypt for each payload size. The AES stage runs a
  smaller number of times, set by `--aes-iterations` (default: the lesser of
  `--iterations` and 10), because large-file AES timing is stable and does not
  need as many repetitions as the tiny KEM operations.
- Generates each test buffer once per size and reuses it, so large sizes
  measure cleanly and quickly.
- Discards one warm-up iteration, then reports min, mean, median, stdev, max.
- Writes a CSV you can drop straight into a paper table or a plot.

Practical guidance:

- For the KEM numbers, use liboqs (the production C backend) with 100 or more
  iterations for stable means. The pure-Python `kyber_py` backend is far slower,
  so benchmark it separately with fewer iterations and only small sizes when you
  want a portable-reference contrast row.
- For very large files (500 MB, 1 GB) keep `--aes-iterations` low (for example
  3 to 5); the per-size AES time is stable, so a handful of runs is enough and
  avoids long waits and large memory use. Example:

```bash
python scripts/benchmark_kem.py --iterations 100 --backends liboqs \
    --sizes 500MB 1GB --aes-iterations 5 --csv kem_results_large.csv
```

Run a couple of times to confirm the numbers are repeatable, and close other
heavy processes first.

## Classical baseline: ML-KEM-1024 vs X25519

To answer the inevitable reviewer question ("why post-quantum and not classical
or hybrid?"), compare the post-quantum KEM against a classical X25519
key-establishment, like-for-like:

```bash
python scripts/compare_kem_classical.py --iterations 1000 --csv compare.csv
```

This is a standalone measurement. It does not modify the KMS in any way; it only
times the two algorithms side by side. The X25519 path is a proper KEM
construction (ephemeral keygen + ECDH + HKDF-SHA256), timed as one unit, against
ML-KEM-1024 encapsulate timed as one unit, so the comparison is fair. The script
reports the delta and states whether the post-quantum KEM is faster or slower.

The result depends heavily on the ML-KEM implementation. With the pure-Python
`kyber_py` backend, ML-KEM is much slower than X25519 (lattice work in
interpreted Python). With the production C backend (liboqs), ML-KEM-1024 is
competitive with X25519 and often faster for encapsulation. Either way the
defensible claim holds: the post-quantum key operation is at most a fraction of
a millisecond different from classical, which is negligible against a real-world
network round-trip of 100 ms or more. Run the comparison with liboqs for the
headline number, and optionally with `kyber_py` to show the portable-reference
contrast.

## End-to-end client benchmark (real-world experience)

From the client machine, with a configured `qcg`:

```bash
qcg encrypt test_10MB.bin --key bench-key --bench
qcg decrypt test_10MB.bin.qcg --bench
```

The output separates:

- Server KEM: the post-quantum operation on the server.
- Local File Crypto: AES-256-GCM on the file, on the client.
- Network (key request round-trip): time on the wire (total minus the two
  above). Only the small wrapped-key request crosses the network, never the
  file, so this is latency-bound and roughly constant regardless of file size.
- End-to-End: total wall-clock.
- KEM backend, and the client machine's specs (CPU, cores/threads, RAM, GPU).

To repeat it many times and capture the output (PowerShell example):

```powershell
1..30 | ForEach-Object {
    .\dist\qcg.exe encrypt test_10MB.bin --key bench-key --bench
} | Out-File bench_runs.txt -Append
```

## Making test files

Linux/macOS:

```bash
for s in 1024 1048576 10485760 104857600; do
    head -c $s /dev/urandom > test_$s.bin
done
```

Windows (PowerShell):

```powershell
fsutil file createnew test_1KB.bin 1024
fsutil file createnew test_1MB.bin 1048576
fsutil file createnew test_10MB.bin 10485760
fsutil file createnew test_100MB.bin 104857600
```

## A clean methodology for the paper

1. Install liboqs on the server; confirm it is active with `curl .../api/about`.
2. Run `scripts/benchmark_kem.py` with `--backends liboqs` and 100+ iterations
   for the KEM stages, on small-to-medium sizes (1MB 10MB 100MB), with CSV out.
   This is your primary "cost of ML-KEM-1024" data.
3. For large files (500MB, 1GB), run a separate pass with `--aes-iterations` set
   low (3 to 5); the per-size AES time is stable so a few runs suffice.
4. For a portable-reference contrast, run `--backends kyber_py` separately with
   fewer iterations and small sizes only (pure-Python is far slower).
5. Run `scripts/compare_kem_classical.py --backends liboqs` for the ML-KEM vs
   X25519 classical-baseline table.
6. Separately, run `qcg ... --bench` from the client for the end-to-end story,
   clearly labeled with the client and server locations.
7. Report server-side (pure-crypto) numbers for the algorithm comparison; report
   end-to-end numbers separately as the deployment experience.
8. State the exact stack: liboqs version, kyber-py version, CPU, RAM, OS. The
   benchmark script prints Python and the CLI `--bench` prints full machine
   specs; record both.
