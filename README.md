# Quantum Cloud Guard (QCG)

This is the code and data behind the QCG paper: a self-hosted, post-quantum key management service built for small businesses that want to keep their own keys instead of handing them to a cloud provider.

The idea is simple. Your data sits in the cloud, but the keys that unlock it never leave a small server you control. Files are encrypted on your own machine before they go up, and only a tiny wrapped key ever touches the server. Even if someone steals everything in the cloud, they get nothing they can read, and they stay safe even against a future quantum computer.

## What's in here

Four folders:

- **QCG-KMS** , the key management service itself. Generates and stores the post-quantum keys (ML-KEM-1024), encrypts data with AES-256-GCM, signs the public keys it hands out (ML-DSA-87) so nobody can swap in a fake one, and comes with a web console and a command-line tool. This is the heart of the project.

- **Sentinel-Gate-QCG** , the gatekeeper that sits in front of the key service. It handles rate limiting, blocks brute-force and credential-stuffing attempts, and soaks up floods of junk traffic before they reach the keys. It runs inside the key service as middleware, not as a separate server.

- **QCG-CLI-Kit** , a standalone version of the command-line tool that builds into a single `.exe`, so an employee can encrypt and decrypt files without installing Python or anything else.

- **Benchmarks** , all the raw measurement data behind every table and number in the paper. See the README inside that folder for what backs which table.

## How the two main parts fit together

They're two separate projects that join up when they run. The key service installs the gateway into its own environment and loads it as middleware, so a request comes in, passes through the gateway's checks, and only then reaches the key logic. Two codebases on disk, one process at runtime.

The live system runs behind Caddy (which handles HTTPS and, by default, negotiates post-quantum TLS too), so the protection is post-quantum at both layers: the connection and the data itself.

## The crypto, in one line each

- **ML-KEM-1024** (FIPS 203) protects the key. Formerly called Kyber.
- **AES-256-GCM** encrypts the actual data.
- **ML-DSA-87** (FIPS 204) signs the public keys so you know they're really yours. Formerly called Dilithium.
- **Argon2id** protects the master key that seals everything at rest.

Both projects use the real, fast liboqs library in production, with pure-Python fallbacks (kyber-py, dilithium-py) so the code runs anywhere even without the compiled library.

## Running it

Each project has its own README with setup steps. The short version:

- KMS: `pip install -e .` inside `QCG-KMS`, then follow its README. Tests: `pytest`.
- Sentinel Gate: same, inside `Sentinel-Gate-QCG`.
- CLI kit: run `BUILD.ps1` (Windows) or `build.sh` to produce the standalone tool.

## Reproducing the paper's numbers

The scripts that produced the benchmarks live in `Benchmarks/Scripts`, and every result file is in `Benchmarks`. The `Benchmarks/README.md` maps each file to the table it backs, and `Benchmarks/Version-Info/pip-freeze-kms.txt` lists the exact versions the live deployment ran, so the software stack can be matched precisely.

## Author

Muhammad Shaheer Bin Junaid

## Licence

See the LICENSE file in each project folder.
