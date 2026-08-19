# HDKEM Artifact

Reference implementation and benchmarking code for **HDKEM**, a hybrid key-establishment prototype combining:

- **ML-KEM-768** for post-quantum KEM key material;
- **X25519** for classical Diffie–Hellman key material;
- an optional external/source-derived secret `k3`;
- a **split-key PRF** based on SHAKE256;
- a selectable two-member ring signature:
  - `gandalf`
  - `falconrs`
- **Ascon-128a** for Finished-message protection and, in `hide` mode, signature confidentiality.

The artifact provides three executables:

- `hdkem_server` — server endpoint and server-side measurements;
- `hdkem_client` — client endpoint and client-side measurements;
- `hdkem_bench` — standalone primitive microbenchmarks and wire accounting.

> **Artifact scope.** This code is a research prototype intended for reproducibility and performance evaluation. It is not a production TLS/AKE implementation.

---

## 1. Protocol Modes

The endpoints support three modes through `-m`:

| Mode | Source secret `k3` | Ring-signature handling |
|---|---:|---|
| `src` | Yes | Client signature is sent in the clear |
| `sourceless` | No | Server authenticates its initial hello; client signature is sent in the clear |
| `hide` | Yes | Client signature is encrypted under a key derived by HDKEM |

The source-backed modes use a public 16-byte source identifier `kid3` and a secret source value `k3`. The identifier is included in the authenticated transcript; `k3` itself is not placed on the wire.

The split-key PRF combines the available secret inputs with the transcript:

```text
k1 = ML-KEM shared secret
k2 = X25519 shared secret
k3 = optional source-derived secret

OKM = SHAKE256(
    "HDKEM-v1-skPRF" ||
    LV(k1) || LV(k2) || LV(k3) || LV(tau)
)
```

For `src` and `sourceless`, the artifact derives 64 output bytes. For `hide`, it derives 96 bytes so that an additional encryption key is available.

---

## 2. Cryptographic Components

### ML-KEM-768

ML-KEM-768 is provided through **liboqs**.

Canonical sizes used by the artifact:

```text
public key      1184 B
secret key      2400 B
ciphertext      1088 B
shared secret     32 B
```

### X25519

X25519 contributes the classical shared secret:

```text
public key        32 B
secret key        32 B
shared secret     32 B
```

### Ring signatures

Two two-member ring-signature implementations are selectable with `-r`.

#### Gandalf

```text
verification key   896 B
secret key        1281 B
signature         1236 B
```

The artifact implements the algebra and wire format of the two-member Gandalf construction, but the runnable backend uses PQClean Falcon-512 NTRU key generation/preimage sampling as a compatibility backend.

**Important:** the concrete Gandalf instantiation in the paper uses Antrag `TpdGen` and MitakaZ `PreSmp`. Therefore, results from this artifact should not be described as bit-for-bit reproduction of the Antrag+MitakaZ implementation.

#### FalconRS

```text
verification key   897 B
secret key        1281 B
signature         1288 B
```

The artifact contains its own implementation of FalconRS Algorithm 8 over Falcon-512 primitives.

**Important:** this implementation has not been established as byte-for-byte equivalent to the authors' reference implementation. Performance numbers should therefore be described as measurements of **this artifact's FalconRS implementation**, not as reproduction of the reference implementation.

### Ascon-128a

Ascon-128a is used for:

1. the server Finished message;
2. the client Finished message;
3. encryption of the client ring signature in `hide` mode.

HDKEM internally derives 32-byte logical `k_cf` / `k_enc` values, while Ascon-128a consumes the first 16 bytes as its AEAD key.

---

## 3. Source Interface

The protocol exposes an explicit source interface using:

```text
(kid3, k3)
```

where:

- `kid3` is a public 16-byte identifier;
- `k3` is a 32-byte or 48-byte secret selected with `-b`.

For artifact testing, `k3` is deterministically derived from a shared 48-byte file:

```text
source_master.bin
```

using SHAKE256 and `kid3`.

This is a **PSK-backed emulator of `Src.Get` / `Src.GetWithID`**. It is not a QKD implementation. A deployment using QKD or another external secret source should replace this emulator while preserving the `(kid3, k3)` interface.

---

## 4. Source Files

A minimal source tree should contain:

```text
.
├── hdkem_bench.c
├── hdkem_client.c
├── hdkem_server.c
├── hdkem_primitives.c
├── hdkem_primitives.h
├── hdkem_wire.h
└── <PQClean Falcon-512 clean source files>
```

`hdkem_primitives.c` directly includes Falcon/PQClean source headers and C files such as:

```text
inner.h
api.h
codec.c
common.c
fft.c
fpr.c
keygen.c
rng.c
sign.c
vrfy.c
pqclean.c
```

These files therefore need to be available on the compiler include path in the layout expected by `hdkem_primitives.c`.

If you downloaded the files from ChatGPT with names such as `hdkem_client(6).c`, rename them to the canonical names used by the `#include` directives:

```bash
mv 'hdkem_client(6).c'     hdkem_client.c
mv 'hdkem_server(6).c'     hdkem_server.c
mv 'hdkem_bench(4).c'      hdkem_bench.c
mv 'hdkem_primitives(7).c' hdkem_primitives.c
mv 'hdkem_primitives(6).h' hdkem_primitives.h
mv 'hdkem_wire(5).h'       hdkem_wire.h
```

---

## 5. Dependencies

The current source requires:

- a C compiler with C11 support;
- **liboqs** with ML-KEM-768 enabled;
- **libsodium**;
- **OpenSSL libcrypto**;
- the **PQClean Falcon-512 clean** source files used by `hdkem_primitives.c`;
- the standard math library (`libm`);
- POSIX sockets for the client/server programs.

On Linux, the final link step will normally require at least:

```text
-loqs -lsodium -lcrypto -lm
```

The exact include/library paths depend on how liboqs and the Falcon/PQClean source tree are installed.

---

## 6. Building

A Makefile was not included with the supplied source files, so the exact build command depends on the local liboqs/PQClean layout.

A typical build has the following form:

```bash
cc -O3 -std=c11 -Wall -Wextra \
   -I/path/to/liboqs/include \
   -I/path/to/falcon512-clean \
   hdkem_primitives.c hdkem_server.c \
   -L/path/to/liboqs/lib \
   -loqs -lsodium -lcrypto -lm \
   -o hdkem_server

cc -O3 -std=c11 -Wall -Wextra \
   -I/path/to/liboqs/include \
   -I/path/to/falcon512-clean \
   hdkem_primitives.c hdkem_client.c \
   -L/path/to/liboqs/lib \
   -loqs -lsodium -lcrypto -lm \
   -o hdkem_client

cc -O3 -std=c11 -Wall -Wextra \
   -I/path/to/liboqs/include \
   -I/path/to/falcon512-clean \
   hdkem_primitives.c hdkem_bench.c \
   -L/path/to/liboqs/lib \
   -loqs -lsodium -lcrypto -lm \
   -o hdkem_bench
```

Adjust the include/library paths to match the local installation.

---

## 7. One-Time Setup

The client and server each need their own ring-signature key pair. The public verification keys must then be exchanged out of band.

### Gandalf

Generate the server key pair:

```bash
./hdkem_server --gen -r gandalf
```

This creates:

```text
server.rvk
server.rsk
```

Generate the client key pair:

```bash
./hdkem_client --gen -r gandalf
```

This creates:

```text
client.rvk
client.rsk
```

Each endpoint must have:

```text
server.rvk
client.rvk
```

and only its own secret key.

### FalconRS

Use the same process with:

```bash
./hdkem_server --gen -r falconrs
./hdkem_client --gen -r falconrs
```

Do not mix key files generated for `gandalf` with an execution using `-r falconrs`, or vice versa.

---

## 8. Provisioning the Source Secret

`src` and `hide` mode require the same `source_master.bin` at both endpoints.

Generate it once:

```bash
./hdkem_server --source-gen
```

or:

```bash
./hdkem_client --source-gen
```

Then provision the resulting:

```text
source_master.bin
```

to the peer.

Do **not** independently run `--source-gen` on both machines. The two endpoints must use the same source-master value.

`sourceless` mode does not require this file.

---

## 9. Running the Protocol

The default endpoint settings are:

```text
host         127.0.0.1       client
port         8443
repetitions  100
mode         src
source size  48 B
ring scheme  gandalf
```

### Example: source-backed mode

Start the server:

```bash
./hdkem_server -m src -b 32 -n 500 -r falconrs
```

Then run the client:

```bash
./hdkem_client -h 127.0.0.1 -p 8443 \
    -m src -b 32 -n 500 -r falconrs
```

### Example: sourceless mode

Server:

```bash
./hdkem_server -m sourceless -n 500 -r falconrs
```

Client:

```bash
./hdkem_client -h 127.0.0.1 \
    -m sourceless -n 500 -r falconrs
```

No `source_master.bin` is required.

### Example: hidden-signature mode

Server:

```bash
./hdkem_server -m hide -b 32 -n 500 -r falconrs
```

Client:

```bash
./hdkem_client -h 127.0.0.1 \
    -m hide -b 32 -n 500 -r falconrs
```

In this mode, the client ring signature is encrypted with the derived `k_enc`.

---

## 10. Command-Line Options

### `hdkem_server`

```text
./hdkem_server --gen
./hdkem_server --source-gen
./hdkem_server [options]
```

Options:

```text
-p <port>                    TCP port; default 8443
-n <reps>                    number of protocol executions; default 100
-m src|sourceless|hide       protocol mode
-b 32|48                     source-secret size
-r gandalf|falconrs          ring-signature implementation
```

### `hdkem_client`

```text
./hdkem_client --gen
./hdkem_client --source-gen
./hdkem_client [options]
```

Options:

```text
-h <host>                    server IPv4 address; default 127.0.0.1
-p <port>                    server TCP port; default 8443
-n <reps>                    number of protocol executions; default 100
-m src|sourceless|hide       protocol mode
-b 32|48                     source-secret size
-r gandalf|falconrs          ring-signature implementation
-o <csv>                     write client timing samples to CSV
```

### `hdkem_bench`

```text
./hdkem_bench [-n reps] [-b 32|48] [-r gandalf|falconrs]
```

Examples:

```bash
./hdkem_bench -n 2000 -b 32 -r falconrs
./hdkem_bench -n 2000 -b 32 -r gandalf
```

The benchmark attempts to pin itself to CPU core 0 on Linux to reduce scheduling noise.

---

## 11. What Is Measured

### Standalone microbenchmark

`hdkem_bench` reports median, 5th percentile, and 95th percentile timings for:

```text
ML-KEM keygen
ML-KEM encaps
ML-KEM decaps
X25519 keygen
X25519 DH
<scheme> keygen
<scheme> sign
<scheme> verify(valid)
Src.GetWithID derive
split-key PRF
Ascon-128a op
```

Each result is printed in milliseconds.

Example format:

```text
ML-KEM encaps             med   0.xxxx ms  p05   0.xxxx  p95   0.xxxx  n=2000
falconrs sign             med   x.xxxx ms  p05   x.xxxx  p95   x.xxxx  n=2000
```

### End-to-end client/server measurements

The endpoints separately record the relevant protocol operations and total elapsed time, including socket I/O.

The client measures operations including:

```text
X25519 keygen
ML-KEM encaps
X25519 DH
Src.Get                 source-backed modes only
split-key PRF
ring-signature sign
Finished AEAD
client total including I/O
```

The server measures operations including:

```text
ephemeral keygen
ring-signature verify
ML-KEM decaps
X25519 DH
Src.GetWithID           source-backed modes only
split-key PRF
Finished AEAD
server total including I/O
```

---

## 12. Wire Accounting

The artifact computes the protocol's expected application-layer wire size explicitly.

The transcript is:

```text
tau =
    pkS1 ||
    c ||
    pkC2 ||
    pkS2 ||
    <IDC> ||
    <IDS> ||
    mode ||
    <kid3>
```

where `kid3` is present only in source-backed modes.

The four protocol frames are:

```text
1. Server Hello
2. Client authentication / key-establishment message
3. Server Finished
4. Client Finished
```

Each frame uses a four-byte framing header.

The output reports:

```text
wire hello payload
wire client-auth payload
wire server-Finished payload
wire client-Finished payload
wire protocol payload total
wire frame headers
wire TCP application bytes
```

The two Finished ciphertexts protect:

```text
label || tau
```

rather than only a short confirmation tag. For this reason, the full end-to-end byte count is larger than a one-flight cryptographic-size sum.

Ring verification keys are provisioned out of band and are **not** included in the measured protocol wire total.

---

## 13. Suggested Reproduction Commands

For the configuration used in the paper-style FalconRS measurements:

```bash
./hdkem_bench -n 2000 -b 32 -r falconrs
```

For end-to-end source mode:

```bash
# terminal 1
./hdkem_server -m src -b 32 -n 500 -r falconrs

# terminal 2
./hdkem_client -h 127.0.0.1 -p 8443 \
    -m src -b 32 -n 500 -r falconrs
```

To save the client-side samples:

```bash
./hdkem_client -h 127.0.0.1 -p 8443 \
    -m src -b 32 -n 500 -r falconrs \
    -o client_falconrs_src.csv
```

For a fair comparison between schemes, keep the machine, compiler flags, source size, number of repetitions, mode, and network configuration fixed:

```bash
./hdkem_bench -n 2000 -b 32 -r gandalf
./hdkem_bench -n 2000 -b 32 -r falconrs
```

---

## 14. Key Files

| File | Purpose | Provisioning |
|---|---|---|
| `server.rsk` | server ring-signature secret key | server only |
| `server.rvk` | server ring verification key | both peers |
| `client.rsk` | client ring-signature secret key | client only |
| `client.rvk` | client ring verification key | both peers |
| `source_master.bin` | source emulator master secret | both peers in `src` / `hide` |

The artifact reads these files using exact expected lengths, so stale key files from another ring scheme can cause startup failure.

---

## 15. Security and Implementation Notes

This repository should be interpreted as an **experimental artifact**, not as production cryptographic software.

In particular:

1. The built-in source provider is a PSK-backed emulator. It does not implement QKD.
2. The Gandalf path is a runnable Figure-5-compatible implementation using a PQClean Falcon-512 backend, not the paper's Antrag+MitakaZ concrete backend.
3. The FalconRS path is this artifact's implementation of Algorithm 8 and should not be presented as the authors' reference implementation without a separate cross-check.
4. The ring is intentionally fixed to **two members**.
5. Some Gaussian/rejection-sampling code is designed for experimental correctness and benchmarking rather than constant-time production use.
6. Endpoint identities are currently compiled into the programs as:

```text
server: SubstationServer001
client: SmartMeterClient042
```

7. The protocol runs directly over TCP with a small application framing layer. It is not TLS.
8. Secret ephemeral material is explicitly cleared with `sodium_memzero()` at the end of protocol executions where implemented.

---

## 16. Troubleshooting

### `missing ring keys`

Generate both endpoint key pairs and exchange the `.rvk` files:

```bash
./hdkem_server --gen -r falconrs
./hdkem_client --gen -r falconrs
```

Both sides then need:

```text
server.rvk
client.rvk
```

as well as their own `.rsk`.

### `missing source_master.bin`

For `src` or `hide`, generate the file once:

```bash
./hdkem_server --source-gen
```

and copy exactly that file to the peer.

### `-b must be 32 or 48`

Only these source sizes are accepted:

```text
-b 32
-b 48
```

### Handshakes fail immediately

Check that:

- client and server use the same `-m`;
- client and server use the same `-b` for source-backed modes;
- client and server use the same `-r`;
- the `.rvk`/`.rsk` files correspond to the selected ring scheme;
- both source-backed endpoints have the same `source_master.bin`;
- the client is connecting to the correct IPv4 address and port.

### `setup failed` in the benchmark

Verify that the selected ring-signature backend is correctly compiled together with the required Falcon/PQClean sources and that liboqs/libsodium are initialized correctly.

---

## 17. Reproducibility Notes

When collecting results for a paper or artifact evaluation:

- build with the same optimization level on all runs;
- record compiler and library versions;
- use the same `-n`, `-b`, `-m`, and `-r` settings;
- avoid mixing results from different ring implementations;
- distinguish primitive microbenchmarks from end-to-end timing;
- report that end-to-end `total incl I/O` includes socket communication;
- report protocol payload separately from the four 4-byte frame headers;
- retain the raw CSV output when using the client's `-o` option;
- repeat measurements on an otherwise idle machine when possible.

The standalone benchmark pins itself to CPU core 0 on Linux, but the client and server executables do not automatically provide a complete controlled-system benchmarking environment.

---

## 18. Citation / Publication Wording

When describing this artifact in a paper, wording along the following lines is appropriate:

> We evaluate an HDKEM prototype combining ML-KEM-768, X25519, an optional source-derived secret, a SHAKE256 split-key PRF, and a selectable two-member ring-signature implementation. The source interface is emulated with a shared master secret for controlled benchmarking. Our Gandalf-compatible implementation follows the construction's algebra and wire format while using a PQClean Falcon-512 compatibility backend rather than the concrete Antrag+MitakaZ backend. Our FalconRS measurements use our implementation of Algorithm 8 and are not presented as measurements of the authors' reference code.

Avoid claiming:

- that `source_master.bin` is QKD;
- that the Gandalf implementation is a bit-for-bit Antrag+MitakaZ reproduction;
- that the FalconRS implementation has been reference-equivalence validated unless that validation is performed separately.

---

## 19. License

No license file was included in the supplied source set. Add the intended project license before public release or redistribution.

---

## 20. Repository Status

The supplied code identifies the wire protocol as **HDKEM artifact version 8**. Some source comments refer to later primitive-file revisions; for reproducible releases, tag the repository and keep the endpoint, wire, and primitive files from one consistent snapshot.
