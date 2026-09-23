# Capture finalization measurements

HTTP/1 interception completes capture finalization before reading its next
request. HTTP/2 and the provider gateway finalize captures before returning from
the handler. For gzip bodies, ADR 0095-chunked-body-envelope requires a second
pass that decrypts the captured wire bytes, decompresses them, and encrypts the
decoded file while preserving a raw fallback if decoding fails.

## Reproduce

```sh
go test ./internal/mitm -run '^$' -bench '^BenchmarkBodyCaptureFinish$' -benchmem -benchtime=20x -count=3
```

The benchmark uses temporary on-disk encrypted captures, a MemoryKeyWrapper,
and entirely synthetic repeated-byte bodies. Initial compression, capture file
creation, body writes, and final file removal are outside timing. Only Finish
is measured, including closing stage one and normalizing gzip where applicable.
The fixture is highly compressible and does not represent typical compression
ratios or production keychain latency. Measurements include local filesystem
behavior and were not collected under controlled disk contention.

Apple M2 Pro, darwin/arm64, 2026-09-23; medians of three 20-iteration runs:

| Expanded bytes | Identity Finish | Gzip Finish | Gzip allocated bytes/op |
| ---: | ---: | ---: | ---: |
| 1 MiB | 0.468 ms | 1.039 ms | 399,496 |
| 16 MiB | 1.341 ms | 11.59 ms | 418,696 |

A validation rerun on the same host measured 1.02/1.55 ms for 1 MiB
identity/gzip and 2.79/13.53 ms for 16 MiB, illustrating filesystem/host timing
variability. Allocation counts and volumes were unchanged.

For this 16 MiB fixture, gzip adds approximately 10 ms of synchronous finishing
work. The limited allocation growth is consistent with the intended chunked
pipeline. Allocated bytes are not a peak-memory measurement. These results
establish a measurable cost, not a production tail-latency or contention problem.

## Decision for this review

Retain the synchronous implementation. There is insufficient evidence that
normalization dominates real requests to justify changing capture ownership,
shutdown, retention, and failure handling. An asynchronous pipeline would need a
bounded queue, a durable raw-capture state, atomic row updates, cleanup/retention
coordination, explicit saturation behavior, and a drain/cancellation contract.
A goroutine around Finish would not establish those guarantees.

If real request completion or HTTP/1 follow-up latency is problematic, profile
that path under representative compressed payloads and storage contention. Use
this benchmark to isolate normalization cost, then record a separate ADR before
introducing an asynchronous lifecycle. Preserve encrypted raw fallback and
bounded memory throughout; do not discard the two-stage contract as a speed fix.
