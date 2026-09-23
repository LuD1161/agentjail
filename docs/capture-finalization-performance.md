# Capture finalization measurements

HTTP/1 interception completes capture finalization before reading its next
request. HTTP/2 and the provider gateway finalize captures before returning from
the handler. For gzip bodies, ADR 0095-chunked-body-envelope requires a second
pass that decrypts the captured wire bytes, decompresses them, and encrypts the
decoded file while preserving a raw fallback if decoding fails.

## Reproduce

```sh
go test ./internal/mitm -run '^$' -bench '^BenchmarkBodyCaptureFinish$' -benchmem -benchtime=3x -count=3 -cpu=1
```

The benchmark uses temporary on-disk encrypted captures, a MemoryKeyWrapper,
and two synthetic bodies: repeated bytes and deterministic JSONL with changing
IDs, token counts, paths, and messages. Sizes are 1, 16, and 64 MiB. Each finished
capture is decrypted and checked for its full length and SHA-256 digest outside
timing. Initial compression, capture creation, writes, verification, and removal
are excluded. Only `Finish` is timed, including closing stage one and normalizing
gzip. Identity throughput therefore does not measure writing the whole body.

Apple M2 Pro, darwin/arm64, Go 1.26.3, 2026-09-23; medians of three runs with
three iterations each, GOMAXPROCS=1. These replace the preliminary repeated-byte
measurements. No production optimization was applied.

| Fixture | Expanded size | Expansion ratio | Identity Finish | Gzip Finish | Gzip allocated bytes/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| Repeated | 1 MiB | 993x | 0.096 ms | 1.077 ms | 399,496 |
| Repeated | 16 MiB | 1,027x | 2.264 ms | 14.281 ms | 418,696 |
| Repeated | 64 MiB | 1,028x | 1.656 ms | 46.573 ms | 480,136 |
| Synthetic JSONL | 1 MiB | 6.47x | 0.082 ms | 3.036 ms | 402,160 |
| Synthetic JSONL | 16 MiB | 6.52x | 0.398 ms | 42.995 ms | 455,936 |
| Synthetic JSONL | 64 MiB | 6.54x | 0.400 ms | 170.559 ms | 610,664 |

The JSONL fixture makes gzip finalization roughly three times more expensive
than repeated bytes at 16–64 MiB. For JSONL, the three run means ranged from
2.93–3.09 ms, 42.80–43.76 ms, and 169.71–174.69 ms respectively. Repeated-byte
64 MiB runs ranged from 45.25–59.27 ms. Identity results vary with filesystem
behavior and should not be interpreted as proportional to body size.

Allocation volume grows much more slowly than expanded payload size, consistent
with chunked processing, but is not peak heap or RSS. This synthetic fixture is
not a production payload distribution, and the in-memory key wrapper excludes
platform keychain behavior. No controlled storage contention was introduced.
Full methodology and raw measurements are in
[the measurement report](performance-measurements-20260923.md).

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
