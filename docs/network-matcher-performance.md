# Network matcher evaluation

Path regexes and reason/impact templates compile when policy packs load. Each
evaluation serializes its payload at most once and renders only the winning
rule. Caches belong to the loaded rule or one evaluation; no request content is
retained between operations. Existing precedence, severity ties, case handling,
scan output, invalid-regex skips, and literal fallback for invalid reason/impact
templates remain unchanged. Header scan ordering is unchanged.

## Reproduce

```sh
go test ./internal/netpolicy -run '^$' -bench BenchmarkMatcherEvaluate -benchmem -count=3
go test -race ./internal/netpolicy/...
```

The benchmark uses matching regex paths, templated reasons/impacts, and one or
eight overlapping payload rules. Timings below are medians of three local runs
on an Apple M2 Pro, darwin/arm64, 2026-09-23; the baseline is commit f766ac89
with the same benchmark. Concurrent host work caused outliers, so these are
indicative measurements, not production latency guarantees.

| Payload / rules | Before | After | Allocations before / after |
| --- | ---: | ---: | ---: |
| 128 B / 1 | 8.34 us | 1.44 us | 160 / 22 |
| 128 B / 8 | 77.8 us | 2.73 us | 1280 / 43 |
| 1 MiB / 1 | 1.24 ms | 1.21 ms | 167 / 32 |
| 1 MiB / 8 | 10.08 ms | 1.55 ms | 1337 / 52 |

For eight rules and a 1 MiB payload, median allocation volume decreased from
23.2 MB/op to 3.23 MB/op. One-rule large-body throughput changes little because
JSON serialization already dominates that workload; allocation volume there
varies with the JSON encoder pool and did not improve in this run.
