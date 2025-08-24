# Benchmarks

No formal benchmarks exist. Informal testing on a laptop with Python 3.11 shows:
- Create and retrieve operations complete in <50ms using in-memory storage.
- Throughput limited primarily by chosen storage backend and QR generation.

## How to Run
```bash
# Run local load test with wrk
wrk -t2 -c20 -d30s http://localhost:8000/api/health
```

Monitor latency and CPU usage; consider profiling AI security regex if throughput drops.
