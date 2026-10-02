#!/usr/bin/env python3
import sys

counts = {
    "failed_login": 0,
    "successful_login": 0
}

for line in sys.stdin:
    key, value = line.strip().split()
    counts[key] += int(value)

for k, v in counts.items():
    print(f"{k}: {v}")
