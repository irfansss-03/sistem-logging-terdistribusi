#!/usr/bin/env python3
import sys
import json

for line in sys.stdin:
    try:
        log = json.loads(line)
        message = log.get("message", "").lower()
        if "failed" in message:
            print("failed_login\t1")
        elif "successful" in message:
            print("successful_login\t1")
    except:
        continue
