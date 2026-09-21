#!/usr/bin/python3
"""Talk to a running omarchy-chatd over its socket.

    scripts/smoke.py                      # status + rooms against the default socket
    scripts/smoke.py --socket /path.sock  # against a test daemon
    scripts/smoke.py '{"cmd":"rooms"}'    # send one request and print the reply

Start a throwaway daemon for testing with:
    omarchy-chatd --socket /tmp/chat-test.sock --data-dir /tmp/chat-test-data
"""
import json
import os
import socket
import sys


def main() -> int:
    args = sys.argv[1:]
    path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "omarchy-chat.sock")
    if args[:1] == ["--socket"]:
        path, args = args[1], args[2:]
    requests = [json.loads(a) for a in args] or [{"cmd": "status"}, {"cmd": "rooms"}]

    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    f = s.makefile("rw", encoding="utf-8")
    print("<-", f.readline().rstrip())  # greeting: current state
    for i, req in enumerate(requests, 1):
        req.setdefault("id", i)
        f.write(json.dumps(req) + "\n")
        f.flush()
        print("->", json.dumps(req))
        while True:
            line = f.readline()
            if not line:
                return 1
            print("<-", line.rstrip())
            if json.loads(line).get("id") == req["id"]:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
