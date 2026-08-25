#!/usr/bin/env python3
"""Run a command under a real PTY and print what it produced.

airlock's interactive paths cannot be exercised from a pipe: without a
controlling terminal the CLI correctly declines to attach one, so a plain
subprocess would test the non-interactive path instead. This allocates a PTY,
sets a known window size, and captures the output.

Usage: pty-probe.py <rows> <cols> <timeout-seconds> <command> [args...]
"""
import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time


def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__, file=sys.stderr)
        return 2

    rows, cols, timeout = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
    command = sys.argv[4:]

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)
        os._exit(127)

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    collected = b""
    deadline = time.time() + timeout
    finished = False

    while time.time() < deadline and not finished:
        ready, _, _ = select.select([fd], [], [], 1.0)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                # The child closed the PTY; it has exited or is about to.
                finished = True
                break
            if not chunk:
                finished = True
                break
            collected += chunk
        if os.waitpid(pid, os.WNOHANG)[0] != 0:
            # Drain whatever is still buffered before giving up the descriptor.
            for _ in range(5):
                ready, _, _ = select.select([fd], [], [], 0.3)
                if not ready:
                    break
                try:
                    more = os.read(fd, 4096)
                except OSError:
                    break
                if not more:
                    break
                collected += more
            finished = True

    if finished:
        # Reap the child so it cannot linger as a zombie.
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass

    if not finished:
        # Timed out: kill the child so the caller is not left with a stray VM.
        try:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        except OSError:
            pass
        print(collected.decode(errors="replace"))
        print("pty-probe: TIMED OUT", file=sys.stderr)
        return 1

    print(collected.decode(errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
