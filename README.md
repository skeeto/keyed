# Keyed: Linux Entropy Interception

This program intercepts a process' entropy-gathering system calls and
serves those requests from a CSPRNG (ChaCha20) seeded from a user
supplied passphrase (via Argon2). In other words, you can force
`/dev/random`, `/dev/urandom`, and `getrandom(2)` to produce
deterministic output for a specific target process.

One primary use is to force key generation derive from a passphrase even
for programs that do not support such a feature.

Requires x86-64 Linux and [libsodium][libsodium].

## Usage

*Keyed* runs the command that follows its own options, so it's as simple
as prepending `keyed` before the command to be run.

    $ keyed foobar --generate-key

In this example, `foobar` will hopefully have deterministic behavior.
You are prompted for a passphrase before the target process is started.

The `-h` option prints a list of options.

## How does it work?

*Keyed* [uses `ptrace(2)`][ptrace] to monitor and intercept system calls
made by the target program. It works at a lower level than `LD_PRELOAD`
and will still work when the target doesn't link against libc (e.g. Go
programs). However, it does make the target program run a little slower,
much like using `strace`.

If the program opens `/dev/random` or `/dev/urandom`, all reads on that
file descriptor and blocked, and instead served by the monitor program
from its CSPRNG.

All `getrandom(2)` system calls are blocked and serviced the same way.

Since `getpid(2)` is so often used as an entropy source, even for
cryptography, it's also optionally be intercepted (`-p`) to return a
configurable PID.

## Limitations

Unfortunately the technique used by *Keyed* does not work so well with
many popular cryptographic programs, such as GnuPG, OpenSSL, and OpenSSH
(e.g. `ssh-keygen`). These programs draw from many different entropy
sources, including the current time. Unfortunately time-retrieval system
calls, such as `gettimeofday(2)`, are accessed via Linux's vDSO and are
not real system calls, making them invisible to *keyed*.

A program could potentially access even more entropy sources not visible
to `ptrace(2)`, like ASLR and random stack gap.

## TODO

* Follow `fork(2)`, `vfork(2)`, and `clone(2)`.


[lib]: https://libsodium.org/
[ptrace]: https://nullprogram.com/blog/2018/06/23/
