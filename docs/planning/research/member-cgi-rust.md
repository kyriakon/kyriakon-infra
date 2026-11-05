# Member-supplied Rust binaries on the member CGI route

For ticket #579, under the map "Wayfinder map: Member CGI" (#572). The question is what a
member has to do to run a Rust binary through the planned route, and what the route has to
supply for it. No OpenBSD host is reachable from this environment, so nothing below was run
on OpenBSD. Each claim is traced to the OpenBSD or Rust source that owns it, and the
handful of things that need a box are listed at the end.

## The short answer

Build the binary on an OpenBSD/amd64 machine running the same release as the host, using the
base system's own Rust package, then upload the result. There is no cheaper route. The rustup
toolchain has no standard library for `x86_64-unknown-openbsd`, and rustc on that target
ignores `+crt-static`, so the binary is always dynamically linked. Inside `/home/www` it then
needs the loader and the base libraries, which are the same files a base interpreter needs,
so one runtime tree serves both. A normal std program fits `stdio rpath exec`, but the current
`slowcgi` never sets exec promises, so the member's program is not pledged at all. "Base
interpreters only" does not exclude a compiled binary, because the rule names interpreters
and a compiled binary is not one.

## 1. The target has no prebuilt standard library

The rustc book page for the OpenBSD targets gives the tier and the consequence in two lines.
The page header is "Tier: 3", and the section on building programs says "Rust does not yet
ship pre-compiled artifacts for these targets"
([rustc book, openbsd](https://doc.rust-lang.org/nightly/rustc/platform-support/openbsd.html)).
The target metadata agrees, with `tier: Some(3)` and `std: Some(true)` on the spec for
`x86_64-unknown-openbsd`
([`x86_64_unknown_openbsd.rs`](https://github.com/rust-lang/rust/blob/main/compiler/rustc_target/src/spec/targets/x86_64_unknown_openbsd.rs)).
Tier 3 means the target builds and is supported by maintainers, and that the standard library
is built from source when someone builds the target, not downloaded.

That is observable on any rustup machine. On rustc 1.97.1, the command and its output:

```
$ rustup target add x86_64-unknown-openbsd
error: toolchain 'stable-aarch64-apple-darwin' has no prebuilt artifacts available for target 'x86_64-unknown-openbsd'
note: this may happen to a low-tier target as per https://doc.rust-lang.org/nightly/rustc/platform-support.html
note: you can find instructions on that page to build the target support from source
```

So `cargo build --target x86_64-unknown-openbsd` from a laptop fails at the first crate that
needs `std`. Two things are missing at once: the target's `std`, and a linker plus an OpenBSD
libc to link against.

## 2. The build story, and the one honest instruction

The port lives at `lang/rust`, not `devel/rust`; the ports tree has no rust under `devel/`
([`lang/rust/Makefile`](https://github.com/openbsd/ports/blob/master/lang/rust/Makefile)).
The current port is `rust-1.99.1`, and its main package installs `bin/cargo`, `bin/rustc` and
the standard library rlibs under `lib/rustlib/x86_64-unknown-openbsd/lib/`
([`PLIST-main`](https://github.com/openbsd/ports/blob/master/lang/rust/pkg/PLIST-main)). The
port builds rustc natively: it sets `host` and `target` to `TRIPLE_ARCH`, which is
`x86_64-unknown-openbsd` on amd64, in the generated `config.toml`, and bootstraps from a
prebuilt rustc tarball.

That gives the instruction a member can follow:

1. Use an OpenBSD/amd64 machine or VM of the same release as the host.
2. `pkg_add rust`.
3. `cargo build --release` in the project.
4. Copy `target/release/<name>` into the site tree and make it executable.

Step 1 is not optional, and not because of tooling convenience. The rustc book warns that
"all OS versions are *major* even if using X.Y notation (`6.8` and `6.9` are different major
versions) and could be binary incompatibles (with breaking changes)". Library major versions
move with each release, as section 4 shows, so a binary built on one release may not load on
another. The member rebuilds when the host is upgraded. The map already puts "running the
Rust toolchain on the box for members" out of scope, so the OpenBSD machine is the member's,
not ours.

Cross building is the second route, and it is documented but not supported in practice. The
same book page says the targets "can be cross-compiled, but LLVM might not build out-of-box",
and shows the configuration knob `cc = "$ARCH-openbsd-cc"`. A cross build needs two things
this repository has never had: a C toolchain that emits OpenBSD ELF, and an OpenBSD sysroot.
The release file sets supply the sysroot pieces, since `comp80.tgz` is "The compiler
collection, headers and libraries"
([OpenBSD FAQ 4](https://www.openbsd.org/faq/faq4.html)), but assembling and maintaining one
is real work, and no part of it was exercised here.

`-Z build-std` is the third route, and it solves only half the problem. It builds `core`,
`alloc` and `std` for the target from the vendored source, which needs a nightly toolchain
and the `rust-src` component, and the rustup error above points at it. It does not supply a
linker or an OpenBSD libc, so the sysroot requirement stands. On an OpenBSD box it is also
redundant, because the port's rustc already carries `std` for the host triple.

Verdict: option 1 is the least-effort honest instruction, and it is honest only if it names
the requirement to build on the same release.

## 3. Static linking is not available, so the binary is dynamic

The OpenBSD target spec never sets a `crt_static_*` field. It sets `dynamic_linking: true`
and nothing else about linking
([`base/openbsd.rs`](https://github.com/rust-lang/rust/blob/main/compiler/rustc_target/src/spec/base/openbsd.rs)).
The defaults for those fields are `crt_static_default: false` and `crt_static_respected:
false`
([`spec/mod.rs`](https://github.com/rust-lang/rust/blob/main/compiler/rustc_target/src/spec/mod.rs#L2812-L2814)),
and the session consult reads:

```rust
pub fn crt_static(&self, crate_type: Option<CrateType>) -> bool {
    if !self.target.crt_static_respected {
        // If the target does not opt in to crt-static support, use its default.
        return self.target.crt_static_default;
    }
```

([`session.rs`](https://github.com/rust-lang/rust/blob/main/compiler/rustc_session/src/session.rs#L773-L777)).

So `-C target-feature=+crt-static` is silently a no-op on OpenBSD, and every Rust binary
carries an interpreter path and library dependencies. Forcing a static link with
`-C link-arg=-static` goes around the compiler's own bookkeeping and is outside the supported
path; it was not attempted here, and would need `libc.a` and the crt objects from the `comp`
set.

This is the opposite of the usual answer for member binaries, so it decides the chroot
contents: there is no self-contained binary to upload.

## 4. What has to exist inside /home/www, and the interpreter tree

A dynamically linked Rust binary needs three things at exec time: the loader, its own file,
and the shared libraries named in its dynamic section.

The loader is the path recorded in the ELF program header, and `ld.so(1)` describes itself as
"a self-contained, position independent program image" that is "initially loaded by the
kernel" ([ld.so(1)](https://man.openbsd.org/ld.so.1)). On OpenBSD that path is
`/usr/libexec/ld.so`, which is what the `libexec/ld.so` directory in the source tree builds
([`libexec/ld.so/Makefile`](https://github.com/openbsd/src/blob/master/libexec/ld.so/Makefile)).
One `readelf -l` on the box confirms it for a given binary, and that check was not run here.

`ld.so` finds the libraries through `LD_LIBRARY_PATH`, then `DT_RUNPATH` or `DT_RPATH`, then
the default path that `ldconfig(8)` recorded, then `/usr/lib`
([ld.so(1)](https://man.openbsd.org/ld.so.1)). The hints file at `/var/run/ld.so.hints` is a
cache, not a requirement, so a chroot without it falls through to `/usr/lib`.

Which libraries are needed. The port declares `WANTLIB-main = ${COMPILER_LIBCXX} c crypto curl m pthread ssl z`
for its own Rust binaries, and the clippy and rustfmt subpackages declare `c m pthread`
([`lang/rust/Makefile`](https://github.com/openbsd/ports/blob/master/lang/rust/Makefile)). A
member's binary is the same shape minus curl, ssl, crypto and z, unless the crate pulls them
in. In `-current` those files are `libc.so.104.0`, `libm.so.10.1` and `libpthread.so.28.1`,
from `major=104` in `libc/shlib_version`, `major=10` in `libm/shlib_version` and `major=28`
in `librthread/shlib_version` (the pthread library is built from `lib/librthread`, with
`LIB=pthread`). The numbers move between releases, which is why section 2 insists on the same
release. `ldd` on the host, run against the uploaded binary before it goes into the tree, is
the authoritative list.

Reuse of the interpreter tree works, because the requirements overlap. Every dynamically
linked program the tree already runs needs the loader and `libc`; a Rust binary adds `libm`
and `libpthread`, and nothing else unless one of its crates links more base libraries. A tree
built for `ksh` or `perl` therefore carries most of what Rust needs, and the difference is at
most those two files. The tree must be built from the host's own files, not copied from
another release, and the member needs read and execute on the binary.

One behaviour of `slowcgi` matters for a program that opens files by relative path. Before
`execve` the child splits `SCRIPT_NAME` and calls `chdir` on the script's directory, falling
back to `/` for a script at the top level
([`slowcgi.c`, `exec_cgi`](https://github.com/openbsd/src/blob/master/usr.sbin/slowcgi/slowcgi.c)).
A Rust page generator therefore starts in its own directory, not in `/`.

## 5. The pledge question, and the gap underneath it

Two answers are needed here, because the premise in the map does not hold as written.

### What a std program needs, against the promise set

`pledge(2)` starts from a whitelist per promise. The `stdio` set covers `mmap`, `mprotect`,
`munmap`, `madvise`, `getentropy`, `clock_gettime`, `gettimeofday`, `nanosleep`, `sigaction`,
`sigprocmask`, `sigaltstack`, `fcntl`, `fstat`, `read`, `write`, `poll`, `pipe`, `dup2`,
`socketpair`, `wait4`, `kqueue`, `kevent`, `getrlimit`, `issetugid` and `getpid`, among
others; `rpath` covers path traversal, `stat` and opening files for read; `exec` allows
`execve` ([pledge(2)](https://man.openbsd.org/pledge.2)). The kernel table that implements it
agrees on the entries that matter here, with `SYS_mmap`, `SYS_mprotect`, `SYS_getentropy`,
`SYS_sigaltstack`, `SYS_sigaction`, `SYS_futex` and `SYS___tfork` at `PLEDGE_STDIO`, and
`SYS___getcwd` at `PLEDGE_RPATH`
([`kern_pledge.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c)).

What a normal program does at startup stays inside that set. OpenBSD uses the signal based
stack overflow handler, which installs `sigaction` and `sigaltstack` and fills the alternate
stack from a mapping
([`stack_overflow/handler_signal.rs`](https://github.com/rust-lang/rust/blob/main/library/std/src/sys/pal/unix/stack_overflow/handler_signal.rs)).
The allocator reaches `mmap`, and `getentropy` covers hash seed randomisation. Standard output
is `write` plus `fcntl`.
`fs::read` is `open` for read plus `fstat` and `read`, and `fs::read_dir` is `getdents`, both
under `rpath`. `std::thread::spawn` works, because OpenBSD creates threads with `__tfork` and
Rust parks on `futex`, and both are `stdio`. Clock and randomness calls are `stdio`.

Three things do not fit, all of them routine in a web program:

- `fs::write`, `File::create`, `fs::remove_file` and `fs::create_dir` need `wpath` or `cpath`.
- `std::process::Command` needs `proc`, because `posix_spawn(3)` calls `fork()` on OpenBSD
  ([`posix_spawn.c`](https://github.com/openbsd/src/blob/master/lib/libc/gen/posix_spawn.c)),
  and `fork(2)` is in that promise.
- `std::net::TcpStream`, `UdpSocket` and DNS resolution need `inet` and `dns`.

Three more are worth naming because they are close to the route's job. `dlopen`, and therefore
`libloading`, fails after the loader calls `kbind`, because `mmap` with `PROT_EXEC` then
requires the `prot_exec` promise; the kernel exempts mappings made before `kbind`, which is
the window `ld.so` uses for the program's own libraries
([`pledge_protexec`](https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c)).
Stock `std::env::current_exe()` uses `sysctl` with `KERN_PROC_ARGS`, which the kernel allows
only under the `ps` promise, so it would be fatal under this set; the OpenBSD port patches
that function to call `getexecpath()` instead
([port patch](https://github.com/openbsd/ports/blob/master/lang/rust/patches/patch-library_std_src_sys_paths_unix_rs)),
so a binary built with the packaged rustc does not carry the problem. `IsTerminal` kills the
process too, because a denied `ioctl` reaches `pledge_fail` with the same effect, and pledge
allows only `FIONREAD`, `FIONBIO`, `FIOCLEX` and `FIONCLEX` by default
([pledge(2)](https://man.openbsd.org/pledge.2)).

A promise violation is not an error return. "Subsystems not listed become unavailable, and
most attempts to use operations in that subsystem result in the process being killed with an
uncatchable `SIGABRT`, delivering a core file if possible"
([pledge(2)](https://man.openbsd.org/pledge.2)). So a member's `fs::write` does not get an
`io::Error`, it aborts the request. The kernel has an `error` promise that turns violations
into `ENOSYS` instead, by returning early in `pledge_fail` when the flag is set
([`kern_pledge.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c)), but
`stdio rpath exec` does not include it.

### The promise is not inherited

The child in `exec_cgi` calls `pledge("stdio rpath exec", NULL)`, and the parent calls
`pledge("stdio rpath unix proc exec", NULL)`
([`slowcgi.c`](https://github.com/openbsd/src/blob/master/usr.sbin/slowcgi/slowcgi.c)). The
second argument is the exec promise set, and it is `NULL` in both calls, which `pledge(2)`
defines as "do not change the current value". Nothing in `slowcgi` ever passes a non-null
value, and neither `init` nor any parent of `slowcgi` can set it for it.

`pledge(2)` then states the outcome for the exec promise in as many words:

> If *execpromises* has been previously set the new program begins with those promises, unless
> setuid/setgid bits are set in which case execution is blocked with `EACCES`. Otherwise the
> new program starts running without pledge active, and hopefully makes a new pledge soon.

The kernel implements that literally. `kern_exec` applies the exec promises only when the
`PS_EXECPLEDGE` flag is set, and otherwise clears the process's promise set:

```c
if (pr->ps_flags & PS_EXECPLEDGE) {
    p->p_pledge = pr->ps_execpledge;
    pr->ps_pledge = pr->ps_execpledge;
    atomic_setbits_int(&pr->ps_flags, PS_PLEDGE);
} else {
    atomic_clearbits_int(&pr->ps_flags, PS_PLEDGE);
    p->p_pledge = 0;
    pr->ps_pledge = 0;
```

([`kern_exec.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_exec.c)), while
`sys_pledge` sets that flag only when the argument is non-null
([`kern_pledge.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c)).

So the map's "the capability contract is `slowcgi`'s child pledge" is wrong for the current
base tool. The child's pledge covers the calls `slowcgi` makes between `fork` and `execve`,
which are `dup2`, `close`, `signal`, `chdir`, `calloc` and `execve`. The member's program
starts with no promises at all, and can write files, open sockets and fork as the member
inside the chroot. That is a finding for the sibling ticket on `slowcgi` internals; it is
recorded here because it changes what this route can promise.

If the route wants the pledge to hold, the exec path has to pass it explicitly, for example
`pledge("stdio rpath exec", "stdio rpath exec")`. That is a change to base `slowcgi`, or a
wrapped launcher, and either way it belongs to the spec, not to this note. Even then the
control is `stdio rpath exec` over the whole chroot, not over the member's directory, and the
member can still read every file the chroot exposes.

## 6. Why the FastCGI service is not this route

A long-lived Rust FastCGI service is started once by its own `rc.d` script as the member and
serves many requests from one process, so it never passes through `slowcgi`'s child: it
inherits no per-request promise set, has no `-t` deadline, and holds full file access inside
the chroot for its whole life. Running one needs a supervisor and rlimits, which the map
explicitly leaves out.

## 7. Does "base interpreters only" exclude a compiled binary

No, and the phrase should not be read that way. The constraint excludes interpreters that are
not in base, such as PHP and the frameworks built on it, because they add a runtime the image
does not carry. A compiled Rust binary is not an interpreter, and it adds no runtime. It
links the base `libc`, plus `libm` or `libpthread` when the code uses them, and the tree
supplies those files. It is admitted by the same rule as `ksh` and `perl` once those files
exist.

Two cases fall outside the rule by their behaviour rather than by their form. A binary that
bundles its own interpreter, such as a PHP CLI or SAPI binary, reintroduces a non-base
runtime under a different name. A binary linked against `/usr/local/lib` libraries will not
resolve inside the chroot, so it fails at exec regardless of policy.

## What this settles for the design

The route can accept a Rust binary with an instruction that fits in four steps, provided the
spec says the build happens on the same OpenBSD release as the host and the member rebuilds
on upgrade. The chroot needs the loader and the base libraries, which the interpreter tree
already holds, so this adds at most `libm` and `libpthread` to an existing tree. Static
uploads are not a thing to plan for, because rustc cannot produce one. The pledge claim in
the map needs rewriting before the spec relies on it: as `slowcgi` stands, the member's
program is unpledged, and the honest statement of the route's containment is the chroot, the
member uid, and whatever limits the per-member service sets, with the pledge available only
after a change to the exec path. The policy answer is that a prebuilt binary is allowed; the
constraint is about interpreters.

## What is not verified

- No OpenBSD host was available. Nothing was built, linked, uploaded or executed, and the
  runtime pledge behaviour was not observed. The note is source reading plus one rustup
  observation.
- The `DT_NEEDED` list and the interpreter path for a real binary. `ldd` and `readelf -l` on
  the host settle both, and the library majors quoted here are from `-current` shlib_version
  files, not from the release the host will run.
- The cross build route, end to end, including whether a given host toolchain can emit an
  OpenBSD executable and where the interpreter path it records comes from.
- Whether the deployed `slowcgi` matches `-current`. The source read is `-current` as of
  2026-11-05; a release branch should be checked against the code above before the spec
  quotes it.
- Any limit behaviour. The map already notes that `slowcgi` has none beyond `-t`, and this
  note did not test what a spinning Rust program does.

## Sources

- rustc book, `*-unknown-openbsd`: <https://doc.rust-lang.org/nightly/rustc/platform-support/openbsd.html>
- target spec: <https://github.com/rust-lang/rust/blob/main/compiler/rustc_target/src/spec/targets/x86_64_unknown_openbsd.rs>
- OpenBSD base target options: <https://github.com/rust-lang/rust/blob/main/compiler/rustc_target/src/spec/base/openbsd.rs>
- `crt_static` defaults: <https://github.com/rust-lang/rust/blob/main/compiler/rustc_target/src/spec/mod.rs#L2812-L2814>
- `Session::crt_static`: <https://github.com/rust-lang/rust/blob/main/compiler/rustc_session/src/session.rs#L773-L777>
- std stack overflow module: <https://github.com/rust-lang/rust/blob/main/library/std/src/sys/pal/unix/stack_overflow/mod.rs>
- OpenBSD `lang/rust` port: <https://github.com/openbsd/ports/blob/master/lang/rust/Makefile> and <https://github.com/openbsd/ports/blob/master/lang/rust/pkg/PLIST-main>
- port patch for `current_exe`: <https://github.com/openbsd/ports/blob/master/lang/rust/patches/patch-library_std_src_sys_paths_unix_rs>
- `pledge(2)`: <https://man.openbsd.org/pledge.2>
- `slowcgi(8)`: <https://man.openbsd.org/slowcgi.8>
- `slowcgi.c`: <https://github.com/openbsd/src/blob/master/usr.sbin/slowcgi/slowcgi.c>
- `kern_pledge.c`: <https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c>
- `kern_exec.c`: <https://github.com/openbsd/src/blob/master/sys/kern/kern_exec.c>
- `ld.so(1)`: <https://man.openbsd.org/ld.so.1>
- `libc/shlib_version`, `libm/shlib_version`, `librthread/shlib_version`: <https://github.com/openbsd/src/tree/master/lib>
- OpenBSD FAQ 4, file sets: <https://www.openbsd.org/faq/faq4.html>
- Cargo unstable features, `build-std`: <https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#build-std>
