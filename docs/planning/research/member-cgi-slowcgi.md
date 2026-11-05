# What a member CGI script can do under slowcgi

Question: the Member CGI map (#572) proposes one `slowcgi` per member, started as
`slowcgi -p /home/www -u <name>`, with base interpreters only, and records two claims that
need checking: that the child's `pledge("stdio rpath exec")` survives `execve` so member code
cannot write files, open sockets or fork, and that `-t` is the only limit `slowcgi` applies.
This note checks both against the OpenBSD source, plus the `SCRIPT_NAME` / `SCRIPT_FILENAME`
split that decides what path a front end can make `slowcgi` execute.

Answer, in nine sentences. The pledge does not survive the exec. `exec_cgi()` calls
`pledge("stdio rpath exec", NULL)` with a null `execpromises` (`slowcgi.c`, line 922), and
`pledge(2)` says a program exec'd without previously set execpromises "starts running without
pledge active"; `kern_exec.c` clears `PS_PLEDGE` when `PS_EXECPLEDGE` is not set (lines 657 to
668), and `sys_pledge()` only sets that flag when the second pointer is non-null
(`kern_pledge.c`, lines 512 to 515). So the member script runs with no pledge at all. Its
confinement is the chroot and the uid, nothing else: it can fork, open sockets, and write any
path the member can write inside the chroot. The `stdio rpath exec` promises cover only the
window between the child's pledge and its `execve` (`dup2`, `close`, `chdir`, `execve`), and if
they did carry they would admit reads, `chdir`, `execve`, writes to already-open descriptors
and the loader's mappings, while killing the process with `SIGABRT` on opening a file for
write or create, unlinking, creating a real socket, or forking. The chroot is the practical
blocker for interpreters: with `-p /home/www`, `/bin/ksh` does not exist inside it, and a
shebang is resolved inside the chroot, so a base `ksh` script does not start at all; only a
static executable runs unless the base userland is copied in or the chroot is dropped with
`-p /`. `-t` closes the script's three streams and leaves the process running, `slowcgi` never
calls `kill`, and there is no CPU, memory or process bound.
Rlimits are inherited from whatever started `slowcgi`, and `rc.subr` starts daemons through
`su -fl -c <class>`, so a login class on the unit does bound the children, with the caveat that
a process may raise its soft limit to the class's hard max. `httpd` sends both script variables
and `slowcgi` lets `SCRIPT_FILENAME` win; `gmid` sends only `SCRIPT_NAME`, so its FastCGI block
must put the execution path in `param SCRIPT_NAME`.

Read from sources, not tested. No OpenBSD host was available in this environment: nothing here
was run on a box, and every runtime statement is inference from the kernel and userland source
plus the man pages. That applies especially to what a pledge violation does at run time, what
`ksh` does under a pledge it never has, and how a front end reports a script that fails to
exec. The deployment pin in this repository is OpenBSD 7.9. The GitHub mirror of `openbsd/src`
publishes only `master` and no release tags, so the exact 7.9 file cannot be fetched from it;
`slowcgi.c` was last changed on 2026-05-31 (`v1.65`, a record-parsing fix in `parse_record()`
and the end-of-params guard) and the pledge, timeout and parameter code predates that change.
gmid's `fcgi.c` at tag `2.1.1` is byte-identical to `master`.

## 1. The child pledge is dropped at execve

The relevant call is in `exec_cgi()`, in the fork's child branch:

```c
	case 0:
		/* Child process */
		if (pledge("stdio rpath exec", NULL) == -1)
			lerr(1, "pledge");
```

`usr.sbin/slowcgi/slowcgi.c`, line 922. The second argument is `NULL`. The parent process made
the same choice earlier, `pledge("stdio rpath unix proc exec", NULL)` at line 369, so no call in
`slowcgi` ever sets execpromises (grep for `pledge(` returns lines 369 and 922 only).

`pledge(2)` on the `exec` promise:

> Allows a process to call execve(2). Coupled with the `proc` promise, this allows a process to
> fork and execute another program. If *execpromises* has been previously set the new program
> begins with those promises, unless setuid/setgid bits are set in which case execution is
> blocked with EACCES. Otherwise the new program starts running without pledge active, and
> hopefully makes a new pledge soon.

The kernel implements exactly that. `sys_pledge()` sets `PS_EXECPLEDGE` only when the
`execpromises` pointer is present:

```c
	if (SCARG(uap, execpromises)) {
		pr->ps_execpledge = execpromises;
		atomic_setbits_int(&pr->ps_flags, PS_EXECPLEDGE);
	}
```

`sys/kern/kern_pledge.c`, lines 512 to 515. At exec, `kern_exec.c` copies the exec promises only
when that flag is set, and otherwise clears the process's pledge and destroys any unveil state:

```c
	if (pr->ps_flags & PS_EXECPLEDGE) {
		p->p_pledge = pr->ps_execpledge;
		pr->ps_pledge = pr->ps_execpledge;
		atomic_setbits_int(&pr->ps_flags, PS_PLEDGE);
	} else {
		atomic_clearbits_int(&pr->ps_flags, PS_PLEDGE);
		p->p_pledge = 0;
		pr->ps_pledge = 0;
		/* Clear our unveil paths out so the child starts afresh */
		unveil_destroy(pr);
		pr->ps_uvdone = 0;
	}
```

`sys/kern/kern_exec.c`, lines 657 to 668.

So the capability contract the map states for member CGI does not exist as written. After
`execve` the member's process is confined by the chroot set at line 356, the uid and gid set at
lines 364 to 366, the inherited rlimits, and nothing else. Inside that chroot it can call
`fork`, `socket`, `open` for write, `unlink`, and `setrlimit`, subject only to file permissions
and those limits. That makes the chroot layout and the uid the whole security boundary, which
is the opposite of treating the pledge as the boundary.

The child's pledge still does useful work for `slowcgi` itself: it constrains the code path
between the pledge and the `execve`, which is `close`, `dup2`, `signal`, `calloc`, `chdir` and
`execve`. It protects the adapter, not the member program.

## 2. What `stdio rpath exec` admits, and what it refuses

This section describes the promise set as if it survived exec, because the ticket asks for the
capability list and because the set is correct for the pre-exec window. The kernel's syscall
table (`sys/kern/kern_pledge.c`, lines 250 to 352) and `pledge(2)` agree on the split.

Admitted:

- `read`, `write`, `readv`, `writev`, `pread`, `pwrite` on descriptors that are already open.
  Writing the CGI response to fd 1 and diagnostics to fd 2 is ordinary `stdio` traffic. A file
  write is only impossible because there is no way to open a file for writing.
- `open` for read, `stat`, `chdir`, `opendir` and the rest of path traversal (`rpath`). This is
  what lets the child `chdir` to the script's directory at lines 945 and 950. `fchdir` is
  `stdio`.
- `execve` (`exec`), which is the only reason the promise is present. `prot_exec` is not
  included, so a later `mmap` or `mprotect` with `PROT_EXEC` is refused.
- `dup2`, `close`, `pipe`, `pipe2`, `socketpair`, `ftruncate`, `fsync`, `sigaction`,
  `getrlimit`, `wait4` (`stdio`).
- `kill` with pid 0 or the process's own pid. The table marks `kill` as `stdio` and
  `pledge_kill()` permits the caller's own pid and pid 0; `pledge(2)` notes that without `proc`
  "kill(2) may still operate on the process group with pid 0". A member script could therefore
  signal its whole process group, which is inherited from `slowcgi`. That is moot as shipped,
  because no pledge is active, but it matters for anyone who fixes the execpromises.

Refused, with the process killed by an uncatchable `SIGABRT`:

- `open` with `O_WRONLY`, `O_RDWR` or `O_TRUNC` needs `wpath`, and `O_CREAT` needs `cpath`
  (`sys/kern/vfs_syscalls.c`, lines 1138 to 1155). No file creation, no overwrite, no truncate.
- `unlink`, `unlinkat`, `rmdir`, `mkdir`, `rename`, `link`, `symlink` need `cpath`.
- `socket` in `AF_INET`, `AF_INET6` or `AF_UNIX` needs `inet`, `unix` or `dns`. `socketpair` is
  allowed, so "no socket" is too strong: no socket that can reach a file system path or a
  network. `bind` and `connect` never get that far.
- `fork`, `vfork`, `setpgid`, `setsid` and `setrlimit` need `proc`.
- `chmod`, `fchmod`, `chown` and their relatives need `fattr` or `chown`.
- `mmap` and `mprotect` with `PROT_EXEC` after the loader has called `kbind`. The check is in
  `pledge_protexec()` and explains the loader case:

```c
	/* Before kbind(2) call, ld.so and crt may create EXEC mappings */
	if (p->p_p->ps_kbind_addr == 0 && p->p_p->ps_kbind_cookie == 0)
		return 0;
	if (!(p->p_pledge & PLEDGE_PROTEXEC) && (prot & PROT_EXEC))
		return pledge_fail(p, EPERM, PLEDGE_PROTEXEC);
```

`sys/kern/kern_pledge.c`, lines 1728 to 1735. A dynamically linked program therefore loads: the
ELF interpreter and crt are allowed their executable mappings before `kbind`, and opening the
shared libraries is `rpath`. Anything that maps executable memory later needs `prot_exec`,
which the child does not have.

The failure is not a polite `EPERM`. `pledge_fail()` sends `SIGABRT` before returning the error,
so a refused operation kills the process, with a core file if the rlimit allows it, and is
accounted with the `P` flag in `lastcomm` (`pledge(2)`, `sys/kern/kern_pledge.c` lines 557 to
587). A member script that tries `echo x > file` under this set dies rather than seeing a
failed open.

## 3. A base `ksh` inside the chroot

With `-p /home/www`, `slowcgi` chroots at line 356 and the script path is interpreted inside
that root. A CGI file with `#!/bin/ksh` does not run, for a reason that comes before either
pledge or fork: the shebang handler execs the interpreter by the path in the file, in the same
process and therefore the same chroot. `execve(2)`:

> An interpreter file begins with a line of the form: `#! interpreter [arg]`. When an
> interpreter file is passed to execve(), the system instead calls execve() with the specified
> interpreter.

`chroot(2)`:

> chroot() causes dirname to become the root directory, that is, the starting point for path
> searches of pathnames beginning with '/'.

So `/bin/ksh` resolves to `/home/www/bin/ksh`. Unless the deployment copies the base userland
into the chroot, nothing is there. The child logs `execve /...: No such file or directory` and
`_exit(1)` (lines 961 to 963), the request produces no CGI output, and the front end reports a
backend failure. A static executable dropped in the tree is the only thing that runs under this
chroot without preparation.

If the chroot is populated, or if `-p /` is used (the man page notes that a path of `/`
effectively disables the chroot), a dynamically linked base `ksh` loads without help from the
pledge. It needs `bin/ksh`, the ELF interpreter, `libc` and `libcurses` from `/usr/lib`; the
base `Makefile` for ksh links `-lcurses` and sets no `LDSTATIC`, so the binary is dynamic (read
from `bin/ksh/Makefile`; the linked libraries themselves are inference from the build rules,
not observed). Its `mmap` calls succeed for the reason in section 2, because they happen before
`kbind`.

Under an enforced `stdio rpath exec` the shell would then die at the first construct that forks:
a pipeline, a subshell, command substitution, or any external command. `ksh(1)` describes
pipelines as commands joined by `|` with each output piped to the next, and `( ... )` as the
subshell syntax, and both require `fork`. Builtins that only write to the inherited descriptors
(`echo`, `print`, `test`, `read`) and `cd` would work. The first file redirection would kill it
through the `wpath` check. None of this is observed; it follows from the promise set and the
shell's documented grammar.

As shipped, with the pledge dropped, `ksh` runs with the member's full rights inside the chroot.
A member script can fork, open a TCP socket, write inside any directory the member owns, and
`ulimit` itself. The chroot stops it seeing the rest of the file system, and the uid stops it
writing to files the member does not own. Neither stops a fork bomb or a network connection.

## 4. What `-t` does to a hung or spinning script

The timeout is a single event timer armed when the request is accepted, not reset on activity:

```c
	evtimer_set(&c->tmo, slowcgi_timeout, c);
	evtimer_add(&c->tmo, &timeout);
```

`slowcgi.c`, lines 510 and 511. The default is 120 seconds and the settable maximum is one year
(`TIMEOUT_DEFAULT` and `TIMEOUT_MAX`, lines 42 and 43; parsing at line 310). Because the timer
is armed once at accept, it bounds the whole request, so a slow but working script is cut off at
the same point as a hung one.

On expiry, `slowcgi_timeout()` calls `cleanup_request()` (lines 516 to 519). That function
deletes the timers and events, closes the FastCGI connection and the parent's ends of the three
pipes, frees the request, and returns. There is no `kill` call anywhere in `slowcgi.c` (grep for
`kill` returns nothing), and the man page says so plainly:

> Terminate the request after *timeout* seconds instead of the default 120 seconds. The CGI
> script is left to run but its standard input, output and error will be closed.

What the script experiences depends on what it does next. Its stdin reaches end of file. Its
stdout and stderr pipes have no reader left, so the next write raises `SIGPIPE`, and the child
restored the default disposition before exec (`signal(SIGPIPE, SIG_DFL)`, line 939). A script
that keeps producing output therefore dies on its next write. A script that spins without
writing, or blocks on a network call, keeps running indefinitely.

The same `cleanup_request()` runs when the front end closes the connection or sends a malformed
record (`slowcgi_request()` calls it on read EOF and on a parse failure, lines 624 to 680), so a
client disconnect has the same effect as the timeout: the pipes close and the process keeps
running.

Reaping is by the `SIGCHLD` handler, which loops on `waitpid(WAIT_ANY, &status, WNOHANG)` (line
533). By the time the child exits the request is usually gone, so the handler logs `caught exit
of unknown child` and reaps it anyway. If `slowcgi` exits first, the child is reparented and
reaped by `init`. Nothing signals or supervises it in between.

There is no CPU, memory or process bound in `slowcgi`. The only indirect limit is file
descriptors: `accept_reserve()` refuses a new connection when `getdtablecount() + 5 +
(inflight + 1) * 6` would reach `getdtablesize()` (lines 439 to 455), which caps how many
requests and therefore scripts run at once but says nothing about what each one consumes. A
request that is already running is not re-counted after the timeout either, so the timeout does
not reduce the run-away process's cost.

## 5. Rlimits and ulimit

Resource limits are process state: `fork` copies them, `execve` preserves them (`execve(2)`
lists "resource limits" among the attributes the new image keeps, pointing at
`getrlimit(2)`), and `setrlimit(2)` says they live in "the per-process information". `slowcgi`
never calls `setrlimit` or `getrlimit`, so whatever limits the daemon starts with are exactly
what every member script inherits.

The daemon's limits come from `rc.subr`, which starts a daemon through `su`:

```sh
	rc_exec() {
		local _rcexec="su -fl -c ${daemon_class} -s /bin/sh ${daemon_user} -c"
```

`etc/rc.d/rc.subr`, lines 180 and 181. `daemon_class` is the unit's own name if
`/etc/login.conf.d/<name>` or `/etc/login.conf` defines it, otherwise `daemon` (lines 383 and
384). `su(1)` takes `-c login-class`, and `login.conf(5)` supplies the limits, with
`cputime`, `filesize`, `datasize`, `stacksize`, `coredumpsize`, `memoryuse`, `memorylocked`,
`maxproc` and `openfiles`, each overridable as `-cur` and `-max`. This repository already relies
on that shape for the onboarding unit, whose `rc.d` comment records the `daemon` class's
`openfiles-cur=128`.

So the map's second claim is right in substance: a login class on the per-member `slowcgi` unit
bounds every script that unit runs. Two details decide whether the bound holds.

- A process may raise its own soft limit up to the hard max. `login.conf(5)` says the current
  limit "is the one normally used, although the user is permitted to increase the current limit
  to the maximum limit", and `getrlimit(2)` says only the superuser may raise the maximum. A
  class that sets only `-cur` lets the member script undo it. Set `-max` to the intended ceiling.
- `cputime` is per process. A script that forks gives each child a fresh CPU budget; only
  `maxproc` (RLIMIT_NPROC, "maximum number of simultaneous processes for this user id") caps
  the number of children. There is no total CPU or total memory budget per request.

OpenBSD `ksh` can set all of the per-process limits it has promises for, through the `ulimit`
builtin: `-a`, `-c`, `-d`, `-f`, `-H`, `-l`, `-m`, `-n`, `-p`, `-S`, `-s`, `-t` (`ksh(1)`).
They map to core size, data size, file size, locked memory, resident set, open descriptors,
processes for the uid, stack size, and CPU seconds in user mode, with `-H` and `-S` choosing
hard or soft. Two notes for using this as a defence: `-m` is documented as "not enforced", and
there is no `-v`, because OpenBSD has no `RLIMIT_AS` (`getrlimit(2)`, BUGS: "The RLIMIT_AS
resource is missing"). Memory can only be bounded through `datasize`, `stacksize` and
`memoryuse`.

Since the member's shell can raise its soft limits up to the class hard max, and can decline to
lower anything, the limit has to be imposed on the `slowcgi` process, not inside the script.

## 6. SCRIPT_NAME versus SCRIPT_FILENAME

`slowcgi` decides what to exec while parsing parameters, and the two variables are not
symmetric:

```c
		if (val_len < PATH_MAX && strcmp(env_entry->val,
		    "SCRIPT_NAME") == 0 && c->script_name[0] == '\0') {
			bcopy(buf, c->script_name, val_len);
			c->script_name[val_len] = '\0';
		} else if (val_len < PATH_MAX && strcmp(env_entry->val,
		    "SCRIPT_FILENAME") == 0) {
			bcopy(buf, c->script_name, val_len);
			c->script_name[val_len] = '\0';
		}
```

`slowcgi.c`, lines 783 to 790. `SCRIPT_NAME` fills the name only while it is still empty;
`SCRIPT_FILENAME` overwrites it unconditionally. So when both arrive, `SCRIPT_FILENAME` wins
regardless of order. A later `SCRIPT_NAME` cannot undo it. If only one arrives, that one is
used. If `SCRIPT_FILENAME` arrives with an empty value it sets the name to empty, and
`execve("")` fails.

`httpd` sends both. In `server_fcgi.c` (`fcgi_add_param()` calls at lines 204 to 218),
`SCRIPT_NAME` is the request's URL prefix for the matched alias, and `SCRIPT_FILENAME` is
`srv_conf->root` plus the stripped alias, then `server_root_strip(script, fcgistrip)` removes
`fastcgi strip N` leading components. Both are relative to httpd's chroot, and the strip exists
so that a slower chroot nested under it can resolve the path. `httpd.conf(5)`:

> Strip *number* path components from the beginning of DOCUMENT_ROOT and SCRIPT_FILENAME before
> sending them to the FastCGI server. This allows FastCGI server chroot to be a directory under
> httpd chroot.

For `httpd` the file to run therefore comes from the request, through `SCRIPT_FILENAME`, and no
`param SCRIPT_NAME` is needed. If one is configured, `SCRIPT_FILENAME` still wins in `slowcgi`.

`gmid` sends no `SCRIPT_FILENAME` at all. There are zero occurrences in `fcgi.c`, and the file
at tag `2.1.1` is identical to `master`. `fcgi_req()` always sends `SCRIPT_NAME`, in one of two
forms (`fcgi.c`, lines 423 to 445):

- If the configured `param SCRIPT_NAME`, with trailing slashes trimmed, is a prefix of the
  stripped request path, it sends that prefix of the stripped path as `SCRIPT_NAME` and the
  remainder as `PATH_INFO`. The configured value is used here as a matching key.
- Otherwise it sends the configured value verbatim as `SCRIPT_NAME` and the whole stripped path
  as `PATH_INFO`.

`gmid.conf(5)` calls `SCRIPT_NAME` "the virtual URI path to the script" and says gmid assumes it
is empty unless configured, recommending a manual value when serving a subtree through FastCGI.
It is not translated through `path_translate()`; only `PATH_TRANSLATED` is.

The consequence for a shared member socket is that the two front ends populate the exec path
differently, and `slowcgi` will not reconcile them. With `httpd`, the CGI path comes from the
request and must exist where `SCRIPT_FILENAME` points inside `slowcgi`'s chroot. With `gmid`,
the CGI path comes from the config, because `param SCRIPT_NAME` is the only source, and it must
be the path `slowcgi` will `execve`, not a URL that gmid will translate. A gmid FastCGI block
with no `SCRIPT_NAME` param sends the empty string and `slowcgi` calls `execve("")`.

## Primary sources

- `usr.sbin/slowcgi/slowcgi.c`, OpenBSD `master` at 2026-11-05, from
  https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/slowcgi/slowcgi.c. Cited lines:
  42 and 43 (timeout constants), 356 to 369 (chroot, `setresuid`, parent pledge), 400 (listener
  with `SOCK_CLOEXEC`), 439 to 455 (`accept_reserve()`), 510 and 511 (timer armed at accept),
  516 to 519 (`slowcgi_timeout()`), 533 (`waitpid()` loop), 701 to 800 (`parse_params()`),
  783 to 790 (the two script variables), 900 to 963 (`exec_cgi()`, including the child pledge at
  922, `SIGPIPE` at 939, `chdir` at 945 and 950, `execve` at 961), 1129 to 1175
  (`cleanup_request()`).
- `slowcgi(8)`, https://man.openbsd.org/slowcgi.8, for the `-p`, `-u`, `-t` and `-s` options and
  the sentence that the script is left to run with its streams closed.
- `pledge(2)`, https://man.openbsd.org/pledge.2, for the promise list, the `exec` and execpromises
  rule, the `SIGABRT` violation, the `prot_exec` rule, and the `kill`/process-group note.
- `sys/kern/kern_pledge.c`, https://raw.githubusercontent.com/openbsd/src/master/sys/kern/kern_pledge.c,
  lines 250 to 352 (syscall table), 512 to 515 (`PS_EXECPLEDGE` set), 557 to 587
  (`pledge_fail()` and `SIGABRT`), 1728 to 1735 (`pledge_protexec()`).
- `sys/kern/kern_exec.c`, https://raw.githubusercontent.com/openbsd/src/master/sys/kern/kern_exec.c,
  lines 613 and 614 (kbind counters reset) and 657 to 668 (pledge carried only with
  execpromises).
- `sys/kern/vfs_syscalls.c`, https://raw.githubusercontent.com/openbsd/src/master/sys/kern/vfs_syscalls.c,
  lines 1118 to 1155, for the `open` flags to promise mapping.
- `execve(2)`, https://man.openbsd.org/execve.2, for shebang handling and the preserved
  attributes list. `chroot(2)`, https://man.openbsd.org/chroot.2, for path resolution inside the
  new root.
- `bin/ksh/Makefile`, https://raw.githubusercontent.com/openbsd/src/master/bin/ksh/Makefile, for
  the `-lcurses` link and the absence of `LDSTATIC`. `ksh(1)`, https://man.openbsd.org/ksh.1,
  for `ulimit` and the pipeline and subshell grammar. `share/mk/bsd.prog.mk` for `LDSTATIC`
  being opt-in.
- `getrlimit(2)`, https://man.openbsd.org/getrlimit.2, for the limit meanings, the hard-limit
  rule, per-process storage and the missing `RLIMIT_AS`.
- `etc/rc.d/rc.subr`, https://raw.githubusercontent.com/openbsd/src/master/etc/rc.d/rc.subr,
  lines 180 and 181 for `su -fl -c ${daemon_class}`, and lines 383 and 384 for the class
  selection. `su(1)`, https://man.openbsd.org/su.1, for `-c login-class`.
- `login.conf(5)`, https://man.openbsd.org/login.conf.5, for the resource capability names, the
  `-cur` and `-max` suffixes, and the rule that a user may raise the current limit to the
  maximum. `etc/rc.d/slowcgi` and `openbsd/etc/rc.d/kyriakon_onboard` in this repository, the
  latter for the existing use of a login class through `rc.subr`.
- `usr.sbin/httpd/server_fcgi.c`,
  https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/httpd/server_fcgi.c, lines 160
  to 235, for `SCRIPT_NAME` and `SCRIPT_FILENAME`. `usr.sbin/httpd/server_http.c` lines 1593 to
  1605 for `server_root_strip()`. `httpd.conf(5)`, https://man.openbsd.org/httpd.conf.5, for
  `fastcgi` and `strip`.
- gmid `fcgi.c`, https://raw.githubusercontent.com/omar-polo/gmid/master/fcgi.c, `fcgi_req()`
  at lines 400 to 505 and `path_translate()` above it; tag `2.1.1` from
  https://raw.githubusercontent.com/omar-polo/gmid/2.1.1/fcgi.c, diffed identical.
  `gmid.conf.5`, https://raw.githubusercontent.com/omar-polo/gmid/master/gmid.conf.5, for the
  `param`, `strip` and `SCRIPT_NAME` description. `utils.c` lines 44 to 58 for `strip_path()`.
- `issue://572` and `issue://573` in this repository, for the claims under test.
