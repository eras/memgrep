# memgrep

`memgrep` is a `grep` for `/proc/pid/mem`. It's licensed under the
[MIT license](LICENSE.MIT).

Why won't regular `grep` do? You can try it, but it will just
immediately fail with an I/O error. This is because you can only read
certain parts of the file and the parts you can read are listed in the
file `/proc/pid/maps`.

So, basically, this tool combines parsing the `maps` file and `grep`ping
those regions for given process ids, or for all processes, while doing
it in parallel with the CPUs you have.

Note that the value kernel parameter
[`kernel.yama.ptrace_scope`](https://linux-audit.com/protect-ptrace-processes-kernel-yama-ptrace_scope/)
can affect `memgrep` abilities, even among your own processes. So for
best results you should choose between setting that value to `0`, or
using `sudo` to run the binary as root.

# usage

    % memgrep --help

    memgrep 1.1.1
    Erkki Seppälä <erkki.seppala@vincit.fi>
    Process address space grepping tool
    
    USAGE:
        memgrep [FLAGS] [OPTIONS] [--] [regex]
    
    FLAGS:
        -a, --all             Grep all processes
        -c, --count           Show only the number of non-zero matches
            --include-self    Include also this process in the results (implied by --pids)
        -l, --list            Show list the processes, not the matches
        -o, --show-content    Show the contents of the match (useful when using wildcards in regex)
        -h, --help            Prints help information
        -V, --version         Prints version information
    
    OPTIONS:
        -p, --pid <pid>...         Process id to grep

You need to provide either `-p pid` or `-a`; you must provide exactly
one [regex](https://docs.rs/regex/1.4.2/regex/#syntax). For
case-insensitive matching you can prefix your regex with `(?i)` (using
the [regex flag
syntax](https://docs.rs/regex/1.4.2/regex/#grouping-and-flags)).

# why?

Why not?

While this application might have few "real" use cases, it can be fun
for discovering if some processes contain e.g. the string "hello
world" with

`memgrep -a -r 'hello world'`

Similarly you can use it to discover how many processes are aware of
your password.. Preferably avoid trying that in a multi-user system
(due to password being visible in `ps`) and avoid putting that
command to your command history; with e.g. zsh you can achieve this
with `setopt histignorespace` and then prefixing the command with a
space.

Perhaps you can also use it for recovering deleted regions from your
text editor; chances are the previously removed content is still
recoverable from the memory. The tool will output the byte ranges you
can use with e.g. `gdb`:

    % gdb -p 1438910 -batch-silent -ex 'dump memory contents.txt 0x7f262c6a5c6d 0x7f262c6a5c72'

Note that the value kernel parameter
[`kernel.yama.ptrace_scope`](https://linux-audit.com/protect-ptrace-processes-kernel-yama-ptrace_scope/)
can affect your ability to run that command.

Fun stuff to try: `sudo memgrep -a -o '.{20}backdoor.{20}'`.

# compiling

`cargo build`. You can also download a binary for Linux/x86_64 from
the [GitHub releases page](../../releases/latest/). Note that debug
mode build (as produced by default with `cargo build`) is tons slower
than the release mode one.

# installing

..or you can just directly install it with `cargo`:

`cargo install --git https://github.com/eras/memgrep`
