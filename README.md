# memgrep

`memgrep` is a `grep` for `/proc/pid/mem`. It's licensed under the
[MIT license](LICENCE.MIT).

Why won't regular `grep` do? You can try it, but it will just
immediately fail with an I/O error. This is because you can only read
certain parts of the file and the parts you can read are listed in the
file `/proc/pid/maps`.

So, basically, this tool combines parsing the `maps` file and `grep`ping
those regions for given process ids, or for all processes, while doing
it in parallel with the CPUs you have.

# usage

    % memgrep --help

    memgrep 0.1.0
    Erkki Seppälä <erkki.seppala@vincit.fi>
    Grep for process memory spaces
    
    USAGE:
        memgrep [FLAGS] [OPTIONS] --regexp <regex>...
    
    FLAGS:
        -a, --all        Grep all processes
        -h, --help       Prints help information
        -V, --version    Prints version information
    
    OPTIONS:
        -p, --pid <pid>...         Process id to grep
        -r, --regexp <regex>...    Regular expresison to use

You need to provide either `-p pid` or `-a`; you must provide exactly
one `-r regex`.

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

# compiling

`cargo build`

# installing

`cargo install --path .`
