#![feature(unboxed_closures)]
#![feature(fn_traits)]
use clap::{App, AppSettings, Arg};
use core::ops::Range;
use lazy_static::lazy_static;
use regex::Regex;
use std::fs::{read_link, File};
use std::io::{self, prelude::*, BufReader, SeekFrom};
use std::sync::{Arc, Mutex};
use thiserror::Error;

use hyperscan::{
    prelude::*, // Pattern, Database,
    Patterns,
    Streaming,
};
use std::iter::FromIterator;

#[derive(Error, Debug)]
enum Error {
    #[error("error: {0}")]
    Message(String),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    RegexError(#[from] regex::Error),

    #[error(transparent)]
    IOError(#[from] io::Error),
}

#[derive(Copy, Clone, Debug)]
pub enum PS {
    P,
    S,
}

#[derive(Copy, Clone, Debug)]
struct Permissions {
    r: bool,
    w: bool,
    x: bool,
    p: Option<PS>,
}

#[derive(Debug)]
struct MemMapping {
    begin: u64,
    end: u64,
    perms: Permissions,
    label: String,
}

#[derive(Debug)]
struct Config {
    pids: Vec<u64>,
    re: String,
    only_count: bool,
    only_list: bool,
    include_self: bool,
    show_content: bool,
}

impl Clone for MemMapping {
    fn clone(&self) -> Self {
        MemMapping {
            begin: self.begin,
            end: self.end,
            perms: self.perms,
            label: self.label.clone(),
        }
    }
}

fn read_mapping(filename: &str) -> Result<Vec<MemMapping>, Error> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);

    lazy_static! {
        static ref RE: Regex = Regex::new(
            r"(?x)
            ^
            (?P<begin>[0-9a-f]+)-
            (?P<end>[0-9a-f]+)\s
            (?P<perms>[r-][w-][x-][ps-])\s
            ([0-9a-f]+)\s
            ([0-9a-f]+:[0-9a-f]+)\s
            ([0-9]+)\s+
            (?P<label>.*)
            $
            "
        )
        .unwrap() /* we assume the regex is flawless */;
    }

    let mut count = 0;
    let mapping_results : Vec<_> = reader
        .lines()
        .map(|line| {
            count += 1;
            RE.captures(&line.unwrap() /* TODO: we assume no IO errors */)
                .map(|cap| {
                    let begin = cap.name("begin").expect("begin").as_str();
                    let end = cap.name("end").expect("end").as_str();
                    let label = cap.name("label").expect("label").as_str();
		    let (c0, c1, c2, c3) =
		        {
			    let perms = cap.name("perms").expect("perms").as_str();
			    let mut cs = perms.chars();
			    (cs.next(),
			     cs.next(),
			     cs.next(),
			     cs.next())
			};
                    {
                        MemMapping {
                            begin: u64::from_str_radix(begin, 16).unwrap() /* assumed to contain valid hex */,
                            end: u64::from_str_radix(end, 16).unwrap() /* assumed to contain valid hex */,
                            perms: Permissions {
                                r: c0 == Some('r'),
                                w: c1 == Some('w'),
                                x: c2 == Some('x'),
                                p: match c3 {
				    Some ('p') => Some(PS::P),
				    Some ('s') => Some(PS::S),
				    Some ('-') => None,
				    _ => panic!("Unsupported format in /proc/pid/maps"),
				}
                            },
                            label: label.to_string(),
                        }
                    }
                })
		.ok_or(format!("failed to parse {} at {}", &filename, count))
        })
        .collect();

    let errors: Vec<_> = mapping_results
        .iter()
        .filter_map(|result| Result::err(result.clone()))
        .collect();

    if !errors.is_empty() {
        Err(Error::Message(errors[0].clone()))
    } else {
        let mappings: Vec<_> = mapping_results
            .iter()
            .filter_map(|result| Result::ok(result.clone()))
            .collect();
        Ok(mappings)
    }
}

struct Match {
    range: Range<usize>,
}

type GrepResults = Vec<Match>;

struct MatcherCommon {
    database: Database<Streaming>,
}

struct MatcherPerThread<'a> {
    common: &'a MatcherCommon,
    scratch: Scratch,
}

struct MatcherStream<'a> {
    thread: &'a MatcherPerThread<'a>,
    stream: Option<Stream>,
}

fn make_matcher_common(regexp: &str) -> MatcherCommon {
    let pattern = Pattern::with_flags(
        regexp,
        CompileFlags::DOTALL | CompileFlags::MULTILINE | CompileFlags::SOM_LEFTMOST,
    )
    .expect("regexp error"); // TODO
    let patterns = Patterns::from_iter(vec![pattern].into_iter());
    let database = patterns.build::<Streaming>().expect("db");

    MatcherCommon { database }
}

fn make_matcher_per_thread(matcher_common: &MatcherCommon) -> MatcherPerThread {
    let scratch = matcher_common.database.alloc_scratch().expect("scratch");

    MatcherPerThread {
        common: &matcher_common,
        scratch,
    }
}

fn make_matcher_stream<'a>(matcher_per_thread: &'a MatcherPerThread) -> MatcherStream<'a> {
    let stream = Some(
        matcher_per_thread
            .common
            .database
            .open_stream()
            .expect("open stream"),
    );

    MatcherStream {
        thread: matcher_per_thread,
        stream,
    }
}

struct MatcherCallback<'a> {
    matches: &'a mut Vec<Match>,
    offset: u64,
}

impl<'a> MatcherCallback<'a> {
    fn callback(&mut self, _id: u32, from: u64, to: u64, _flags: u32) -> Matching {
        let range = Range {
            start: (from + self.offset) as usize,
            end: (to + self.offset) as usize,
        };
        self.matches.push(Match { range });
        Matching::Continue
    }
}

impl<'a> FnOnce<(u32, u64, u64, u32)> for MatcherCallback<'a> {
    type Output = Matching;
    extern "rust-call" fn call_once(mut self, args: (u32, u64, u64, u32)) -> Matching {
        self.call_mut(args)
    }
}

impl<'a> FnMut<(u32, u64, u64, u32)> for MatcherCallback<'a> {
    extern "rust-call" fn call_mut(&mut self, args: (u32, u64, u64, u32)) -> Matching {
        self.callback(args.0, args.1, args.2, args.3)
    }
}

fn make_matcher_callback<'a>(matches: &'a mut Vec<Match>, offset: u64) -> MatcherCallback<'a> {
    MatcherCallback { matches, offset }
}

fn call_matcher<'a>(
    matcher_stream: &MatcherStream<'a>,
    callback: &mut MatcherCallback,
    data: &[u8],
) {
    let stream = matcher_stream.stream.as_deref().expect("stream expected");
    stream
        .scan(data, &matcher_stream.thread.scratch, callback)
        .expect("scan stream");
}

fn reset_matcher(matcher_stream: &mut MatcherStream, callback: &mut MatcherCallback) {
    let stream = matcher_stream.stream.as_deref().expect("stream expected");
    stream
        .reset(&matcher_stream.thread.scratch, callback)
        .expect("reset stream");
}

fn destroy_matcher(matcher_stream: &mut MatcherStream) {
    matcher_stream
        .stream
        .take()
        .expect("stream expected")
        .close(&matcher_stream.thread.scratch, |_, _, _, _| {
            Matching::Continue
        })
        .expect("close stream");
}

fn grepper(
    core: &str,
    mappings: Vec<MemMapping>,
    matcher_per_thread: &MatcherPerThread,
) -> Result<GrepResults, Error> {
    let mut file = File::open(core)?;

    let mut matches = Vec::new();

    let mut buf = [0; 65536];
    let buf_len = buf.len();

    let mut matcher_stream = make_matcher_stream(&matcher_per_thread);
    for mapping in mappings.iter() {
        if mapping.perms.r {
            file.seek(SeekFrom::Start(mapping.begin))?;
            let mut offset = mapping.begin as usize;
            while let Ok(n) =
                file.read(&mut buf[0..std::cmp::min(buf_len, mapping.end as usize - offset)])
            {
                offset += n;
                if n != buf.len() {
                    let rest = &buf[0..n];
                    call_matcher(
                        &matcher_stream,
                        &mut make_matcher_callback(&mut matches, mapping.begin),
                        &rest,
                    );
                    break;
                } else {
                    call_matcher(
                        &matcher_stream,
                        &mut make_matcher_callback(&mut matches, mapping.begin),
                        &buf,
                    );
                }
            }
            reset_matcher(
                &mut matcher_stream,
                &mut make_matcher_callback(&mut matches, mapping.begin),
            );
        }
    }
    destroy_matcher(&mut matcher_stream);
    Ok(matches)
}

fn core_of_pid(pid: u64) -> String {
    format!("/proc/{}/mem", pid)
}

fn handle_pid(pid: u64, matcher_per_thread: &MatcherPerThread) -> Result<GrepResults, Error> {
    let mapping = read_mapping(&format!("/proc/{}/maps", pid))?;
    grepper(&core_of_pid(pid), mapping, matcher_per_thread)
}

fn dump_bytes(bytes: &[u8]) {
    let mut was_hex = false;
    for byte in bytes {
        if *byte >= 32 && *byte <= 127 {
            print!("{}{}", if was_hex { " " } else { "" }, *byte as char);
            was_hex = false;
        } else {
            print!(" 0x{:02x}", *byte);
            was_hex = true;
        }
    }
    println!();
}

fn dump_match(pid: u64, match_: &Match) -> Result<(), Error> {
    let mut file = File::open(core_of_pid(pid))?;

    let size = match_.range.end - match_.range.start;
    let mut buf = vec![0; size];
    file.seek(SeekFrom::Start(match_.range.start as u64))?;
    file.read_exact(&mut buf)?;
    dump_bytes(&buf);
    Ok(())
}

fn show_matches(pid: u64, matches: GrepResults, config: &Config) {
    if !matches.is_empty() {
        let executable = read_link(format!("/proc/{}/exe", pid))
            .map_or(String::from("(cannot read)"), |filename| {
                String::from(filename.to_str().map_or("(invalid unicode)", |x| x))
            });
        print!("{} {}", pid, executable);
        if config.only_list {
            println!();
        } else if config.only_count {
            println!(": {}", matches.len());
        } else {
            println!(":");
            for match_ in matches {
                print!("  {:x}-{:x}", match_.range.start, match_.range.end);
                if config.show_content {
                    print!(": ");
                    match dump_match(pid, &match_) {
                        Ok(()) => {}
                        Err(_) => println!("error while reading memory"),
                    }
                } else {
                    println!()
                }
            }
        }
    }
}

fn all_pids() -> Result<Vec<u64>, Error> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        if let Ok(pid) = entry?
            .file_name()
            .into_string()
            .unwrap() /* assumed to contain legal unicode */
            .parse::<u64>()
        {
            pids.push(pid)
        }
    }
    Ok(pids)
}

struct PidHandler<'a> {
    pid: u64,
    config: &'a Config,
    output_mutex: Arc<Mutex<()>>,
}

impl<'a> FnOnce<(&rayon::Scope<'_>, &MatcherCommon)> for PidHandler<'a> {
    type Output = ();
    extern "rust-call" fn call_once(self, args: (&rayon::Scope<'_>, &MatcherCommon)) {
        if let Ok(matches) = handle_pid(self.pid, &make_matcher_per_thread(args.1)) {
            let _guard = self.output_mutex.lock().unwrap() /* assumed to succeed */;
            show_matches(self.pid, matches, self.config);
        }
    }
}

fn handle_pids(config: &Config) -> Result<(), Error> {
    // TODO: it would be cooler to have a thread receive the results
    // and thus replace the mutex?  it would also be path forward for
    // json outupt
    let output_mutex = Arc::new(Mutex::new(()));
    let matcher_common = make_matcher_common(&config.re);
    rayon::scope(|scope| {
        for pid in &config.pids {
            if config.include_self || *pid != std::process::id() as u64 {
                let pid_handler = PidHandler {
                    pid: *pid,
                    config,
                    // TODO: is this cloning fake in that it breaks sharing?
                    output_mutex: Arc::clone(&output_mutex),
                };
                scope.spawn(|scope| pid_handler(scope, &matcher_common));
            }
        }
    });
    Ok(())
}

fn main() -> Result<(), Error> {
    let args = App::new("memgrep")
        .version(option_env!("GIT_DESCRIBE").unwrap_or_else(|| env!("VERGEN_SEMVER")))
        .author("Erkki Seppälä <erkki.seppala@vincit.fi>")
        .about("Process address space grepping tool")
        .arg(
            Arg::new("all")
                .long("all")
                .short('a')
                .takes_value(false)
                .about("Choose all processes for grepping"),
        )
        .arg(
            Arg::new("count")
                .long("count")
                .short('c')
                .takes_value(false)
                .about("Show only the number of non-zero matches"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .short('l')
                .takes_value(false)
                .about("Show list the processes, not the matches"),
        )
        .arg(
            Arg::new("include-self")
                .long("include-self")
                .takes_value(false)
                .about("Include also this process in the results (implied by --pids)"),
        )
        .arg(
            Arg::new("show-content")
                .long("show-content")
                .short('o')
                .takes_value(false)
                .about("Show the contents of the match (useful when using wildcards in regex)"),
        )
        .arg(
            Arg::new("pid")
                .long("pid")
                .short('p')
                .multiple(true)
                .number_of_values(1)
                .takes_value(true)
                .about("Process id to grep"),
        )
        .setting(AppSettings::TrailingVarArg)
        .arg(Arg::new("regex").multiple(false).required(true))
        .get_matches();
    if !args.is_present("pid") && !args.is_present("all") {
        println!("You need to provide either --pid or --all");
        Ok(())
    } else {
        let re = args.value_of("regex").unwrap(); /* "regex" is assumed to exist */
        let mut config = Config {
            pids: Vec::new(),
            re: String::from(re),
            only_count: args.is_present("count"),
            only_list: args.is_present("list"),
            include_self: args.is_present("include-self"),
            show_content: args.is_present("show-content"),
        };
        if args.is_present("all") {
            config.pids = all_pids()?;
            handle_pids(&config)?;
        } else {
            let pid_results: Vec<_> = args
                .values_of("pid")
                .unwrap() // "pid" is assumed to exist
                .map(|pid_str| pid_str.parse::<u64>())
                .collect();
            let pids: Vec<_> = pid_results
                .iter()
                .filter_map(|result| Result::ok(result.clone()))
                .collect();
            let errors: Vec<_> = pid_results
                .iter()
                .filter_map(|result| Result::err(result.clone()))
                .collect();
            if !errors.is_empty() {
                return Result::Err(Error::ParseIntError(errors[0].clone()));
            } else {
                config.include_self = true;
                config.pids = pids;
                handle_pids(&config)?;
            }
        }
        Ok(())
    }
}
