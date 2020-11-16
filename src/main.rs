use clap::{App, Arg}; // AppSettings
use core::ops::Range;
use lazy_static::lazy_static;
use regex;
use regex::bytes::Regex as RegexB;
use regex::Regex;
use std::fs::{read_link, File};
use std::io::{self, prelude::*, BufReader, SeekFrom};
use std::sync::{Arc, Mutex};
use thiserror::Error;

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
    re: RegexB,
    only_count: bool,
    only_list: bool,
    include_self: bool,
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
                .and_then(|cap| {
                    let begin = cap.name("begin").expect("begin").as_str();
                    let end = cap.name("end").expect("end").as_str();
                    let perms = cap.name("perms").expect("perms").as_str();
                    let label = cap.name("label").expect("label").as_str();
                    Some({
                        MemMapping {
                            begin: u64::from_str_radix(begin, 16).unwrap() /* assumed to contain valid hex */,
                            end: u64::from_str_radix(end, 16).unwrap() /* assumed to contain valid hex */,
                            perms: Permissions {
                                r: perms.chars().nth(0) == Some('r'),
                                w: perms.chars().nth(1) == Some('w'),
                                x: perms.chars().nth(2) == Some('x'),
                                p: match perms.chars().nth(3) {
				    Some ('p') => Some(PS::P),
				    Some ('s') => Some(PS::S),
				    Some ('-') => None,
				    _ => panic!("Unsupported format in /proc/pid/maps"),
				}
                            },
                            label: label.to_string(),
                        }
                    })
                })
		.ok_or(format!("failed to parse {} at {}", &filename, count).to_owned())
        })
        .collect();

    let errors: Vec<_> = mapping_results
        .iter()
        .filter_map(|result| Result::err(result.clone()))
        .collect();

    if errors.len() > 0 {
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

fn grepper(core: &str, mappings: Vec<MemMapping>, re: &RegexB) -> Result<GrepResults, Error> {
    let mut file = File::open(core)?;

    let mut matches = Vec::new();

    let mut buf = Vec::with_capacity(1024000);

    for mapping in mappings.iter() {
        if mapping.perms.r {
            let size = (mapping.end - mapping.begin) as usize;
            buf.resize(size, 0);
            file.seek(SeekFrom::Start(mapping.begin))?;
            match file.read_exact(&mut buf) {
                Ok(()) => {
                    for match_ in re.find_iter(&buf) {
                        let mut range = match_.range();
                        range.start += mapping.begin as usize;
                        range.end += mapping.begin as usize;
                        matches.push(Match { range })
                    }
                    // println!("done greppin'");
                }
                Err(_) => {
                    // ignore read errors
                }
            }
        }
    }
    Ok(matches)
}

fn handle_pid(pid: u64, re: &RegexB) -> Result<GrepResults, Error> {
    let mapping = read_mapping(&format!("/proc/{}/maps", pid))?;
    grepper(&format!("/proc/{}/mem", pid), mapping, re)
}

fn show_matches(pid: u64, matches: GrepResults, config: &Config) {
    if matches.len() > 0 {
        let executable = read_link(format!("/proc/{}/exe", pid))
            .map_or(String::from("(cannot read)"), |filename| {
                String::from(filename.to_str().map_or("(invalid unicode)", |x| x))
            });
        print!("{} {}", pid, executable);
        if config.only_list {
            println!("");
        } else if config.only_count {
            println!(": {}", matches.len());
        } else {
            println!(":");
            for match_ in matches {
                println!("  {:x}-{:x}", match_.range.start, match_.range.end);
            }
        }
    }
}

fn all_pids() -> Result<Vec<u64>, Error> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        match entry?
            .file_name()
            .into_string()
            .unwrap() /* assumed to contain legal unicode */
            .parse::<u64>()
        {
            Ok(pid) => pids.push(pid),
            _ => {
                // skip non-numeric entries
            }
        }
    }
    return Ok(pids);
}

fn handle_pids(config: &Config) -> Result<(), Error> {
    // TODO: it would be cooler to have a thread receive the results
    // and thus replace the mutex?  it would also be path forward for
    // json outupt
    let output_mutex = Arc::new(Mutex::new(()));
    rayon::scope(|scope| {
        for pid in &config.pids {
            if config.include_self || *pid != std::process::id() as u64 {
                let output_mutex_ = Arc::clone(&output_mutex);
                scope.spawn(move |_| match handle_pid(*pid, &config.re) {
                    Ok(matches) => {
                        let _guard = output_mutex_.lock().unwrap() /* assumed to succeed */;
                        show_matches(*pid, matches, config);
                    }
                    _ => {}
                })
            }
        }
    });
    return Ok(());
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
            Arg::new("pid")
                .long("pid")
                .short('p')
                .multiple(true)
                .number_of_values(1)
                .takes_value(true)
                .about("Process id to grep"),
        )
        .arg(
            Arg::new("regex")
                .long("regex")
                .short('r')
                .required(true)
                .multiple(false)
                .takes_value(true)
                .about("Regular expression to use"),
        )
        //.setting(AppSettings::TrailingVarArg)
        // .arg(
        //     Arg::new("regex")
        //         .multiple(true)
        //         .value_hint(ValueHint::CommandWithArguments)
        // )
        .get_matches();
    if !args.is_present("pid") && !args.is_present("all") {
        println!("You need to provide either --pid or --all");
        Ok(())
    } else {
        let re: RegexB = RegexB::new(
            args.value_of("regex").unwrap(), /* "regex" is assumed to exist */
        )?;
        let mut config = Config {
            pids: Vec::new(),
            re: re.clone(),
            only_count: args.is_present("count"),
            only_list: args.is_present("list"),
            include_self: args.is_present("include-self"),
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
            if errors.len() > 0 {
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
