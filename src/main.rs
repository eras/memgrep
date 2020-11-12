use clap::{App, Arg}; // AppSettings
use lazy_static::lazy_static;
use regex::bytes::Regex as RegexB;
use regex::Regex;
use std::fs::File;
use std::io::{prelude::*, BufReader, SeekFrom};

#[derive(Copy, Clone, Debug)]
struct Permisisons {
    r: bool,
    w: bool,
    x: bool,
    p: bool, // TODO: s
}

#[derive(Debug)]
struct MemMapping {
    begin: u64,
    end: u64,
    perms: Permisisons,
    label: String,
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

fn read_mapping(filename: &str) -> Result<Vec<MemMapping>, Box<dyn std::error::Error>> {
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
        .unwrap();
    }

    let mut count = 0;
    let mappings = reader
        .lines()
        .map(|line| {
            count += 1;
            RE.captures(&line.unwrap())
                .and_then(|cap| {
                    let begin = cap.name("begin").expect("begin").as_str();
                    let end = cap.name("end").expect("end").as_str();
                    let perms = cap.name("perms").expect("perms").as_str();
                    let label = cap.name("label").expect("label").as_str();
                    Some({
                        MemMapping {
                            begin: u64::from_str_radix(begin, 16).unwrap(),
                            end: u64::from_str_radix(end, 16).unwrap(),
                            perms: Permisisons {
                                r: perms.chars().nth(0) == Some('r'),
                                w: perms.chars().nth(0) == Some('w'),
                                x: perms.chars().nth(0) == Some('x'),
                                p: perms.chars().nth(0) == Some('p'),
                            },
                            label: label.to_string(),
                        }
                    })
                })
                .expect(format!("failed to parse {} at {}", &filename, count).as_str())
        })
        .collect();

    Ok(mappings)
}

fn grepper(core: &str,
           mappings: Vec<MemMapping>,
           re : RegexB) -> Result<u64, Box<dyn std::error::Error>> {
    let mut file = File::open(core)?;

    let mut num_matches : u64 = 0;
    
    for mapping in mappings.iter() {
        if mapping.perms.r {
            let size = (mapping.end - mapping.begin) as usize;
            let mut buf = Vec::with_capacity(size);
            unsafe {
                buf.set_len(size);
            }
            file.seek(SeekFrom::Start(mapping.begin))?;
            match file.read_exact(&mut buf) {
                Ok (()) => {
                    for capture in re.captures_iter(&buf) {
                        num_matches += 1
                    }
                    // println!("done greppin'");
                }
                Err(_) => {
                    // ignore read errors
                }
            }
        }
    }
    Ok (num_matches)
}

fn handle_pid(pid: u64, re: RegexB) -> Result<u64, Box<dyn std::error::Error>> {
    let mapping = read_mapping(&format!("/proc/{}/maps", pid))?;
    grepper(&format!("/proc/{}/mem", pid), mapping, re)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = App::new("memgrep")
        .version("0.1.0")
        .author("Erkki Seppälä <flux@inside.org>")
        .about("Grep for process memory spaces")
        .arg(
            Arg::new("all")
                .long("all")
                .short('a')
                .takes_value(false)
                .about("Grep all processes"),
        )
        .arg(
            Arg::new("pid")
                .long("pid")
                .short('p')
                .multiple(true)
                .takes_value(true)
                .about("Process id to grep"),
        )
        .arg(
            Arg::new("regex")
                .long("regexp")
                .short('r')
                .required(true)
                .multiple(true)
                .takes_value(true)
                .about("Regular expresison to use"),
        )
        //.setting(AppSettings::TrailingVarArg)
        // .arg(
        //     Arg::new("regexp")
        //         .multiple(true)
        //         .value_hint(ValueHint::CommandWithArguments)
        // )
        .get_matches();
    if !args.is_present("pid") && !args.is_present("all") {
        println!("You need to provide either --pid or --all");
        Ok(())
    } else {
        let re: RegexB = RegexB::new(args.value_of("regex").unwrap())?;
        if args.is_present("all") {
            for entry in std::fs::read_dir("/proc")? {
                match entry?.file_name().into_string().unwrap().parse::<u64>() {
                    Ok (pid) => {
                        match handle_pid(pid, re.clone()) {
                            Ok (matches) => {
                                if matches > 0 {
                                    println!("{} {}", pid, matches);
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        // skip non-numeric entries
                    }
                }
            }
        } else {
            for pid in args.values_of("pid").unwrap() {
                match handle_pid(pid.parse::<u64>().unwrap(), re.clone()) {
                    Ok (matches) => {
                        println!("{} {}", pid, matches);
                    }
                    _ => {}
                }
            }
        }
        Ok (())
    }
}
