use anyhow;
use core::ops::Range;
use std::iter::FromIterator;
use thiserror::Error;

use hyperscan::{
    prelude::*, // Pattern, Database,
    Patterns,
    Streaming,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    AnyError(#[from] anyhow::Error),
}

pub struct MatcherCommon {
    database: Database<Streaming>,
}

pub struct MatcherPerThread<'a> {
    common: &'a MatcherCommon,
    scratch: Scratch,
}

pub struct MatcherStream<'a> {
    thread: &'a MatcherPerThread<'a>,
    stream: Option<Stream>,
}

pub fn make_matcher_common(regexp: &str) -> Result<MatcherCommon, Error> {
    let pattern = Pattern::with_flags(
        regexp,
        CompileFlags::DOTALL | CompileFlags::MULTILINE | CompileFlags::SOM_LEFTMOST,
    )?;
    let patterns = Patterns::from_iter(vec![pattern].into_iter());
    let database = patterns.build::<Streaming>()?;

    Ok(MatcherCommon { database })
}

pub fn make_matcher_per_thread(matcher_common: &MatcherCommon) -> MatcherPerThread {
    let scratch = matcher_common.database.alloc_scratch().expect("scratch");

    MatcherPerThread {
        common: &matcher_common,
        scratch,
    }
}

pub fn make_matcher_stream<'a>(matcher_per_thread: &'a MatcherPerThread) -> MatcherStream<'a> {
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

pub struct Match {
    pub range: Range<usize>,
}

pub struct MatcherCallback<'a> {
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

pub fn make_matcher_callback<'a>(matches: &'a mut Vec<Match>, offset: u64) -> MatcherCallback<'a> {
    MatcherCallback { matches, offset }
}

pub fn call_matcher<'a>(
    matcher_stream: &MatcherStream<'a>,
    callback: &mut MatcherCallback,
    data: &[u8],
) {
    let stream = matcher_stream.stream.as_deref().expect("stream expected");
    stream
        .scan(data, &matcher_stream.thread.scratch, callback)
        .expect("scan stream");
}

pub fn reset_matcher(matcher_stream: &mut MatcherStream, callback: &mut MatcherCallback) {
    let stream = matcher_stream.stream.as_deref().expect("stream expected");
    stream
        .reset(&matcher_stream.thread.scratch, callback)
        .expect("reset stream");
}

pub fn destroy_matcher(matcher_stream: &mut MatcherStream) {
    matcher_stream
        .stream
        .take()
        .expect("stream expected")
        .close(&matcher_stream.thread.scratch, |_, _, _, _| {
            Matching::Continue
        })
        .expect("close stream");
}
