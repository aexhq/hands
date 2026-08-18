//! Per-stream spill store with bounded tail retention.
//!
//! Output is appended to a file under the spill dir and read back by byte offset (I7: bytes
//! never travel as tool results, only bounded slices). Retention is `max_retained_bytes` per
//! stream, kept as **two segments of half that size**: when the newer segment fills, the older
//! one is deleted. So the retained region is always the most recent `[cap/2, cap]` bytes and
//! `retained_from` marks its start; a read below it is `operation_output_evicted`.
//!
//! While the stream fits in a single segment (the common case) that segment's path is exposed
//! as `spill_path`, readable by the agent's own tools.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aex_contracts::abi::Sha256Hex;
use sha2::{Digest, Sha256};

pub const MIN_SEGMENT_BYTES: u64 = 4096;

struct Segment {
    start: u64,
    len: u64,
    path: PathBuf,
    file: File,
}

pub struct Spill {
    dir: PathBuf,
    name: String,
    seg_cap: u64,
    segments: VecDeque<Segment>,
    produced: u64,
    /// Running digest of the whole stream; only meaningful (reported) if nothing was evicted.
    hasher: Sha256,
    evicted: bool,
    next_seg_no: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("offset {offset} predates the retained region starting at {retained_from}")]
    Evicted { offset: u64, retained_from: u64 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Spill {
    /// `name` is e.g. `op-0001.stdout`; segments are `<name>` (first) then `<name>.<n>`.
    pub fn new(dir: &Path, name: &str, max_retained_bytes: u64) -> Self {
        let seg_cap = (max_retained_bytes / 2).max(MIN_SEGMENT_BYTES);
        Self {
            dir: dir.to_path_buf(),
            name: name.to_string(),
            seg_cap,
            segments: VecDeque::new(),
            produced: 0,
            hasher: Sha256::new(),
            evicted: false,
            next_seg_no: 0,
        }
    }

    pub fn produced(&self) -> u64 {
        self.produced
    }

    pub fn retained_from(&self) -> u64 {
        self.segments
            .front()
            .map(|s| s.start)
            .unwrap_or(self.produced)
    }

    pub fn retained_bytes(&self) -> u64 {
        self.produced - self.retained_from()
    }

    pub fn evicted(&self) -> bool {
        self.evicted
    }

    /// Path of the single segment while the stream fits in one; `None` once it has rolled.
    pub fn spill_path(&self) -> Option<PathBuf> {
        if self.segments.len() == 1 && self.next_seg_no == 1 {
            self.segments.front().map(|s| s.path.clone())
        } else {
            None
        }
    }

    /// Digest over the whole stream, only when nothing was evicted (else it would not describe
    /// what the reader can read).
    pub fn sha256(&self) -> Option<Sha256Hex> {
        if self.evicted {
            return None;
        }
        let digest = self.hasher.clone().finalize();
        Some(Sha256Hex::try_from(hex::encode(digest)).expect("hex sha256"))
    }

    fn open_segment(&mut self) -> std::io::Result<()> {
        let path = if self.next_seg_no == 0 {
            self.dir.join(&self.name)
        } else {
            self.dir.join(format!("{}.{}", self.name, self.next_seg_no))
        };
        self.next_seg_no += 1;
        // Append mode: writes always land at end even though `read` seeks this same handle.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        self.segments.push_back(Segment {
            start: self.produced,
            len: 0,
            path,
            file,
        });
        if self.segments.len() > 2
            && let Some(old) = self.segments.pop_front()
        {
            drop(old.file);
            let _ = std::fs::remove_file(&old.path);
            self.evicted = true;
        }
        Ok(())
    }

    pub fn append(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        self.hasher.update(data);
        while !data.is_empty() {
            let need_new = match self.segments.back() {
                None => true,
                Some(s) => s.len >= self.seg_cap,
            };
            if need_new {
                self.open_segment()?;
            }
            let seg_cap = self.seg_cap;
            let seg = self.segments.back_mut().expect("segment");
            let room = (seg_cap - seg.len) as usize;
            let n = room.min(data.len());
            seg.file.write_all(&data[..n])?;
            seg.len += n as u64;
            self.produced += n as u64;
            data = &data[n..];
        }
        Ok(())
    }

    /// Bytes from `offset`, at most `max`. `eof` = the returned slice reaches `produced`.
    pub fn read(&mut self, offset: u64, max: usize) -> Result<(Vec<u8>, bool), ReadError> {
        let retained_from = self.retained_from();
        if offset < retained_from {
            return Err(ReadError::Evicted {
                offset,
                retained_from,
            });
        }
        let mut out = Vec::new();
        let mut pos = offset;
        for seg in self.segments.iter_mut() {
            if out.len() >= max || pos >= self.produced {
                break;
            }
            let seg_end = seg.start + seg.len;
            if pos >= seg_end {
                continue;
            }
            let in_seg = pos - seg.start;
            let want = ((seg_end - pos) as usize).min(max - out.len());
            seg.file.seek(SeekFrom::Start(in_seg))?;
            let mut buf = vec![0u8; want];
            let mut filled = 0;
            while filled < want {
                let n = seg.file.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            buf.truncate(filled);
            pos += filled as u64;
            out.extend_from_slice(&buf);
            if filled < want {
                break;
            }
        }
        let eof = pos >= self.produced;
        Ok((out, eof))
    }

    /// Reads the whole retained region (for `persist` of an operation stream).
    pub fn read_retained(&mut self) -> Result<Vec<u8>, ReadError> {
        let from = self.retained_from();
        let len = (self.produced - from) as usize;
        Ok(self.read(from, len)?.0)
    }

    pub fn remove(&mut self) {
        while let Some(seg) = self.segments.pop_front() {
            drop(seg.file);
            let _ = std::fs::remove_file(&seg.path);
        }
    }

    /// Forces retained bytes to durable storage. Called from the `/suspend` lifecycle hook so
    /// the snapshot the platform takes holds every byte the streams have produced.
    pub fn flush(&mut self) {
        for seg in &self.segments {
            let _ = seg.file.sync_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_the_tail_in_two_segments() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Spill::new(dir.path(), "t.stdout", 8192); // segments of 4096
        assert_eq!(s.retained_from(), 0);
        s.append(&[b'a'; 3000]).unwrap();
        assert!(s.spill_path().is_some());
        assert_eq!(s.read(0, 10).unwrap().0, vec![b'a'; 10]);
        s.append(&[b'b'; 3000]).unwrap(); // rolls into segment 2 at offset 4096
        assert_eq!(s.produced(), 6000);
        assert_eq!(s.retained_from(), 0);
        assert!(s.spill_path().is_none());
        // Read across the a->b transition inside segment 1 (a: 0..3000, b: 3000..6000).
        let (bytes, eof) = s.read(2997, 6).unwrap();
        assert_eq!(bytes, b"aaabbb".to_vec());
        assert!(!eof);
        // Read across the segment-1/segment-2 boundary at 4096 (all b there).
        let (bytes, eof) = s.read(4093, 6).unwrap();
        assert_eq!(bytes, vec![b'b'; 6]);
        assert!(!eof);
        s.append(&[b'c'; 3000]).unwrap(); // rolls again: segment 1 (0..4096) evicted
        assert_eq!(s.retained_from(), 4096);
        assert!(s.evicted());
        assert!(s.sha256().is_none());
        assert!(matches!(s.read(0, 10), Err(ReadError::Evicted { .. })));
        let (bytes, eof) = s.read(8000, 10_000).unwrap();
        assert_eq!(bytes.len(), 1000);
        assert!(eof);
        assert_eq!(bytes[0], b'c');
        s.remove();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn digest_covers_the_whole_stream_when_nothing_evicted() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Spill::new(dir.path(), "t.stdout", 1 << 20);
        s.append(b"hello ").unwrap();
        s.append(b"world").unwrap();
        let expected = hex::encode(Sha256::digest(b"hello world"));
        assert_eq!(&*s.sha256().unwrap(), &expected);
        assert_eq!(s.read_retained().unwrap(), b"hello world".to_vec());
    }
}
