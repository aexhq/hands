//! Workspace sync (D7): diff the sync scope against the last manifest, upload one `tar+zstd`
//! pack of added/modified files plus a new manifest listing the whole tree; restore is the
//! inverse. Everything travels over presigned URLs handed to us per request.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use brain_protocol::abi::{
    ErrorCode, GenerationId, RestoreReport, RestoreSource, Sha256Hex, SyncEntry, SyncManifest,
    SyncManifestPackFormat, SyncManifestPacksItem, SyncRequest, SyncResponse, WallMs,
};
use globset::{Glob, GlobSet, GlobSetBuilder};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::errors::{AbiResult, err, internal};
use crate::transfer;

/// Sync scope: roots plus gitignore-style exclude patterns (matched against the path relative to
/// its root, and against every ancestor directory so excluded trees are pruned).
#[derive(Clone)]
pub struct SyncScope {
    pub roots: Vec<PathBuf>,
    exclude: GlobSet,
}

impl SyncScope {
    pub fn new(roots: Vec<PathBuf>, exclude: &[String]) -> AbiResult<Self> {
        let mut b = GlobSetBuilder::new();
        for pat in exclude {
            let g = Glob::new(pat)
                .map_err(|e| err(ErrorCode::MalformedRequest, format!("exclude {pat:?}: {e}")))?;
            b.add(g);
            // A bare directory pattern like `node_modules` should also prune its subtree.
            if !pat.contains('/')
                && !pat.contains('*')
                && let Ok(g2) = Glob::new(&format!("**/{pat}/**"))
            {
                b.add(g2);
            }
        }
        let exclude = b
            .build()
            .map_err(|e| err(ErrorCode::MalformedRequest, format!("exclude: {e}")))?;
        Ok(Self { roots, exclude })
    }

    fn excluded(&self, rel: &Path) -> bool {
        !self.exclude.is_empty() && self.exclude.is_match(rel)
    }
}

/// What the hand knows about the last manifest (restored or synced) in this generation.
#[derive(Default)]
pub struct SyncState {
    pub last: Option<SyncManifest>,
    /// path -> entry, for the diff.
    index: HashMap<String, SyncEntry>,
}

impl SyncState {
    pub fn set(&mut self, m: SyncManifest) {
        self.index = m
            .entries
            .iter()
            .map(|e| (entry_path(e).to_string(), e.clone()))
            .collect();
        self.last = Some(m);
    }
}

pub fn entry_path(e: &SyncEntry) -> &str {
    match e {
        SyncEntry::File { path, .. }
        | SyncEntry::Symlink { path, .. }
        | SyncEntry::Dir { path, .. } => path,
    }
}

enum Seen {
    File {
        path: PathBuf,
        size: u64,
        mtime_ns: u64,
        mode: i64,
    },
    Symlink {
        path: PathBuf,
        target: String,
    },
    Dir {
        path: PathBuf,
        mode: i64,
    },
}

fn walk(scope: &SyncScope) -> Vec<Seen> {
    let mut out = Vec::new();
    for root in &scope.roots {
        let scope2 = scope.clone();
        let root2 = root.clone();
        let it = WalkDir::new(root)
            .min_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_entry(move |e| {
                let rel = e.path().strip_prefix(&root2).unwrap_or(e.path());
                !scope2.excluded(rel)
            });
        for entry in it {
            let Ok(entry) = entry else { continue };
            let ft = entry.file_type();
            let path = entry.path().to_path_buf();
            let Ok(md) = entry.metadata() else { continue };
            if ft.is_symlink() {
                if let Ok(target) = std::fs::read_link(&path) {
                    out.push(Seen::Symlink {
                        path,
                        target: target.to_string_lossy().into_owned(),
                    });
                }
            } else if ft.is_dir() {
                out.push(Seen::Dir {
                    path,
                    mode: (md.mode() & 0o7777) as i64,
                });
            } else if ft.is_file() {
                out.push(Seen::File {
                    path,
                    size: md.len(),
                    mtime_ns: mtime_ns(&md),
                    mode: (md.mode() & 0o7777) as i64,
                });
            }
            // sockets, fifos, devices: not synced
        }
    }
    out
}

fn mtime_ns(md: &std::fs::Metadata) -> u64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn now_wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
}
impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Builds `<tmp_dir>/<pack_id>.tar.zst` from `files` (absolute paths). Returns (bytes, sha256).
fn build_pack(
    tmp_dir: &Path,
    pack_id: &str,
    files: &[PathBuf],
) -> std::io::Result<(PathBuf, u64, Sha256Hex)> {
    let path = tmp_dir.join(format!("{pack_id}.tar.zst"));
    let file = std::fs::File::create(&path)?;
    let hw = HashingWriter {
        inner: std::io::BufWriter::new(file),
        hasher: Sha256::new(),
        written: 0,
    };
    let enc = zstd::Encoder::new(hw, 3)?;
    let mut tar = tar::Builder::new(enc);
    tar.follow_symlinks(false);
    for f in files {
        let name = f.to_string_lossy();
        let name = name.trim_start_matches('/');
        // Skip files that vanished between the walk and the pack; the manifest below is built
        // from what the pack actually holds.
        if let Ok(mut fh) = std::fs::File::open(f) {
            let md = fh.metadata()?;
            let mut header = tar::Header::new_gnu();
            header.set_size(md.len());
            header.set_mode(md.mode() & 0o7777);
            header.set_mtime(md.mtime() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut header, name, &mut fh)?;
        }
    }
    let enc = tar.into_inner()?;
    let mut hw = enc.finish()?;
    hw.flush()?;
    let sha = Sha256Hex::try_from(hex::encode(hw.hasher.clone().finalize())).expect("hex");
    Ok((path, hw.written, sha))
}

/// One sync. `tmp_dir` is where the pack is staged (outside the sync scope).
pub async fn sync(
    client: &reqwest::Client,
    scope: &SyncScope,
    state: &mut SyncState,
    req: &SyncRequest,
    generation_id: &GenerationId,
    tmp_dir: &Path,
) -> AbiResult<SyncResponse> {
    let started = Instant::now();
    let scope2 = scope.clone();
    let seen = tokio::task::spawn_blocking(move || walk(&scope2))
        .await
        .map_err(internal)?;

    let mut entries: BTreeMap<String, SyncEntry> = BTreeMap::new();
    let mut to_pack: Vec<PathBuf> = Vec::new();
    let mut to_hash: Vec<(String, PathBuf, u64, u64, i64)> = Vec::new();
    let (mut added, mut modified) = (0u64, 0u64);
    for s in seen {
        match s {
            Seen::Dir { path, mode } => {
                entries.insert(
                    path.to_string_lossy().into_owned(),
                    SyncEntry::Dir {
                        path: path.to_string_lossy().into_owned(),
                        mode,
                    },
                );
            }
            Seen::Symlink { path, target } => {
                entries.insert(
                    path.to_string_lossy().into_owned(),
                    SyncEntry::Symlink {
                        path: path.to_string_lossy().into_owned(),
                        target,
                    },
                );
            }
            Seen::File {
                path,
                size,
                mtime_ns,
                mode,
            } => {
                let key = path.to_string_lossy().into_owned();
                let unchanged = if req.full {
                    None
                } else {
                    match state.index.get(&key) {
                        Some(SyncEntry::File {
                            size: ps,
                            mtime_ns: pm,
                            sha256,
                            pack_id,
                            ..
                        }) if *ps == size && *pm == mtime_ns => Some(SyncEntry::File {
                            path: key.clone(),
                            size,
                            mtime_ns,
                            mode,
                            sha256: sha256.clone(),
                            pack_id: pack_id.clone(),
                        }),
                        _ => None,
                    }
                };
                match unchanged {
                    Some(e) => {
                        entries.insert(key, e);
                    }
                    None => {
                        if state.index.contains_key(&key) {
                            modified += 1
                        } else {
                            added += 1
                        }
                        to_hash.push((key, path.clone(), size, mtime_ns, mode));
                        to_pack.push(path);
                    }
                }
            }
        }
    }
    let deleted = state
        .index
        .keys()
        .filter(|k| !entries.contains_key(*k) && !to_hash.iter().any(|(p, ..)| p == *k))
        .count() as u64;

    // Nothing changed at all (no file added/modified/deleted, dirs and symlinks identical): no
    // upload, the previous manifest stays current.
    let nonfile_changed = {
        let prev: BTreeMap<&String, &SyncEntry> = state
            .index
            .iter()
            .filter(|(_, e)| !matches!(e, SyncEntry::File { .. }))
            .collect();
        let cur: BTreeMap<&String, &SyncEntry> = entries
            .iter()
            .filter(|(_, e)| !matches!(e, SyncEntry::File { .. }))
            .collect();
        prev != cur
    };
    let changed = state.last.is_none() || !to_hash.is_empty() || deleted > 0 || nonfile_changed;
    if !changed {
        let m = state.last.as_ref().expect("checked");
        return Ok(SyncResponse {
            changed: false,
            manifest_id: m.manifest_id.clone(),
            files_total: m
                .entries
                .iter()
                .filter(|e| matches!(e, SyncEntry::File { .. }))
                .count() as u64,
            bytes_total: m
                .entries
                .iter()
                .map(|e| {
                    if let SyncEntry::File { size, .. } = e {
                        *size
                    } else {
                        0
                    }
                })
                .sum(),
            files_added: 0,
            files_modified: 0,
            files_deleted: 0,
            bytes_uploaded: 0,
            packs_referenced: m.packs.len() as u64,
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    // Hash + pack the changed files (blocking work).
    let pack_id = req.pack_id.clone();
    let tmp = tmp_dir.to_path_buf();
    let to_pack2 = to_pack.clone();
    let hashed: Vec<(String, u64, u64, i64, Sha256Hex)> = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        for (key, path, _size, _mtime, mode) in to_hash {
            // Re-stat at hash time so size/mtime describe exactly the bytes we hash.
            let Ok(md) = std::fs::metadata(&path) else {
                continue;
            };
            let Ok((size, sha)) = transfer::sha256_file(&path) else {
                continue;
            };
            out.push((key, size, mtime_ns(&md), mode, sha));
        }
        out
    })
    .await
    .map_err(internal)?;
    let mut bytes_uploaded = 0u64;
    let mut pack_ref: Option<SyncManifestPacksItem> = None;
    if !hashed.is_empty() {
        let (pack_path, pack_bytes, pack_sha) =
            tokio::task::spawn_blocking(move || build_pack(&tmp, &pack_id, &to_pack2))
                .await
                .map_err(internal)?
                .map_err(|e| err(ErrorCode::Internal, format!("build pack: {e}")))?;
        transfer::upload_file(client, &req.pack_put_url, &pack_path, "application/zstd").await?;
        let _ = tokio::fs::remove_file(&pack_path).await;
        bytes_uploaded = pack_bytes;
        pack_ref = Some(SyncManifestPacksItem {
            pack_id: req.pack_id.clone(),
            bytes: pack_bytes,
            sha256: Some(pack_sha),
        });
    }
    for (key, size, mtime_ns, mode, sha) in hashed {
        entries.insert(
            key.clone(),
            SyncEntry::File {
                path: key,
                size,
                mtime_ns,
                mode,
                sha256: sha,
                pack_id: req.pack_id.clone(),
            },
        );
    }

    // Packs still referenced by some file entry, plus the new one.
    let referenced: HashSet<String> = entries
        .values()
        .filter_map(|e| {
            if let SyncEntry::File { pack_id, .. } = e {
                Some(pack_id.to_string())
            } else {
                None
            }
        })
        .collect();
    let mut packs: Vec<SyncManifestPacksItem> = state
        .last
        .as_ref()
        .map(|m| {
            m.packs
                .iter()
                .filter(|p| referenced.contains(&*p.pack_id))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(p) = pack_ref
        && !packs.iter().any(|x| x.pack_id == p.pack_id)
    {
        packs.push(p);
    }
    let files_total = entries
        .values()
        .filter(|e| matches!(e, SyncEntry::File { .. }))
        .count() as u64;
    let bytes_total: u64 = entries
        .values()
        .map(|e| {
            if let SyncEntry::File { size, .. } = e {
                *size
            } else {
                0
            }
        })
        .sum();
    let manifest = SyncManifest {
        version: 1,
        manifest_id: req.manifest_id.clone(),
        parent_manifest_id: state.last.as_ref().map(|m| m.manifest_id.clone()),
        created_at_wall_ms: WallMs(now_wall_ms()),
        generation_id: generation_id.clone(),
        roots: scope
            .roots
            .iter()
            .map(|r| r.to_string_lossy().into_owned())
            .collect(),
        pack_format: SyncManifestPackFormat::TarZstd,
        packs,
        entries: entries.into_values().collect(),
    };
    let body = serde_json::to_vec(&manifest).map_err(internal)?;
    transfer::upload_bytes(client, &req.manifest_put_url, body, "application/json").await?;
    let packs_referenced = manifest.packs.len() as u64;
    state.set(manifest);
    Ok(SyncResponse {
        changed: true,
        manifest_id: req.manifest_id.clone(),
        files_total,
        bytes_total,
        files_added: added,
        files_modified: modified,
        files_deleted: deleted,
        bytes_uploaded,
        packs_referenced,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Restores a manifest + packs into the (empty or not) scope. Files listed in the manifest are
/// written with their mode and mtime; nothing else is touched.
pub async fn restore(
    client: &reqwest::Client,
    state: &mut SyncState,
    src: &RestoreSource,
    tmp_dir: &Path,
) -> AbiResult<RestoreReport> {
    let started = Instant::now();
    let resp = client
        .get(&src.manifest_get_url)
        .send()
        .await
        .map_err(|e| err(ErrorCode::RestoreFailed, format!("GET manifest: {e}")))?;
    if !resp.status().is_success() {
        return Err(err(
            ErrorCode::RestoreFailed,
            format!(
                "GET manifest {}: HTTP {}",
                transfer::redact(&src.manifest_get_url),
                resp.status()
            ),
        ));
    }
    let manifest: SyncManifest = resp
        .json()
        .await
        .map_err(|e| err(ErrorCode::RestoreFailed, format!("manifest json: {e}")))?;
    if manifest.manifest_id != src.manifest_id {
        return Err(err(
            ErrorCode::RestoreFailed,
            format!(
                "manifest id {} != requested {}",
                *manifest.manifest_id, *src.manifest_id
            ),
        ));
    }
    // Directories first (so modes apply after files land: mode 0o500 dirs would block writes).
    let mut dirs: Vec<(PathBuf, i64)> = Vec::new();
    let mut wanted: HashMap<String, HashMap<String, (i64, u64)>> = HashMap::new(); // pack -> path -> (mode, mtime)
    let mut symlinks: Vec<(PathBuf, String)> = Vec::new();
    for e in &manifest.entries {
        match e {
            SyncEntry::Dir { path, mode } => dirs.push((PathBuf::from(path), *mode)),
            SyncEntry::Symlink { path, target } => {
                symlinks.push((PathBuf::from(path), target.clone()))
            }
            SyncEntry::File {
                path,
                mode,
                mtime_ns,
                pack_id,
                ..
            } => {
                wanted
                    .entry(pack_id.to_string())
                    .or_default()
                    .insert(path.clone(), (*mode, *mtime_ns));
            }
        }
    }
    for (d, _) in &dirs {
        std::fs::create_dir_all(d).map_err(|e| {
            err(
                ErrorCode::RestoreFailed,
                format!("mkdir {}: {e}", d.display()),
            )
        })?;
    }
    let mut files = 0u64;
    let mut bytes = 0u64;
    let url_by_pack: HashMap<String, String> = src
        .packs
        .iter()
        .map(|p| (p.pack_id.to_string(), p.get_url.clone()))
        .collect();
    for (pack_id, paths) in wanted {
        let Some(url) = url_by_pack.get(&pack_id) else {
            return Err(err(
                ErrorCode::RestoreFailed,
                format!("manifest references pack {pack_id} but no URL was given for it"),
            ));
        };
        let tmp = tmp_dir.join(format!("restore-{pack_id}.tar.zst"));
        transfer::download_to(client, url, &tmp, None, None)
            .await
            .map_err(|e| {
                err(
                    ErrorCode::RestoreFailed,
                    format!("pack {pack_id}: {}", e.message),
                )
            })?;
        let tmp2 = tmp.clone();
        let (n, b) = tokio::task::spawn_blocking(move || extract_pack(&tmp2, &paths))
            .await
            .map_err(internal)?
            .map_err(|e| {
                err(
                    ErrorCode::RestoreFailed,
                    format!("extract pack {pack_id}: {e}"),
                )
            })?;
        let _ = tokio::fs::remove_file(&tmp).await;
        files += n;
        bytes += b;
    }
    for (path, target) in symlinks {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&path);
        std::os::unix::fs::symlink(&target, &path).map_err(|e| {
            err(
                ErrorCode::RestoreFailed,
                format!("symlink {}: {e}", path.display()),
            )
        })?;
    }
    for (d, mode) in &dirs {
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(*mode as u32));
    }
    let report = RestoreReport {
        manifest_id: manifest.manifest_id.clone(),
        files,
        bytes,
        duration_ms: started.elapsed().as_millis() as u64,
    };
    state.set(manifest);
    Ok(report)
}

fn extract_pack(pack: &Path, wanted: &HashMap<String, (i64, u64)>) -> std::io::Result<(u64, u64)> {
    let file = std::fs::File::open(pack)?;
    let dec = zstd::Decoder::new(std::io::BufReader::new(file))?;
    let mut archive = tar::Archive::new(dec);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);
    let (mut files, mut bytes) = (0u64, 0u64);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        let abs = format!("/{}", name.trim_start_matches('/'));
        let Some((mode, mtime_ns)) = wanted.get(&abs) else {
            continue;
        };
        let dest = PathBuf::from(&abs);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&dest);
        entry.unpack(&dest)?;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(*mode as u32))?;
        let ft = filetime::FileTime::from_unix_time(
            (mtime_ns / 1_000_000_000) as i64,
            (mtime_ns % 1_000_000_000) as u32,
        );
        filetime::set_file_mtime(&dest, ft)?;
        files += 1;
        bytes += entry.header().size().unwrap_or(0);
    }
    Ok((files, bytes))
}
