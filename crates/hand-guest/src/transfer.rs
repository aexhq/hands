//! Files in and out over presigned URLs (I8: the hand holds no credential), and the sync-scope
//! path check used by `put`, `persist` and `sync`.

use std::path::{Component, Path, PathBuf};

use aex_contracts::abi::{ErrorCode, Sha256Hex};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::errors::{AbiResult, err, err_retryable};

/// The directories a session may read/write through the ABI: `hello.sync.roots`, canonicalised.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub roots: Vec<PathBuf>,
}

impl Scope {
    pub fn new(roots: &[String]) -> AbiResult<Self> {
        let mut out = Vec::new();
        for r in roots {
            let p = Path::new(r);
            if !p.is_absolute() {
                return Err(err(
                    ErrorCode::MalformedRequest,
                    format!("sync root {r} is not absolute"),
                ));
            }
            std::fs::create_dir_all(p)
                .map_err(|e| err(ErrorCode::Internal, format!("create root {r}: {e}")))?;
            let c = p
                .canonicalize()
                .map_err(|e| err(ErrorCode::Internal, format!("canonicalize root {r}: {e}")))?;
            out.push(c);
        }
        Ok(Self { roots: out })
    }

    /// Resolves `path` (absolute; symlinks in the existing prefix followed) and checks it lies
    /// under one of the roots. Returns the resolved absolute path.
    pub fn resolve(&self, path: &str) -> AbiResult<PathBuf> {
        let p = Path::new(path);
        if !p.is_absolute() {
            return Err(err(
                ErrorCode::PathOutsideScope,
                format!("{path}: must be absolute"),
            ));
        }
        let resolved = resolve_existing_prefix(p);
        if self.roots.iter().any(|r| resolved.starts_with(r)) {
            Ok(resolved)
        } else {
            Err(err(
                ErrorCode::PathOutsideScope,
                format!(
                    "{path} resolves to {} which is outside the sync scope",
                    resolved.display()
                ),
            ))
        }
    }
}

/// Canonicalises the longest existing prefix of `p` and appends the rest (normalised).
pub fn resolve_existing_prefix(p: &Path) -> PathBuf {
    let mut existing = p.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => break,
        }
    }
    let mut out = existing.canonicalize().unwrap_or(existing);
    for name in rest.into_iter().rev() {
        match Path::new(&name).components().next() {
            Some(Component::ParentDir) => {
                out.pop();
            }
            Some(Component::CurDir) | None => {}
            _ => out.push(name),
        }
    }
    out
}

pub fn sha256_hex(bytes: &[u8]) -> Sha256Hex {
    Sha256Hex::try_from(hex::encode(Sha256::digest(bytes))).expect("hex")
}

pub fn sha256_file(path: &Path) -> std::io::Result<(u64, Sha256Hex)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((
        total,
        Sha256Hex::try_from(hex::encode(hasher.finalize())).expect("hex"),
    ))
}

/// Streams a GET into `dest` (written via a temp file next to it), verifying size and digest.
pub async fn download_to(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    expected_bytes: Option<u64>,
    expected_sha: Option<&Sha256Hex>,
) -> AbiResult<(u64, Sha256Hex)> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| err_retryable(ErrorCode::TransferFailed, format!("GET: {e}")))?;
    if !resp.status().is_success() {
        return Err(err_retryable(
            ErrorCode::TransferFailed,
            format!("GET {}: HTTP {}", redact(url), resp.status()),
        ));
    }
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| err(ErrorCode::Internal, format!("mkdir: {e}")))?;
    }
    let tmp = dest.with_extension(format!(
        "{}.aex-tmp",
        dest.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .map_err(|e| err(ErrorCode::Internal, format!("create: {e}")))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| err_retryable(ErrorCode::TransferFailed, format!("GET body: {e}")))?;
        hasher.update(&chunk);
        total += chunk.len() as u64;
        if let Some(limit) = expected_bytes
            && total > limit
        {
            drop(file);
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err(
                ErrorCode::ChecksumMismatch,
                format!("body exceeds declared {limit} bytes"),
            ));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| err(ErrorCode::Internal, format!("write: {e}")))?;
    }
    file.flush()
        .await
        .map_err(|e| err(ErrorCode::Internal, format!("flush: {e}")))?;
    drop(file);
    let sha = Sha256Hex::try_from(hex::encode(hasher.finalize())).expect("hex");
    if expected_bytes.is_some_and(|b| b != total) || expected_sha.is_some_and(|s| *s != sha) {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(err(
            ErrorCode::ChecksumMismatch,
            format!(
                "downloaded {} bytes sha256 {}; expected {:?} bytes sha256 {:?}",
                total,
                *sha,
                expected_bytes,
                expected_sha.map(|s| s.to_string())
            ),
        ));
    }
    tokio::fs::rename(&tmp, dest)
        .await
        .map_err(|e| err(ErrorCode::Internal, format!("rename into place: {e}")))?;
    Ok((total, sha))
}

/// PUTs a file's bytes to `url`. Returns (bytes, sha256).
pub async fn upload_file(
    client: &reqwest::Client,
    url: &str,
    path: &Path,
    media_type: &str,
) -> AbiResult<(u64, Sha256Hex)> {
    let p = path.to_path_buf();
    let (len, sha) = tokio::task::spawn_blocking(move || sha256_file(&p))
        .await
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?
        .map_err(|e| err(ErrorCode::PathNotFound, format!("{}: {e}", path.display())))?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| err(ErrorCode::PathNotFound, format!("{}: {e}", path.display())))?;
    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
    let resp = client
        .put(url)
        .header(reqwest::header::CONTENT_TYPE, media_type)
        .header(reqwest::header::CONTENT_LENGTH, len)
        .body(body)
        .send()
        .await
        .map_err(|e| err_retryable(ErrorCode::TransferFailed, format!("PUT: {e}")))?;
    if !resp.status().is_success() {
        return Err(err_retryable(
            ErrorCode::TransferFailed,
            format!("PUT {}: HTTP {}", redact(url), resp.status()),
        ));
    }
    Ok((len, sha))
}

pub async fn upload_bytes(
    client: &reqwest::Client,
    url: &str,
    bytes: Vec<u8>,
    media_type: &str,
) -> AbiResult<(u64, Sha256Hex)> {
    let len = bytes.len() as u64;
    let sha = sha256_hex(&bytes);
    let resp = client
        .put(url)
        .header(reqwest::header::CONTENT_TYPE, media_type)
        .header(reqwest::header::CONTENT_LENGTH, len)
        .body(bytes)
        .send()
        .await
        .map_err(|e| err_retryable(ErrorCode::TransferFailed, format!("PUT: {e}")))?;
    if !resp.status().is_success() {
        return Err(err_retryable(
            ErrorCode::TransferFailed,
            format!("PUT {}: HTTP {}", redact(url), resp.status()),
        ));
    }
    Ok((len, sha))
}

/// Presigned URLs carry a signature in the query string; never echo it into errors or logs.
pub fn redact(url: &str) -> String {
    match url.split_once('?') {
        Some((base, _)) => format!("{base}?<redacted>"),
        None => url.to_string(),
    }
}
