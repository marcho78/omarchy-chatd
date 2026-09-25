//! Attachments: describing them, fetching them into a cache, sending them.
//!
//! Downloads land in `$XDG_CACHE_HOME/omarchy-yapper/media/`, named by a
//! hash of the event id so the same file is never fetched twice. In
//! encrypted rooms the SDK decrypts on the way in and encrypts on the way
//! out; nothing here touches keys.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};

use std::{future::Future, io::Read, pin::Pin, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use matrix_sdk::{
    Client,
    attachment::{AttachmentConfig, AttachmentInfo, BaseAudioInfo, BaseFileInfo, BaseImageInfo},
    media::{MediaEventContent, MediaFetcher, MediaFormat, MediaRequestParameters, MediaThumbnailSettings},
    ruma::{
        EventId, UInt,
        api::{Metadata as _, client::authenticated_media},
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent, SyncMessageLikeEvent,
            room::{
                MediaSource,
                message::{MessageType, TextMessageEventContent},
            },
        },
        media::Method,
    },
};
use tracing::info;

use crate::{core::Core, protocol::Attachment};

const THUMB_SIZE: u32 = 640;
const MAX_UPLOAD: u64 = 100 * 1024 * 1024;
/// The most a single attachment download may occupy, matching the upload limit.
const MAX_DOWNLOAD: u64 = 100 * 1024 * 1024;
/// A server-side thumbnail is small by construction; anything past this is not one.
const MAX_THUMBNAIL: u64 = 16 * 1024 * 1024;
/// The whole download, connect to last byte.
const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(300);

/// Downloads media in bounded pieces: the response is refused if it declares
/// more than the cap, dropped the moment it exceeds it, and abandoned when
/// the deadline passes. Installed on every Client the daemon builds, so the
/// SDK's cache and thumbnail handling stay in place with its own unbounded
/// fetch replaced. Encrypted files are decrypted after the capped download.
#[derive(Debug, Default)]
pub struct BoundedMediaFetcher;

pub fn bounded_media_fetcher() -> Arc<dyn MediaFetcher> {
    Arc::new(BoundedMediaFetcher)
}

fn media_error(msg: impl Into<String>) -> matrix_sdk::Error {
    matrix_sdk::Error::UnknownError(msg.into().into())
}

impl MediaFetcher for BoundedMediaFetcher {
    fn fetch_media_content<'a>(
        &'a self,
        client: &'a Client,
        request: &'a MediaRequestParameters,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, matrix_sdk::Error>> + Send + 'a>> {
        Box::pin(async move {
            let (uri, encrypted) = match &request.source {
                MediaSource::Encrypted(file) => (&file.url, Some(file.as_ref())),
                MediaSource::Plain(uri) => (uri, None),
            };
            let (server, media_id) = uri.parts().map_err(|e| media_error(format!("bad mxc uri: {e}")))?;
            // A thumbnail request for an encrypted file makes no sense server-side; fetch the file.
            let thumbnail = match &request.format {
                MediaFormat::Thumbnail(settings) if encrypted.is_none() => Some(settings),
                _ => None,
            };
            let cap = if thumbnail.is_some() { MAX_THUMBNAIL } else { MAX_DOWNLOAD };

            // The same endpoints the SDK uses: authenticated media when the server has it.
            let versions = client.supported_versions().await?;
            let use_auth = authenticated_media::get_content::v1::Request::PATH_BUILDER.is_supported(&versions);
            let mut url = client.homeserver();
            {
                let mut segments = url
                    .path_segments_mut()
                    .map_err(|_| media_error("homeserver url cannot take a path"))?;
                segments.pop_if_empty();
                if use_auth {
                    segments.extend(["_matrix", "client", "v1", "media"]);
                } else {
                    segments.extend(["_matrix", "media", "v3"]);
                }
                segments.push(if thumbnail.is_some() { "thumbnail" } else { "download" });
                segments.push(server.as_str());
                segments.push(media_id);
            }
            if let Some(settings) = thumbnail {
                let method = match settings.method {
                    Method::Crop => "crop",
                    _ => "scale",
                };
                url.query_pairs_mut()
                    .append_pair("width", &settings.width.to_string())
                    .append_pair("height", &settings.height.to_string())
                    .append_pair("method", method)
                    .append_pair("animated", if settings.animated { "true" } else { "false" });
            }
            let mut req = client.http_client().get(url);
            if use_auth {
                let token = client.access_token().ok_or_else(|| media_error("not signed in"))?;
                req = req.bearer_auth(token);
            }

            let bytes = tokio::time::timeout(DOWNLOAD_DEADLINE, async {
                let response = req.send().await.map_err(|e| media_error(format!("download: {e}")))?;
                let status = response.status();
                if !status.is_success() {
                    return Err(media_error(format!("download: server answered {status}")));
                }
                if let Some(len) = response.content_length()
                    && len > cap
                {
                    return Err(media_error(format!("download: {len} bytes declared, the limit is {cap}")));
                }
                let mut response = response;
                let mut buf: Vec<u8> = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|e| media_error(format!("download: {e}")))? {
                    if buf.len() as u64 + chunk.len() as u64 > cap {
                        return Err(media_error(format!("download: more than {cap} bytes, stopped")));
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(buf)
            })
            .await
            .map_err(|_| media_error(format!("download: no result within {} s", DOWNLOAD_DEADLINE.as_secs())))??;

            info!(
                bytes = bytes.len(),
                thumbnail = thumbnail.is_some(),
                encrypted = encrypted.is_some(),
                "media downloaded within the cap"
            );
            let Some(file) = encrypted else { return Ok(bytes) };
            let len = bytes.len();
            let mut cursor = std::io::Cursor::new(bytes);
            let mut reader = matrix_sdk_base::crypto::AttachmentDecryptor::new(&mut cursor, file.clone().into())?;
            let mut decrypted = Vec::with_capacity(len);
            reader.read_to_end(&mut decrypted)?;
            Ok(decrypted)
        })
    }
}
/// ffmpeg loudness filter for voice: the usual speech target, with a
/// true-peak ceiling so it never clips.
const LOUDNORM: &str = "loudnorm=I=-16:TP=-1.5:LRA=11";
/// ffmpeg by absolute path, never through PATH.
const FFMPEG: &str = "/usr/bin/ffmpeg";
/// The longest ffmpeg may run on one file, and the longest input it may read.
const FFMPEG_DEADLINE: Duration = Duration::from_secs(120);
const FFMPEG_MAX_SECONDS: &str = "900";
/// A voice-note waveform is at most 256 samples (MSC3245).
const MAX_WAVEFORM: usize = 256;

/// Run ffmpeg on one local file with a deadline; the child is killed if the
/// deadline passes or the future is dropped. Input demuxing is restricted to
/// local files and `-t` bounds how much of the input is read.
async fn run_ffmpeg(args: &[&std::ffi::OsStr], output: &Path) -> bool {
    let mut cmd = tokio::process::Command::new(FFMPEG);
    cmd.args(["-nostdin", "-y", "-loglevel", "error", "-protocol_whitelist", "file"])
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let ok = match tokio::time::timeout(FFMPEG_DEADLINE, cmd.status()).await {
        Ok(Ok(st)) => st.success(),
        Ok(Err(e)) => {
            tracing::warn!("ffmpeg could not run: {e}");
            false
        }
        Err(_) => {
            tracing::warn!("ffmpeg exceeded {} s on {}", FFMPEG_DEADLINE.as_secs(), output.display());
            false
        }
    };
    if !ok {
        let _ = std::fs::remove_file(output);
    }
    ok
}

/// Extensions a cached attachment may carry, by kind. Anything else is .bin:
/// the sender's declared MIME type and file name choose nothing that a
/// desktop opener would treat as a document or executable content.
fn safe_extension(kind: &str, sniffed_image: Option<&str>, mime: Option<&str>, filename: &str) -> String {
    const IMAGES: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp"];
    const AUDIO: &[&str] = &["ogg", "oga", "opus", "mp3", "m4a", "aac", "flac", "wav"];
    const VIDEO: &[&str] = &["mp4", "webm", "mkv", "mov", "m4v"];
    const FILES: &[&str] = &["pdf", "txt", "md", "zip", "tar", "gz", "xz", "zst", "7z", "csv", "json", "log", "odt", "ods", "odp", "docx", "xlsx", "pptx", "epub"];
    let allowed: &[&str] = match kind {
        "image" => IMAGES,
        "audio" => AUDIO,
        "video" => VIDEO,
        _ => FILES,
    };
    // An image is what its bytes say it is, never what the sender declared.
    if kind == "image" {
        return sniffed_image
            .and_then(mime2ext::mime2ext)
            .filter(|e| IMAGES.contains(e))
            .unwrap_or("bin")
            .to_owned();
    }
    let candidate = mime
        .and_then(mime2ext::mime2ext)
        .map(str::to_owned)
        .or_else(|| Path::new(filename).extension().map(|e| e.to_string_lossy().to_lowercase()));
    match candidate {
        Some(e) if allowed.contains(&e.as_str()) => e,
        _ => "bin".to_owned(),
    }
}


/// What the client needs to know to render an attachment message.
pub fn attachment_of(msgtype: &MessageType) -> Option<Attachment> {
    let caption = match msgtype {
        MessageType::Image(c) => c.caption(),
        MessageType::File(c) => c.caption(),
        MessageType::Video(c) => c.caption(),
        MessageType::Audio(c) => c.caption(),
        _ => None,
    }
    .map(str::to_owned)
    .filter(|c| !c.trim().is_empty());
    let (kind, name, mime, size, width, height, thumb) = match msgtype {
        MessageType::Image(c) => {
            let i = c.info.as_deref();
            (
                "image",
                c.filename().to_owned(),
                i.and_then(|i| i.mimetype.clone()),
                i.and_then(|i| i.size).map(u64::from),
                i.and_then(|i| i.width).map(u64::from),
                i.and_then(|i| i.height).map(u64::from),
                // Images without an explicit thumbnail can be scaled by the server (unencrypted) —
                // for our purposes "has thumbnail" means the SDK can produce one.
                true,
            )
        }
        MessageType::File(c) => {
            let i = c.info.as_deref();
            (
                "file",
                c.filename().to_owned(),
                i.and_then(|i| i.mimetype.clone()),
                i.and_then(|i| i.size).map(u64::from),
                None,
                None,
                i.map(|i| i.thumbnail_source.is_some()).unwrap_or(false),
            )
        }
        MessageType::Video(c) => {
            let i = c.info.as_deref();
            (
                "video",
                c.filename().to_owned(),
                i.and_then(|i| i.mimetype.clone()),
                i.and_then(|i| i.size).map(u64::from),
                i.and_then(|i| i.width).map(u64::from),
                i.and_then(|i| i.height).map(u64::from),
                i.map(|i| i.thumbnail_source.is_some()).unwrap_or(false),
            )
        }
        MessageType::Audio(c) => {
            let i = c.info.as_deref();
            (
                "audio",
                c.filename().to_owned(),
                i.and_then(|i| i.mimetype.clone()),
                i.and_then(|i| i.size).map(u64::from),
                None,
                None,
                false,
            )
        }
        _ => return None,
    };
    // Voice messages carry their length and waveform in the MSC3245 blocks;
    // plain audio may still say how long it is in `info`.
    let (voice, duration_ms, waveform) = match msgtype {
        MessageType::Audio(c) => (
            c.voice.is_some(),
            c.audio
                .as_ref()
                .map(|a| a.duration.as_millis() as u64)
                .or_else(|| {
                    c.info
                        .as_deref()
                        .and_then(|i| i.duration)
                        .map(|d| d.as_millis() as u64)
                }),
            c.audio.as_ref().and_then(|a| {
                (!a.waveform.is_empty()).then(|| {
                    a.waveform
                        .iter()
                        .take(MAX_WAVEFORM)
                        .map(|v| u16::try_from(u64::from(v.get())).unwrap_or(u16::MAX))
                        .collect::<Vec<u16>>()
                })
            }),
        ),
        _ => (false, None, None),
    };
    Some(Attachment {
        kind: kind.to_owned(),
        name,
        caption,
        voice,
        duration_ms,
        waveform,
        mime,
        size,
        width,
        height,
        has_thumbnail: thumb,
    })
}

fn cache_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".cache"),
    };
    let dir = base.join("omarchy-yapper").join("media");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn avatar_cache_dir() -> Result<PathBuf> {
    let dir = cache_dir()?
        .parent()
        .unwrap_or(Path::new("."))
        .join("avatars");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn hash_of(s: &str) -> String {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn cache_name(event_id: &str, thumbnail: bool, ext: &str) -> String {
    let mut h = DefaultHasher::new();
    event_id.hash(&mut h);
    format!(
        "{:016x}{}.{}",
        h.finish(),
        if thumbnail { "-thumb" } else { "" },
        ext
    )
}

impl Core {
    /// Fetch an attachment (or its thumbnail) into the cache; returns the
    /// local path and mime type. Cached files are returned without a fetch.
    pub(crate) async fn download(
        &self,
        room_id: &str,
        event_id: &str,
        thumbnail: bool,
    ) -> Result<(String, String)> {
        let room = self.room(room_id).await?;
        let client = self.client().await?;
        let eid = EventId::parse(event_id).context("invalid event id")?;
        let ev = room.event(&eid, None).await.context("fetching the event")?;
        let parsed: AnySyncTimelineEvent = ev.raw().deserialize().context("reading the event")?;
        let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
            SyncMessageLikeEvent::Original(msg),
        )) = parsed
        else {
            bail!("not a message event");
        };

        let is_voice = matches!(&msg.content.msgtype, MessageType::Audio(c) if c.voice.is_some());
        let (bytes, mime, name): (Vec<u8>, String, String) = match &msg.content.msgtype {
            MessageType::Image(c) => {
                fetch(
                    &client,
                    c,
                    c.filename(),
                    c.info.as_deref().and_then(|i| i.mimetype.clone()),
                    c.info.as_deref().and_then(|i| i.size).map(u64::from),
                    thumbnail,
                )
                .await?
            }
            MessageType::File(c) => {
                fetch(
                    &client,
                    c,
                    c.filename(),
                    c.info.as_deref().and_then(|i| i.mimetype.clone()),
                    c.info.as_deref().and_then(|i| i.size).map(u64::from),
                    thumbnail,
                )
                .await?
            }
            MessageType::Video(c) => {
                fetch(
                    &client,
                    c,
                    c.filename(),
                    c.info.as_deref().and_then(|i| i.mimetype.clone()),
                    c.info.as_deref().and_then(|i| i.size).map(u64::from),
                    thumbnail,
                )
                .await?
            }
            MessageType::Audio(c) => {
                fetch(
                    &client,
                    c,
                    c.filename(),
                    c.info.as_deref().and_then(|i| i.mimetype.clone()),
                    c.info.as_deref().and_then(|i| i.size).map(u64::from),
                    false,
                )
                .await?
            }
            _ => bail!("this message has no attachment"),
        };

        let kind = match &msg.content.msgtype {
            MessageType::Image(_) => "image",
            MessageType::Audio(_) => "audio",
            MessageType::Video(_) => "video",
            _ => "file",
        };
        let ext = if thumbnail {
            safe_extension("image", infer_image_mime(&bytes).as_deref(), None, "")
        } else {
            safe_extension(kind, infer_image_mime(&bytes).as_deref(), Some(&mime), &name)
        };
        let path = cache_dir()?.join(cache_name(event_id, thumbnail, &ext));
        if !path.exists() {
            std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        }
        // Voice notes arrive at whatever level they were recorded; hand the
        // player a loudness-normalised copy when ffmpeg can make one.
        if is_voice {
            let norm = path.with_file_name(format!(
                "{}-norm.ogg",
                path.file_stem()
                    .map(|s| s.to_string_lossy())
                    .unwrap_or_default()
            ));
            // Only something that is audio by its bytes goes near ffmpeg.
            if !norm.exists() && infer::get(&bytes).is_some_and(|t| t.matcher_type() == infer::MatcherType::Audio) {
                let input = path.as_os_str();
                let out = norm.as_os_str();
                let args: Vec<&std::ffi::OsStr> = vec![
                    "-t".as_ref(), FFMPEG_MAX_SECONDS.as_ref(), "-i".as_ref(), input,
                    "-af".as_ref(), LOUDNORM.as_ref(), "-c:a".as_ref(), "libopus".as_ref(), "-b:a".as_ref(), "48k".as_ref(),
                    "-f".as_ref(), "ogg".as_ref(), out,
                ];
                run_ffmpeg(&args, &norm).await;
            }
            if norm.exists() {
                return Ok((norm.to_string_lossy().into_owned(), "audio/ogg".to_owned()));
            }
        }
        Ok((path.to_string_lossy().into_owned(), mime))
    }

    /// Upload a local file. Images get their dimensions so clients can lay
    /// them out before the download; everything else is a plain file.
    pub(crate) async fn send_file(
        &self,
        room_id: &str,
        path: &str,
        caption: Option<String>,
    ) -> Result<String> {
        let room = self.room(room_id).await?;
        let path = Path::new(path);
        let meta =
            std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if !meta.is_file() {
            bail!("{} is not a file", path.display());
        }
        if meta.len() > MAX_UPLOAD {
            bail!("file is larger than 100 MB");
        }
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_owned());
        let mime = mime_guess::from_path(path).first_or_octet_stream();

        let info = if mime.type_() == mime::IMAGE {
            let (w, h) = imagesize::blob_size(&data)
                .map(|s| (s.width as u64, s.height as u64))
                .unwrap_or((0, 0));
            AttachmentInfo::Image(BaseImageInfo {
                width: (w > 0).then(|| UInt::new(w)).flatten(),
                height: (h > 0).then(|| UInt::new(h)).flatten(),
                size: UInt::new(meta.len()),
                blurhash: None,
                is_animated: None,
            })
        } else {
            AttachmentInfo::File(BaseFileInfo {
                size: UInt::new(meta.len()),
            })
        };
        let mut config = AttachmentConfig::new().info(info);
        if let Some(c) = caption
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())
        {
            config = config.caption(Some(TextMessageEventContent::plain(c)));
        }

        let resp = room
            .send_attachment(name.clone(), &mime, data, config)
            .await
            .context("uploading")?;
        info!(room = %room.room_id(), file = %name, "attachment sent");
        Ok(resp.event_id.to_string())
    }

    /// A recorded WAV (16-bit PCM, as `pw-record --format=s16` writes)
    /// becomes an Opus voice message. The waveform is 100 loudness samples
    /// of the recording; ffmpeg does the encoding, and without it the WAV
    /// itself is sent, still flagged as a voice message.
    pub(crate) async fn send_voice(&self, room_id: &str, path: &str) -> Result<String> {
        let room = self.room(room_id).await?;
        let wav_path = PathBuf::from(path);
        let wav =
            std::fs::read(&wav_path).with_context(|| format!("reading {}", wav_path.display()))?;
        let (duration, waveform) = analyse_wav(&wav).context("reading the recording")?;
        if duration < std::time::Duration::from_millis(300) {
            let _ = std::fs::remove_file(&wav_path);
            bail!("the recording is too short");
        }
        let ogg_path = wav_path.with_extension("ogg");
        // Speech-level loudness whatever the mic's gain was.
        let encoded = {
            let input = wav_path.as_os_str();
            let out = ogg_path.as_os_str();
            let args: Vec<&std::ffi::OsStr> = vec![
                "-t".as_ref(), FFMPEG_MAX_SECONDS.as_ref(), "-f".as_ref(), "wav".as_ref(), "-i".as_ref(), input,
                "-af".as_ref(), LOUDNORM.as_ref(), "-c:a".as_ref(), "libopus".as_ref(), "-b:a".as_ref(), "32k".as_ref(),
                "-application".as_ref(), "voip".as_ref(), "-f".as_ref(), "ogg".as_ref(), out,
            ];
            run_ffmpeg(&args, &ogg_path).await
        };
        let (data, mime, name) = if encoded {
            (
                std::fs::read(&ogg_path).context("reading the encoded voice message")?,
                "audio/ogg".parse::<mime::Mime>().expect("static mime"),
                "Voice message.ogg",
            )
        } else {
            tracing::warn!("ffmpeg unavailable or failed; sending the WAV as recorded");
            (
                wav,
                "audio/wav".parse::<mime::Mime>().expect("static mime"),
                "Voice message.wav",
            )
        };
        let _ = std::fs::remove_file(&wav_path);
        let _ = std::fs::remove_file(&ogg_path);
        if data.len() as u64 > MAX_UPLOAD {
            bail!("the recording is too large");
        }
        let info = AttachmentInfo::Voice(BaseAudioInfo {
            duration: Some(duration),
            size: UInt::new(data.len() as u64),
            waveform: Some(waveform),
        });
        let resp = room
            .send_attachment(name, &mime, data, AttachmentConfig::new().info(info))
            .await
            .context("uploading the voice message")?;
        info!(room = %room.room_id(), secs = duration.as_secs_f32(), "voice message sent");
        Ok(resp.event_id.to_string())
    }
}

/// Duration and a 100-point loudness curve (0–1) of a PCM WAV. Handles the
/// common layouts: 16-bit or 32-bit integer samples, any channel count.
fn analyse_wav(bytes: &[u8]) -> Result<(std::time::Duration, Vec<f32>)> {
    if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        bail!("not a WAV file");
    }
    let (mut channels, mut rate, mut bits) = (1u16, 48000u32, 16u16);
    let mut data: Option<&[u8]> = None;
    let mut pos = 12;
    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let len = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        let body = &bytes[pos + 8..(pos + 8 + len).min(bytes.len())];
        match id {
            b"fmt " if body.len() >= 16 => {
                channels = u16::from_le_bytes([body[2], body[3]]).max(1);
                rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]).max(1);
                bits = u16::from_le_bytes([body[14], body[15]]);
            }
            b"data" => data = Some(body),
            _ => {}
        }
        pos += 8 + len + (len & 1);
    }
    let data = data.ok_or_else(|| anyhow!("no audio data"))?;
    let bytes_per_sample = match bits {
        16 => 2,
        32 => 4,
        other => bail!("unsupported sample size: {other} bits"),
    };
    let frame = bytes_per_sample * channels as usize;
    let frames = data.len() / frame.max(1);
    let duration = std::time::Duration::from_secs_f64(frames as f64 / rate as f64);
    // RMS per bucket, normalised to the loudest bucket.
    const BUCKETS: usize = 100;
    let mut curve = vec![0f32; BUCKETS];
    if frames > 0 {
        let per = (frames / BUCKETS).max(1);
        for (b, slot) in curve.iter_mut().enumerate() {
            let start = b * per;
            let end = ((b + 1) * per).min(frames);
            if start >= end {
                break;
            }
            let mut acc = 0f64;
            let mut n = 0usize;
            for f in start..end {
                let off = f * frame;
                let v = if bits == 16 {
                    i16::from_le_bytes([data[off], data[off + 1]]) as f64 / i16::MAX as f64
                } else {
                    i32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                        as f64
                        / i32::MAX as f64
                };
                acc += v * v;
                n += 1;
            }
            *slot = (acc / n.max(1) as f64).sqrt() as f32;
        }
        let peak = curve.iter().cloned().fold(0f32, f32::max);
        if peak > 0.0 {
            for v in curve.iter_mut() {
                *v = (*v / peak).clamp(0.0, 1.0);
            }
        }
    }
    Ok((duration, curve))
}

async fn fetch(
    client: &matrix_sdk::Client,
    content: &impl MediaEventContent,
    filename: &str,
    mime: Option<String>,
    declared_size: Option<u64>,
    thumbnail: bool,
) -> Result<(Vec<u8>, String, String)> {
    let media = client.media();
    if thumbnail {
        let settings = MediaThumbnailSettings::new(UInt::from(THUMB_SIZE), UInt::from(THUMB_SIZE));
        if let Some(bytes) = media
            .get_thumbnail(content, settings, true)
            .await
            .context("fetching thumbnail")?
        {
            // Thumbnails are whatever the sender/server produced; sniff the type.
            let m = infer_image_mime(&bytes)
                .unwrap_or_else(|| mime.clone().unwrap_or_else(|| "image/jpeg".to_owned()));
            return Ok((bytes, m, filename.to_owned()));
        }
        // No separate thumbnail (typical for encrypted images): fall through to the file.
    }
    if let Some(size) = declared_size
        && size > MAX_DOWNLOAD
    {
        bail!("this attachment is {size} bytes; the limit is {MAX_DOWNLOAD}");
    }
    let bytes = media
        .get_file(content, true)
        .await
        .context("fetching attachment")?
        .ok_or_else(|| anyhow!("no media source"))?;
    let m = mime
        .or_else(|| infer_image_mime(&bytes))
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    Ok((bytes, m, filename.to_owned()))
}

fn infer_image_mime(bytes: &[u8]) -> Option<String> {
    let t = match imagesize::image_type(bytes).ok()? {
        imagesize::ImageType::Png => "image/png",
        imagesize::ImageType::Jpeg => "image/jpeg",
        imagesize::ImageType::Gif => "image/gif",
        imagesize::ImageType::Webp => "image/webp",
        imagesize::ImageType::Bmp => "image/bmp",
        _ => return None,
    };
    Some(t.to_owned())
}

#[cfg(test)]
mod tests {
    use super::safe_extension;

    #[test]
    fn images_take_their_extension_from_the_bytes_only() {
        assert_eq!(safe_extension("image", Some("image/png"), Some("text/html"), "x.html"), "png");
        assert_eq!(safe_extension("image", None, Some("text/html"), "x.html"), "bin");
        assert_eq!(safe_extension("image", Some("image/svg+xml"), None, ""), "bin");
    }

    #[test]
    fn other_kinds_use_an_allowlist() {
        assert_eq!(safe_extension("file", None, Some("application/pdf"), "a"), "pdf");
        assert_eq!(safe_extension("file", None, Some("text/html"), "page.html"), "bin");
        assert_eq!(safe_extension("file", None, None, "evil.desktop"), "bin");
        assert_eq!(safe_extension("file", None, None, "notes.TXT"), "txt");
        assert_eq!(safe_extension("audio", None, Some("audio/ogg"), "v"), "oga");
        assert_eq!(safe_extension("audio", None, Some("text/x-shellscript"), "v.sh"), "bin");
        assert_eq!(safe_extension("video", None, Some("video/mp4"), "v"), "mp4");
    }
}
