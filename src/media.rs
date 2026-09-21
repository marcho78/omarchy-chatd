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

use anyhow::{Context, Result, anyhow, bail};
use matrix_sdk::{
    attachment::{AttachmentConfig, AttachmentInfo, BaseFileInfo, BaseImageInfo},
    media::{MediaEventContent, MediaThumbnailSettings},
    ruma::{
        EventId, UInt,
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent, SyncMessageLikeEvent,
            room::message::{MessageType, TextMessageEventContent},
        },
    },
};
use tracing::info;

use crate::{core::Core, protocol::Attachment};

const THUMB_SIZE: u32 = 640;
const MAX_UPLOAD: u64 = 100 * 1024 * 1024;

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
            ("audio", c.filename().to_owned(), i.and_then(|i| i.mimetype.clone()), i.and_then(|i| i.size).map(u64::from), None, None, false)
        }
        _ => return None,
    };
    Some(Attachment { kind: kind.to_owned(), name, caption, mime, size, width, height, has_thumbnail: thumb })
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
    let dir = cache_dir()?.parent().unwrap_or(Path::new(".")).join("avatars");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn hash_of(s: &str) -> String {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn cache_name(event_id: &str, thumbnail: bool, mime: Option<&str>, filename: &str) -> String {
    let mut h = DefaultHasher::new();
    event_id.hash(&mut h);
    let ext = mime
        .and_then(mime2ext::mime2ext)
        .map(str::to_owned)
        .or_else(|| Path::new(filename).extension().map(|e| e.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "bin".to_owned());
    format!("{:016x}{}.{}", h.finish(), if thumbnail { "-thumb" } else { "" }, ext)
}

impl Core {
    /// Fetch an attachment (or its thumbnail) into the cache; returns the
    /// local path and mime type. Cached files are returned without a fetch.
    pub(crate) async fn download(&self, room_id: &str, event_id: &str, thumbnail: bool) -> Result<(String, String)> {
        let room = self.room(room_id).await?;
        let client = self.client().await?;
        let eid = EventId::parse(event_id).context("invalid event id")?;
        let ev = room.event(&eid, None).await.context("fetching the event")?;
        let parsed: AnySyncTimelineEvent = ev.raw().deserialize().context("reading the event")?;
        let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(SyncMessageLikeEvent::Original(msg))) = parsed
        else {
            bail!("not a message event");
        };

        let (bytes, mime, name): (Vec<u8>, String, String) = match &msg.content.msgtype {
            MessageType::Image(c) => fetch(&client, c, c.filename(), c.info.as_deref().and_then(|i| i.mimetype.clone()), thumbnail).await?,
            MessageType::File(c) => fetch(&client, c, c.filename(), c.info.as_deref().and_then(|i| i.mimetype.clone()), thumbnail).await?,
            MessageType::Video(c) => fetch(&client, c, c.filename(), c.info.as_deref().and_then(|i| i.mimetype.clone()), thumbnail).await?,
            MessageType::Audio(c) => fetch(&client, c, c.filename(), c.info.as_deref().and_then(|i| i.mimetype.clone()), false).await?,
            _ => bail!("this message has no attachment"),
        };

        let path = cache_dir()?.join(cache_name(event_id, thumbnail, Some(&mime), &name));
        if !path.exists() {
            std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        }
        Ok((path.to_string_lossy().into_owned(), mime))
    }

    /// Upload a local file. Images get their dimensions so clients can lay
    /// them out before the download; everything else is a plain file.
    pub(crate) async fn send_file(&self, room_id: &str, path: &str, caption: Option<String>) -> Result<String> {
        let room = self.room(room_id).await?;
        let path = Path::new(path);
        let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if !meta.is_file() {
            bail!("{} is not a file", path.display());
        }
        if meta.len() > MAX_UPLOAD {
            bail!("file is larger than 100 MB");
        }
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".to_owned());
        let mime = mime_guess::from_path(path).first_or_octet_stream();

        let info = if mime.type_() == mime::IMAGE {
            let (w, h) = imagesize::blob_size(&data).map(|s| (s.width as u64, s.height as u64)).unwrap_or((0, 0));
            AttachmentInfo::Image(BaseImageInfo {
                width: (w > 0).then(|| UInt::new(w)).flatten(),
                height: (h > 0).then(|| UInt::new(h)).flatten(),
                size: UInt::new(meta.len()),
                blurhash: None,
                is_animated: None,
            })
        } else {
            AttachmentInfo::File(BaseFileInfo { size: UInt::new(meta.len()) })
        };
        let mut config = AttachmentConfig::new().info(info);
        if let Some(c) = caption.map(|c| c.trim().to_owned()).filter(|c| !c.is_empty()) {
            config = config.caption(Some(TextMessageEventContent::plain(c)));
        }

        let resp = room.send_attachment(name.clone(), &mime, data, config).await.context("uploading")?;
        info!(room = %room.room_id(), file = %name, "attachment sent");
        Ok(resp.event_id.to_string())
    }
}

async fn fetch(
    client: &matrix_sdk::Client,
    content: &impl MediaEventContent,
    filename: &str,
    mime: Option<String>,
    thumbnail: bool,
) -> Result<(Vec<u8>, String, String)> {
    let media = client.media();
    if thumbnail {
        let settings = MediaThumbnailSettings::new(UInt::from(THUMB_SIZE), UInt::from(THUMB_SIZE));
        if let Some(bytes) = media.get_thumbnail(content, settings, true).await.context("fetching thumbnail")? {
            // Thumbnails are whatever the sender/server produced; sniff the type.
            let m = infer_image_mime(&bytes).unwrap_or_else(|| mime.clone().unwrap_or_else(|| "image/jpeg".to_owned()));
            return Ok((bytes, m, filename.to_owned()));
        }
        // No separate thumbnail (typical for encrypted images): fall through to the file.
    }
    let bytes = media.get_file(content, true).await.context("fetching attachment")?.ok_or_else(|| anyhow!("no media source"))?;
    let m = mime.or_else(|| infer_image_mime(&bytes)).unwrap_or_else(|| "application/octet-stream".to_owned());
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
