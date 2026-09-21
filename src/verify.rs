//! Device verification (SAS emoji), recovery and key backup.
//!
//! Every flow is identified by its Matrix flow id. The SDK owns the state
//! machines; we follow their change streams and forward each step as a
//! `verification` event, and look the objects up again by id when the user
//! acts. Nothing is accepted or confirmed without a command from a client.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use matrix_sdk::{
    Client,
    encryption::{
        backups::BackupState,
        recovery::RecoveryState,
        verification::{
            Emoji, SasState, SasVerification, Verification, VerificationRequest,
            VerificationRequestState,
        },
    },
    ruma::{
        OwnedUserId,
        events::{
            key::verification::request::ToDeviceKeyVerificationRequestEvent,
            room::message::{MessageType, OriginalSyncRoomMessageEvent},
        },
    },
};
use tracing::{info, warn};

use crate::{
    core::Core,
    protocol::{DeviceInfo, EmojiInfo, Event, VerificationInfo, VerificationStatus},
};

// ---------- event handlers ----------

/// Incoming verification requests: to-device (our other devices) and
/// in-room (other users, in a DM).
pub fn install_handlers(core: &Arc<Core>, client: &Client) {
    let c = core.clone();
    client.add_event_handler(
        move |ev: ToDeviceKeyVerificationRequestEvent, client: Client| {
            let core = c.clone();
            async move {
                let flow_id = ev.content.transaction_id.to_string();
                match client
                    .encryption()
                    .get_verification_request(&ev.sender, &ev.content.transaction_id)
                    .await
                {
                    Some(request) => core.track_request(request, false).await,
                    None => warn!(%flow_id, "verification request without an object"),
                }
            }
        },
    );
    let c = core.clone();
    client.add_event_handler(move |ev: OriginalSyncRoomMessageEvent, client: Client| {
        let core = c.clone();
        async move {
            if !matches!(ev.content.msgtype, MessageType::VerificationRequest(_)) {
                return;
            }
            match client
                .encryption()
                .get_verification_request(&ev.sender, &ev.event_id)
                .await
            {
                Some(request) => core.track_request(request, false).await,
                None => warn!(event = %ev.event_id, "room verification request without an object"),
            }
        }
    });
}

impl Core {
    // ---------- status ----------

    pub(crate) async fn verification_status(&self) -> Result<VerificationStatus> {
        let client = self.client().await?;
        let enc = client.encryption();
        let me = client.user_id().ok_or_else(|| anyhow!("no user id"))?;
        let own_device_id = client
            .device_id()
            .map(|d| d.to_string())
            .unwrap_or_default();

        let own = enc.get_own_device().await.ok().flatten();
        let device_verified = own
            .as_ref()
            .map(|d| d.is_cross_signed_by_owner())
            .unwrap_or(false);
        let cross_signing = enc
            .cross_signing_status()
            .await
            .map(|s| s.has_master)
            .unwrap_or(false);

        let mut other_devices = Vec::new();
        if let Ok(devices) = enc.get_user_devices(me).await {
            for d in devices.devices() {
                if d.device_id().as_str() == own_device_id {
                    continue;
                }
                other_devices.push(DeviceInfo {
                    id: d.device_id().to_string(),
                    name: d.display_name().map(str::to_owned),
                    verified: d.is_verified(),
                });
            }
        }

        Ok(VerificationStatus {
            device_verified,
            cross_signing,
            recovery: match enc.recovery().state() {
                RecoveryState::Unknown => "unknown",
                RecoveryState::Enabled => "enabled",
                RecoveryState::Disabled => "disabled",
                RecoveryState::Incomplete => "incomplete",
            }
            .to_owned(),
            backup: match enc.backups().state() {
                BackupState::Unknown => "unknown",
                BackupState::Creating => "creating",
                BackupState::Enabling => "enabling",
                BackupState::Resuming => "resuming",
                BackupState::Enabled => "enabled",
                BackupState::Downloading => "downloading",
                BackupState::Disabling => "disabling",
            }
            .to_owned(),
            device_id: own_device_id,
            other_devices,
        })
    }

    // ---------- SAS with our other devices ----------

    /// Ask every other device of ours to verify this one.
    pub(crate) async fn verify_request(self: &Arc<Self>) -> Result<String> {
        let client = self.client().await?;
        let me = client.user_id().ok_or_else(|| anyhow!("no user id"))?;
        let identity = client
            .encryption()
            .get_user_identity(me)
            .await
            .context("looking up our identity")?
            .ok_or_else(|| anyhow!("this account has no cross-signing identity yet; set up recovery first or verify from a device that has it"))?;
        let request = identity
            .request_verification()
            .await
            .context("sending verification request")?;
        let flow_id = request.flow_id().to_owned();
        info!(%flow_id, "verification requested from our other devices");
        self.track_request(request, true).await;
        Ok(flow_id)
    }

    async fn request_by_id(&self, flow_id: &str) -> Result<(Client, VerificationRequest)> {
        let client = self.client().await?;
        let user = self
            .flows
            .lock()
            .await
            .get(flow_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown verification {flow_id}"))?;
        let req = client
            .encryption()
            .get_verification_request(&user, flow_id)
            .await
            .ok_or_else(|| anyhow!("verification {flow_id} is gone"))?;
        Ok((client, req))
    }

    async fn sas_by_id(&self, flow_id: &str) -> Result<SasVerification> {
        let client = self.client().await?;
        let user = self
            .flows
            .lock()
            .await
            .get(flow_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown verification {flow_id}"))?;
        match client.encryption().get_verification(&user, flow_id).await {
            Some(Verification::SasV1(sas)) => Ok(sas),
            _ => bail!("verification {flow_id} has no emoji exchange yet"),
        }
    }

    pub(crate) async fn verify_accept(self: &Arc<Self>, flow_id: &str) -> Result<()> {
        let (_, req) = self.request_by_id(flow_id).await?;
        req.accept().await.context("accepting verification")?;
        Ok(())
    }

    pub(crate) async fn verify_confirm(&self, flow_id: &str) -> Result<()> {
        let sas = self.sas_by_id(flow_id).await?;
        // Only meaningful once both sides have the emoji on screen.
        if !matches!(sas.state(), SasState::KeysExchanged { .. }) {
            bail!("nothing to confirm yet");
        }
        sas.confirm().await.context("confirming")?;
        Ok(())
    }

    pub(crate) async fn verify_cancel(&self, flow_id: &str) -> Result<()> {
        if let Ok(sas) = self.sas_by_id(flow_id).await {
            let _ = sas.mismatch().await;
            return Ok(());
        }
        let (_, req) = self.request_by_id(flow_id).await?;
        req.cancel().await.context("cancelling")?;
        Ok(())
    }

    /// Follow a request through to a SAS, then the SAS to the end,
    /// broadcasting each step. Auto-accept never happens here: an incoming
    /// request waits for `verify_accept`.
    async fn track_request(self: &Arc<Self>, request: VerificationRequest, outgoing: bool) {
        let flow_id = request.flow_id().to_owned();
        let other: OwnedUserId = request.other_user_id().to_owned();
        self.flows
            .lock()
            .await
            .insert(flow_id.clone(), other.clone());
        self.emit(&request, outgoing, "requested", Vec::new(), None);

        let core = self.clone();
        tokio::spawn(async move {
            let mut changes = request.changes();
            while let Some(state) = changes.next().await {
                match state {
                    VerificationRequestState::Created { .. }
                    | VerificationRequestState::Requested { .. } => {}
                    VerificationRequestState::Ready { .. } => {
                        core.emit(&request, outgoing, "ready", Vec::new(), None);
                        // Whoever is ready first starts the emoji exchange;
                        // if the other side already did, Transitioned follows.
                        if let Ok(Some(sas)) = request.start_sas().await {
                            core.track_sas(request.clone(), sas, outgoing);
                        }
                    }
                    VerificationRequestState::Transitioned { verification } => {
                        if let Verification::SasV1(sas) = verification {
                            core.track_sas(request.clone(), sas, outgoing);
                        }
                        break;
                    }
                    VerificationRequestState::Done => {
                        core.emit(&request, outgoing, "done", Vec::new(), None);
                        break;
                    }
                    VerificationRequestState::Cancelled(info) => {
                        core.emit(
                            &request,
                            outgoing,
                            "cancelled",
                            Vec::new(),
                            Some(info.reason().to_owned()),
                        );
                        break;
                    }
                }
            }
            core.flows.lock().await.remove(&flow_id);
        });
    }

    fn track_sas(
        self: &Arc<Self>,
        request: VerificationRequest,
        sas: SasVerification,
        outgoing: bool,
    ) {
        let core = self.clone();
        tokio::spawn(async move {
            if !sas.we_started() {
                if let Err(e) = sas.accept().await {
                    warn!("accepting SAS: {e:#}");
                }
            }
            let mut changes = sas.changes();
            while let Some(state) = changes.next().await {
                match state {
                    SasState::KeysExchanged { emojis, .. } => {
                        let list = emojis
                            .map(|e| e.emojis.iter().map(emoji_info).collect::<Vec<_>>())
                            .unwrap_or_default();
                        core.emit_sas(&request, &sas, outgoing, "emoji", list, None);
                    }
                    SasState::Confirmed => {
                        core.emit(&request, outgoing, "confirmed", Vec::new(), None)
                    }
                    SasState::Done { .. } => {
                        info!(device = %sas.other_device().device_id(), "device verified");
                        core.emit(&request, outgoing, "done", Vec::new(), None);
                        let _ = core.events().send(Event::VerificationStatusChanged);
                        break;
                    }
                    SasState::Cancelled(info) => {
                        core.emit(
                            &request,
                            outgoing,
                            "cancelled",
                            Vec::new(),
                            Some(info.reason().to_owned()),
                        );
                        break;
                    }
                    SasState::Created { .. }
                    | SasState::Started { .. }
                    | SasState::Accepted { .. } => {}
                }
            }
        });
    }

    fn emit_sas(
        &self,
        request: &VerificationRequest,
        sas: &SasVerification,
        outgoing: bool,
        state: &str,
        emojis: Vec<EmojiInfo>,
        reason: Option<String>,
    ) {
        let dev = sas.other_device();
        let _ = self.events().send(Event::Verification(VerificationInfo {
            flow_id: request.flow_id().to_owned(),
            other_user: request.other_user_id().to_string(),
            other_device: Some(dev.device_id().to_string()),
            other_device_name: dev.display_name().map(str::to_owned),
            outgoing,
            state: state.to_owned(),
            emojis,
            reason,
        }));
    }

    fn emit(
        &self,
        request: &VerificationRequest,
        outgoing: bool,
        state: &str,
        emojis: Vec<EmojiInfo>,
        reason: Option<String>,
    ) {
        let _ = self.events().send(Event::Verification(VerificationInfo {
            flow_id: request.flow_id().to_owned(),
            other_user: request.other_user_id().to_string(),
            other_device: None,
            other_device_name: None,
            outgoing,
            state: state.to_owned(),
            emojis,
            reason,
        }));
    }

    // ---------- recovery / backup ----------

    pub(crate) async fn recover(&self, key: &str) -> Result<()> {
        let client = self.client().await?;
        let recovery = client.encryption().recovery();
        recovery
            .recover(key.trim())
            .await
            .context("recovering with that key")?;
        match recovery.state() {
            RecoveryState::Enabled => {}
            RecoveryState::Incomplete => {
                bail!("recovered some secrets but not all; try again or verify with another device")
            }
            _ => bail!("recovery did not complete"),
        }
        let _ = self.events().send(Event::VerificationStatusChanged);
        Ok(())
    }

    /// First device on the account: create the cross-signing identity (which
    /// also signs this device), then secret storage and backup. Returns the
    /// recovery key to show exactly once.
    pub(crate) async fn setup_recovery(&self) -> Result<String> {
        let client = self.client().await?;
        let enc = client.encryption();
        let has_master = enc
            .cross_signing_status()
            .await
            .map(|s| s.has_master)
            .unwrap_or(false);
        if has_master && matches!(enc.recovery().state(), RecoveryState::Enabled) {
            bail!("recovery is already set up; use the recovery key or verify with another device");
        }
        if !has_master {
            // matrix.org (MAS) lets a first identity be uploaded without
            // re-authentication; a homeserver that asks for it surfaces here.
            enc.bootstrap_cross_signing(None)
                .await
                .context("creating the cross-signing identity (the homeserver may require re-authentication)")?;
            info!("cross-signing identity created");
        }
        // A fresh store gets one key; a store we started earlier without the
        // identity is re-keyed so the key covers everything.
        let key = match enc.recovery().state() {
            RecoveryState::Enabled => bail!("recovery is already set up"),
            RecoveryState::Disabled | RecoveryState::Unknown => enc
                .recovery()
                .enable()
                .await
                .context("setting up recovery")?,
            RecoveryState::Incomplete => enc
                .recovery()
                .reset_key()
                .await
                .context("re-keying recovery")?,
        };
        let _ = self.events().send(Event::VerificationStatusChanged);
        Ok(key)
    }
}

impl Core {
    pub(crate) async fn reset_recovery_key(&self) -> Result<String> {
        let client = self.client().await?;
        let enc = client.encryption();
        if !enc
            .cross_signing_status()
            .await
            .map(|s| s.has_master)
            .unwrap_or(false)
        {
            bail!("no encryption identity yet; set up encryption first");
        }
        let key = enc
            .recovery()
            .reset_key()
            .await
            .context("creating a new recovery key")?;
        info!("recovery key reset");
        let _ = self.events().send(Event::VerificationStatusChanged);
        Ok(key)
    }
}

fn emoji_info(e: &Emoji) -> EmojiInfo {
    EmojiInfo {
        symbol: e.symbol.to_owned(),
        description: e.description.to_owned(),
    }
}
