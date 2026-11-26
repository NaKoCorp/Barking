//! Contact requests and invites: the requests received from unknown
//! senders (accept, refuse, block, hide), and the invite I send to a contact
//! who has not added me yet.

use barking_core::identity::root::Fingerprint;
use barking_core::{ContactRequest, ContactSummary, InviteState, parse_fingerprint};

use crate::device::{Device, now};
use crate::{BarkingError, guard};

/// A pending request, as shown to the user.
#[derive(Debug, uniffi::Record)]
pub struct ContactRequestInfo {
    pub fingerprint: String,
    /// The name the requester declares (unverified).
    pub display_name: String,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Invites received from this sender.
    pub invite_count: u32,
    /// Messages held until the request is accepted.
    pub pending_messages: u32,
    /// Hidden by the user on this device.
    pub hidden: bool,
    /// Not shown to the user yet.
    pub unseen: bool,
    /// The declared name equals (ignoring case) the alias or the name of a
    /// contact that is not blocked.
    pub name_clash: bool,
}

/// State of the invite I sent to a contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum InviteStatus {
    /// No invite sent.
    None,
    /// Sent at `at`, no answer yet.
    Sent { at: u64 },
    /// Sent at `at`, refused or no answer before it expired.
    Unanswered { at: u64 },
    /// Accepted; `at` is when I learned it.
    Accepted { at: u64 },
}

impl From<InviteState> for InviteStatus {
    fn from(s: InviteState) -> Self {
        match s {
            InviteState::None => InviteStatus::None,
            InviteState::Sent { at } => InviteStatus::Sent { at },
            InviteState::Unanswered { at } => InviteStatus::Unanswered { at },
            InviteState::Accepted { at } => InviteStatus::Accepted { at },
        }
    }
}

/// The fingerprint of a request (not a contact: `resolve` does not know it).
fn request_fp(s: &str) -> Result<Fingerprint, BarkingError> {
    parse_fingerprint(s).ok_or_else(|| BarkingError::invalid("fingerprint"))
}

/// Does `name` equal, ignoring case, the alias or the name of one of the
/// (not blocked) `contacts`? An empty name clashes with nothing.
fn name_clash(name: &str, contacts: &[ContactSummary]) -> bool {
    let name = name.to_lowercase();
    !name.is_empty()
        && contacts.iter().filter(|c| !c.blocked).any(|c| {
            c.display_name.to_lowercase() == name
                || c.alias.as_deref().is_some_and(|a| a.to_lowercase() == name)
        })
}

fn info(r: ContactRequest, contacts: &[ContactSummary]) -> ContactRequestInfo {
    ContactRequestInfo {
        fingerprint: r.fingerprint.to_string(),
        name_clash: name_clash(&r.display_name, contacts),
        display_name: r.display_name,
        first_seen: r.first_seen,
        last_seen: r.last_seen,
        invite_count: r.invite_count,
        pending_messages: r.pending_messages,
        hidden: r.hidden,
        unseen: r.unseen,
    }
}

#[uniffi::export]
impl Device {
    /// The pending requests, hidden ones included, most recently seen first.
    pub fn requests(&self) -> Result<Vec<ContactRequestInfo>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                let contacts = core.contacts()?;
                Ok(core
                    .requests()?
                    .into_iter()
                    .map(|r| info(r, &contacts))
                    .collect())
            })
        })
    }

    /// The safety code with a requester, before accepting: 12 groups of 5
    /// digits, the same as `safety_number` once accepted.
    pub fn request_safety_number(&self, fingerprint: String) -> Result<Vec<String>, BarkingError> {
        guard(|| {
            let fp = request_fp(&fingerprint)?;
            self.with_core_read(|core| {
                Ok(core
                    .request_safety_number(&fp)?
                    .split(' ')
                    .map(str::to_owned)
                    .collect())
            })
        })
    }

    /// Accepts a request: the requester becomes a contact (unverified) and
    /// its held messages are shown. Returns the contact's fingerprint. An
    /// alias already used: `InvalidInput { detail: "alias taken" }`, and
    /// nothing is written.
    pub fn accept_request(
        &self,
        fingerprint: String,
        alias: Option<String>,
    ) -> Result<String, BarkingError> {
        guard(|| {
            let fp = request_fp(&fingerprint)?;
            self.with_core(|core| {
                let accepted =
                    core.accept_request(&fp, alias.as_deref(), now(), &mut rand::rng())?;
                Ok(accepted.contact.to_string())
            })
        })
    }

    /// Refuses a request: it and its messages are dropped, nothing goes to
    /// the requester.
    pub fn refuse_request(&self, fingerprint: String) -> Result<(), BarkingError> {
        guard(|| {
            let fp = request_fp(&fingerprint)?;
            self.with_core(|core| {
                core.refuse_request(&fp, now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }

    /// Blocks a requester: the request is dropped, and so are its later
    /// invites.
    pub fn block_request(&self, fingerprint: String) -> Result<(), BarkingError> {
        guard(|| {
            let fp = request_fp(&fingerprint)?;
            self.with_core(|core| {
                core.block_request(&fp, now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }

    /// Hides or shows a request in the main list (this device only).
    pub fn set_request_hidden(
        &self,
        fingerprint: String,
        hidden: bool,
    ) -> Result<(), BarkingError> {
        guard(|| {
            let fp = request_fp(&fingerprint)?;
            self.with_core(|core| Ok(core.set_request_hidden(&fp, hidden)?))
        })
    }

    /// The user opened the list of requests: none is `unseen` any more.
    pub fn mark_requests_seen(&self) -> Result<(), BarkingError> {
        guard(|| self.with_core(|core| Ok(core.mark_requests_seen()?)))
    }

    /// Invites a contact who has not added me yet. Again within 24 hours:
    /// `TooSoon { retry_at }`.
    pub fn invite(&self, contact: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                core.invite(&fp, now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }

    /// State of the invite I sent to a contact.
    pub fn invite_status(&self, contact: String) -> Result<InviteStatus, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.invite_state(&fp, now())?.into())
            })
        })
    }
}
