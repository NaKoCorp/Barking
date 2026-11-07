//! Delivery state of sent messages: each packet's delivery
//! (`deliveries.status`) and the state of its message, recomputed from the
//! deliveries to the contact's devices after every delivery state write.

use rusqlite::params;

use crate::Result;
use crate::packet::Packet;
use crate::store::{MessageId, Queries, map_err};

/// Recomputes the state of the outgoing message `message_id` from its
/// deliveries to the contact's devices (`own = 0`): `Received` if one is
/// received, else `OnNetwork` if one is on the network, else `Pending` if
/// one is pending, else `NotDelivered`. Copies for my own devices never
/// count. A message without any delivery to the contact (sent from another
/// of my devices, imported history) and a received message are left as they
/// are, as is an unknown identifier (a messageless delivery).
pub(crate) fn recompute_message_status(q: &impl Queries, message_id: MessageId) -> Result<()> {
    q.conn()
        .execute(
            "UPDATE messages SET status = (
                SELECT CASE
                    WHEN sum(d.status = 3) > 0 THEN 3
                    WHEN sum(d.status = 1) > 0 THEN 1
                    WHEN sum(d.status = 0) > 0 THEN 0
                    ELSE 5 END
                FROM deliveries d WHERE d.message_id = messages.message_id AND d.own = 0)
            WHERE message_id = ?1 AND direction = 0
              AND EXISTS (SELECT 1 FROM deliveries d WHERE d.message_id = ?1 AND d.own = 0)",
            params![message_id.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Bytes of `packet` on the wire (its tier's fixed size): `deliveries.size`.
pub(crate) fn packet_size(packet: &Packet) -> u32 {
    u32::try_from(packet.tier.size()).unwrap_or(u32::MAX)
}
