//! Domain-separation labels specific to the packet module.

/// BLAKE3 context for the packet identifier of an acknowledgement.
pub const ACK_CONTEXT: &str = "barking/v0/ack";

/// BLAKE3 context for the frame key (fragmentation).
pub const FRAME_CONTEXT: &str = "barking/v0/frame";
