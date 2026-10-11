//! Shadow Spoof wire protocol – the application-level packet that rides inside
//! spoofed UDP (data channel) or ICMP Echo (control channel) payloads.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 4-byte magic number at the start of every ShadowPacket.
pub const MAGIC: u32 = 0xCA_FE_5F_00;
/// Current protocol version.
pub const VERSION: u8 = 1;

/// Length of the authentication tag appended to each packet on the wire
/// (truncated HMAC-SHA256).  128 bits is ample for packet authentication.
pub const MAC_LEN: usize = 16;

/// Derive the HMAC key bytes from the configured `pre_shared_key`.
///
/// The key is documented as a hex string; when it decodes cleanly as hex we use
/// the decoded bytes, otherwise we fall back to the raw UTF-8 bytes so a
/// hand-written passphrase still works.  Both peers must configure the identical
/// key, so they always derive identical key bytes.
pub fn derive_key(pre_shared_key: &str) -> Vec<u8> {
    let k = pre_shared_key.trim();
    if !k.is_empty() && k.len() % 2 == 0 && k.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..k.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&k[i..i + 2], 16).unwrap_or(0))
            .collect()
    } else {
        k.as_bytes().to_vec()
    }
}

fn mac_tag(key: &[u8], bytes: &[u8]) -> [u8; MAC_LEN] {
    // HMAC accepts a key of any length, so this never fails.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(bytes);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&full[..MAC_LEN]);
    tag
}
/// Minimum wire size of a ShadowPacket (no payload).
///
/// Layout: magic(4) + version(1) + kind(1) + tunnel_id(4) + seq(4) + ack(4)
/// + window(2) = 20 bytes.  This MUST equal the number of bytes `encode`
/// writes and `decode` consumes before the payload; otherwise `decode` can
/// pass the length guard and then panic reading past the end of the buffer.
pub const HEADER_SIZE: usize = 20;

/// Type of a ShadowPacket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// Application data.
    Data = 0,
    /// Cumulative acknowledgement.
    Ack = 1,
    /// Negative acknowledgement (request retransmission).
    Nack = 2,
    /// Tunnel open request (client → server).
    Syn = 3,
    /// Tunnel open acknowledgement (server → client).
    SynAck = 4,
    /// Tunnel teardown.
    Fin = 5,
    /// Keepalive ping.
    Heartbeat = 6,
    /// Keepalive pong.
    HeartbeatAck = 7,
}

impl TryFrom<u8> for PacketKind {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Ack),
            2 => Ok(Self::Nack),
            3 => Ok(Self::Syn),
            4 => Ok(Self::SynAck),
            5 => Ok(Self::Fin),
            6 => Ok(Self::Heartbeat),
            7 => Ok(Self::HeartbeatAck),
            _ => bail!("unknown packet kind {}", v),
        }
    }
}

/// An application-level Shadow Spoof packet.
///
/// Wire format (big-endian):
/// ```text
/// [magic:4][version:1][kind:1][tunnel_id:4][seq:4][ack:4][window:2][payload…]
/// ```
#[derive(Debug, Clone)]
pub struct ShadowPacket {
    pub kind:      PacketKind,
    pub tunnel_id: u32,
    /// Sequence number of this packet (data) or highest received seq + 1 (ack).
    pub seq:       u32,
    /// Cumulative ACK – next seq the sender expects to receive.
    pub ack:       u32,
    /// Receiver window in packets.
    pub window:    u16,
    /// Payload bytes (may be empty for control packets).
    pub payload:   Bytes,
}

impl ShadowPacket {
    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn new_syn(tunnel_id: u32, seq: u32) -> Self {
        Self {
            kind:      PacketKind::Syn,
            tunnel_id,
            seq,
            ack:       0,
            window:    64,
            payload:   Bytes::new(),
        }
    }

    pub fn new_syn_ack(tunnel_id: u32, peer_seq: u32, our_seq: u32) -> Self {
        Self {
            kind:      PacketKind::SynAck,
            tunnel_id,
            seq:       our_seq,
            ack:       peer_seq.wrapping_add(1),
            window:    64,
            payload:   Bytes::new(),
        }
    }

    pub fn new_ack(tunnel_id: u32, ack: u32, window: u16) -> Self {
        Self {
            kind:      PacketKind::Ack,
            tunnel_id,
            seq:       0,
            ack,
            window,
            payload:   Bytes::new(),
        }
    }

    pub fn new_nack(tunnel_id: u32, missing_seq: u32) -> Self {
        Self {
            kind:      PacketKind::Nack,
            tunnel_id,
            seq:       missing_seq,
            ack:       0,
            window:    0,
            payload:   Bytes::new(),
        }
    }

    pub fn new_data(tunnel_id: u32, seq: u32, ack: u32, window: u16, payload: Bytes) -> Self {
        Self { kind: PacketKind::Data, tunnel_id, seq, ack, window, payload }
    }

    pub fn new_heartbeat(tunnel_id: u32, seq: u32) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            kind:      PacketKind::Heartbeat,
            tunnel_id,
            seq,
            ack:       0,
            window:    0,
            payload:   Bytes::copy_from_slice(&ts.to_be_bytes()),
        }
    }

    pub fn new_fin(tunnel_id: u32) -> Self {
        Self {
            kind:      PacketKind::Fin,
            tunnel_id,
            seq:       0,
            ack:       0,
            window:    0,
            payload:   Bytes::new(),
        }
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    /// Encode the packet to bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.put_u32(MAGIC);
        buf.put_u8(VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u32(self.tunnel_id);
        buf.put_u32(self.seq);
        buf.put_u32(self.ack);
        buf.put_u16(self.window);
        buf.put(self.payload.clone());
        buf.freeze()
    }

    /// Encode the packet and append a keyed HMAC authentication tag.
    ///
    /// This is the form used on the wire: `encode()` bytes followed by a
    /// [`MAC_LEN`]-byte tag over those bytes, keyed by the pre-shared key.
    pub fn encode_authenticated(&self, key: &[u8]) -> Bytes {
        let body = self.encode();
        let tag = mac_tag(key, &body);
        let mut buf = BytesMut::with_capacity(body.len() + MAC_LEN);
        buf.put(body);
        buf.put_slice(&tag);
        buf.freeze()
    }

    /// Verify the trailing authentication tag and decode the packet.
    ///
    /// Returns an error (without panicking) when the frame is too short, the
    /// tag does not match the pre-shared key, or the inner packet is malformed.
    /// The tag check is constant-time (`hmac`'s `verify_slice`).
    pub fn decode_authenticated(data: Bytes, key: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE + MAC_LEN {
            bail!(
                "authenticated packet too short: {} bytes (min {})",
                data.len(),
                HEADER_SIZE + MAC_LEN
            );
        }
        let split = data.len() - MAC_LEN;
        let (body, tag) = (data.slice(..split), data.slice(split..));
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&body);
        // `verify_truncated_left` checks the leading MAC_LEN bytes in constant time.
        mac.verify_truncated_left(&tag)
            .map_err(|_| anyhow::anyhow!("packet authentication failed (wrong pre_shared_key?)"))?;
        Self::decode(body)
    }

    /// Decode a packet from bytes. Returns an error on invalid input.
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            bail!("packet too short: {} bytes (min {})", data.len(), HEADER_SIZE);
        }
        let magic = data.get_u32();
        if magic != MAGIC {
            bail!("bad magic 0x{:08x}", magic);
        }
        let version = data.get_u8();
        if version != VERSION {
            bail!("unsupported version {}", version);
        }
        let kind      = PacketKind::try_from(data.get_u8())?;
        let tunnel_id = data.get_u32();
        let seq       = data.get_u32();
        let ack       = data.get_u32();
        let window    = data.get_u16();
        let payload   = data; // remaining bytes
        Ok(ShadowPacket { kind, tunnel_id, seq, ack, window, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_uses_provided_sequence() {
        let pkt = ShadowPacket::new_syn(42, 12345);
        assert_eq!(pkt.kind, PacketKind::Syn);
        assert_eq!(pkt.tunnel_id, 42);
        assert_eq!(pkt.seq, 12345);
    }

    #[test]
    fn header_size_matches_encoded_header() {
        // An empty-payload packet must encode to exactly HEADER_SIZE bytes.
        let pkt = ShadowPacket::new_fin(7);
        assert_eq!(pkt.encode().len(), HEADER_SIZE);
    }

    #[test]
    fn encode_decode_round_trips() {
        let original = ShadowPacket::new_data(
            0xDEAD_BEEF,
            0x0102_0304,
            0x0506_0708,
            0x090A,
            Bytes::from_static(b"hello candy"),
        );
        let decoded = ShadowPacket::decode(original.encode()).expect("decode");
        assert_eq!(decoded.kind, original.kind);
        assert_eq!(decoded.tunnel_id, original.tunnel_id);
        assert_eq!(decoded.seq, original.seq);
        assert_eq!(decoded.ack, original.ack);
        assert_eq!(decoded.window, original.window);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn authenticated_round_trip_with_correct_key() {
        let key = derive_key("00112233445566778899aabbccddeeff");
        let original = ShadowPacket::new_data(1, 2, 3, 4, Bytes::from_static(b"payload"));
        let wire = original.encode_authenticated(&key);
        assert_eq!(wire.len(), original.encode().len() + MAC_LEN);
        let decoded = ShadowPacket::decode_authenticated(wire, &key).expect("auth decode");
        assert_eq!(decoded.payload, original.payload);
        assert_eq!(decoded.seq, original.seq);
    }

    #[test]
    fn authenticated_decode_rejects_wrong_key() {
        let key_a = derive_key("00112233445566778899aabbccddeeff");
        let key_b = derive_key("ffeeddccbbaa99887766554433221100");
        let wire = ShadowPacket::new_syn(9, 9).encode_authenticated(&key_a);
        assert!(ShadowPacket::decode_authenticated(wire, &key_b).is_err());
    }

    #[test]
    fn authenticated_decode_rejects_tampered_payload() {
        let key = derive_key("00112233445566778899aabbccddeeff");
        let wire = ShadowPacket::new_data(1, 2, 3, 4, Bytes::from_static(b"abc"))
            .encode_authenticated(&key);
        let mut bytes = wire.to_vec();
        // Flip a bit in the payload region (after the header, before the tag).
        bytes[HEADER_SIZE] ^= 0x01;
        assert!(ShadowPacket::decode_authenticated(Bytes::from(bytes), &key).is_err());
    }

    #[test]
    fn derive_key_hex_vs_raw() {
        // Even-length all-hex string decodes to bytes ...
        assert_eq!(derive_key("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
        // ... otherwise the raw UTF-8 bytes are used (passphrase fallback).
        assert_eq!(derive_key("not-hex!"), b"not-hex!".to_vec());
    }

    #[test]
    fn decode_rejects_short_packets_without_panicking() {
        // Regression: a packet shorter than the real header (e.g. 18 or 19
        // bytes) must be rejected by the length guard, never decoded past the
        // end of the buffer.  Before the HEADER_SIZE fix these lengths passed
        // the guard and panicked inside `get_u16`.
        for len in 0..HEADER_SIZE {
            let mut buf = BytesMut::new();
            buf.put_u32(MAGIC);
            buf.resize(len, 0);
            let short = buf.freeze();
            assert_eq!(short.len(), len);
            assert!(
                ShadowPacket::decode(short).is_err(),
                "packet of {len} bytes should be rejected, not decoded"
            );
        }
    }
}
