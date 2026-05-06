package sniff

import "fmt"

// QUICHeader holds the minimal fields from a QUIC Long Header needed to
// construct a Version Negotiation response (RFC 9000 §17.2.1).
type QUICHeader struct {
	DCID []byte
	SCID []byte
}

// ParseQUICLongHeader parses the first bytes of a QUIC long-header packet
// (Initial, 0-RTT, Handshake, or Retry) and extracts the connection IDs.
// Returns an error if the packet is too short or not a long-header form.
func ParseQUICLongHeader(buf []byte) (QUICHeader, error) {
	// Long header: first byte bit 7 must be 1, bit 6 (Fixed Bit) must be 1.
	// We accept any long-header packet (Initial = 0xC0..0xCF etc.).
	if len(buf) < 7 {
		return QUICHeader{}, fmt.Errorf("packet too short")
	}
	if buf[0]&0x80 == 0 {
		return QUICHeader{}, fmt.Errorf("not a long-header packet")
	}

	// bytes 1-4: Version (4 bytes) — skip
	pos := 5

	// DCID length (1 byte) + DCID
	if pos >= len(buf) {
		return QUICHeader{}, fmt.Errorf("truncated at DCID length")
	}
	dcidLen := int(buf[pos])
	pos++
	if pos+dcidLen > len(buf) {
		return QUICHeader{}, fmt.Errorf("truncated DCID")
	}
	dcid := make([]byte, dcidLen)
	copy(dcid, buf[pos:pos+dcidLen])
	pos += dcidLen

	// SCID length (1 byte) + SCID
	if pos >= len(buf) {
		return QUICHeader{}, fmt.Errorf("truncated at SCID length")
	}
	scidLen := int(buf[pos])
	pos++
	if pos+scidLen > len(buf) {
		return QUICHeader{}, fmt.Errorf("truncated SCID")
	}
	scid := make([]byte, scidLen)
	copy(scid, buf[pos:pos+scidLen])

	return QUICHeader{DCID: dcid, SCID: scid}, nil
}

// BuildVersionNegotiation constructs a QUIC Version Negotiation packet
// (RFC 9000 §17.2.1) that lists no supported versions, causing any QUIC client
// to immediately fall back to TCP/TLS.
//
// Response DCID = client's SCID, response SCID = client's DCID.
func BuildVersionNegotiation(h QUICHeader) []byte {
	// Total: 1 (flags) + 4 (version=0) + 1 (dcid len) + dcid + 1 (scid len) + scid
	size := 1 + 4 + 1 + len(h.SCID) + 1 + len(h.DCID)
	pkt := make([]byte, 0, size)

	// Flags: Long Header (bit7=1), Fixed Bit (bit6=1), reserved bits 0 → 0xC0
	pkt = append(pkt, 0xC0)

	// Version = 0x00000000 — signals Version Negotiation
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)

	// DCID = client's SCID
	pkt = append(pkt, byte(len(h.SCID)))
	pkt = append(pkt, h.SCID...)

	// SCID = client's DCID
	pkt = append(pkt, byte(len(h.DCID)))
	pkt = append(pkt, h.DCID...)

	// No supported versions → client falls back to TCP immediately.
	// RFC 9000 §6.1: "A client MUST discard any Version Negotiation packet
	// that lists the QUIC version selected by the client."
	// Listing nothing is valid and universally causes TCP fallback.

	return pkt
}
