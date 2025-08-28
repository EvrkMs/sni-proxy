package udpproxy

import (
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"
)

func extractConnectionIDs(b []byte, logger *zap.Logger) (dcid, scid []byte, err error) {
	if len(b) < 7 {
		logger.Debug("[QUIC] extractConnectionIDs: insufficient data for header", zap.Int("len", len(b)))
		return nil, nil, fmt.Errorf("insufficient QUIC header")
	}
	if (b[0] & 0x80) == 0 {
		logger.Debug("[QUIC] extractConnectionIDs: not a Long Header (flags=0x%x)", zap.Uint8("flags", b[0]))
		return nil, nil, fmt.Errorf("not a QUIC Long Header")
	}

	pos := 1 + 4 // flags(1) + version(4)

	dlen := int(b[pos])
	pos++
	if pos+dlen > len(b) {
		logger.Debug("[QUIC] extractConnectionIDs: truncated DCID", zap.Int("pos", pos), zap.Int("dlen", dlen), zap.Int("total_len", len(b)))
		return nil, nil, fmt.Errorf("truncated DCID")
	}
	dcid = make([]byte, dlen)
	copy(dcid, b[pos:pos+dlen])
	pos += dlen
	logger.Debug("[QUIC] extractConnectionIDs: DCID parsed", zap.String("dcid_hex", fmt.Sprintf("%x", dcid)))

	if pos >= len(b) {
		logger.Debug("[QUIC] extractConnectionIDs: no space for SCID length")
		return nil, nil, fmt.Errorf("no space for SCID length")
	}
	slen := int(b[pos])
	pos++
	if pos+slen > len(b) {
		logger.Debug("[QUIC] extractConnectionIDs: truncated SCID", zap.Int("pos", pos), zap.Int("slen", slen), zap.Int("total_len", len(b)))
		return nil, nil, fmt.Errorf("truncated SCID")
	}
	scid = make([]byte, slen)
	copy(scid, b[pos:pos+slen])
	logger.Debug("[QUIC] extractConnectionIDs: SCID parsed", zap.String("scid_hex", fmt.Sprintf("%x", scid)))

	return dcid, scid, nil
}

func extractSNIFromQUICInitial(b []byte, logger *zap.Logger) (string, string, error) {
	if len(b) < 6 || (b[0]&0x80) == 0 {
		logger.Debug("[QUIC] extractSNI: not Long Header or too short", zap.Int("len", len(b)))
		return "", "", fmt.Errorf("not Long Header")
	}
	packetType := (b[0] & 0x30) >> 4
	if packetType != 0 {
		logger.Debug("[QUIC] extractSNI: not an Initial packet (type=0x%x)", zap.Uint8("type", packetType))
		return "", "", fmt.Errorf("not Initial packet")
	}

	pos := 1 + 4 // flags + version

	for i := 0; i < 2; i++ {
		if pos >= len(b) {
			logger.Debug("[QUIC] extractSNI: truncating DCID/SCID area at i=%d, pos=%d", zap.Int("i", i), zap.Int("pos", pos))
			return "", "", fmt.Errorf("truncating DCID/SCID area")
		}
		l := int(b[pos])
		pos++
		pos += l
	}

	tok, n, err := quicvarint.Parse(b[pos:])
	if err != nil {
		logger.Debug("[QUIC] extractSNI: bad token length varint", zap.Int("pos", pos))
		return "", "", fmt.Errorf("bad token length")
	}
	logger.Debug("[QUIC] extractSNI: token length varint", zap.Uint64("token_len", tok), zap.Int("bytes_read", n))
	pos += n + int(tok)

	length, n, err := quicvarint.Parse(b[pos:])
	if err != nil {
		logger.Debug("[QUIC] extractSNI: bad length varint", zap.Int("pos", pos))
		return "", "", fmt.Errorf("bad length varint")
	}
	logger.Debug("[QUIC] extractSNI: length varint", zap.Uint64("length", length), zap.Int("bytes_read", n))
	pos += n

	for pos < len(b) {
		ft := b[pos]
		pos++
		off, n, err := quicvarint.Parse(b[pos:])
		if err != nil {
			logger.Debug("[QUIC] extractSNI: bad offset varint", zap.Int("pos", pos))
			return "", "", fmt.Errorf("bad offset varint")
		}
		pos += n
		_ = off
		flen, n2, err := quicvarint.Parse(b[pos:])
		if err != nil {
			logger.Debug("[QUIC] extractSNI: bad length varint", zap.Int("pos", pos))
			return "", "", fmt.Errorf("bad length varint")
		}
		pos += n2
		if pos+int(flen) > len(b) {
			logger.Debug("[QUIC] extractSNI: CRYPTO frame truncated", zap.Int("pos", pos), zap.Int("flen", int(flen)), zap.Int("total_len", len(b)))
			return "", "", fmt.Errorf("CRYPTO truncated")
		}
		if ft != 0x06 {
			pos += int(flen)
			continue
		}

		logger.Debug("[QUIC] extractSNI: found CRYPTO frame, trying parse ClientHello", zap.Int("crypto_len", int(flen)))
		slice := b[pos : pos+int(flen)]
		ch := utls.UnmarshalClientHello(slice)
		if ch != nil && ch.ServerName != "" {
			logger.Debug("[QUIC] extractSNI: ClientHello parsed, SNI found", zap.String("sni", ch.ServerName))
			alpn := ""
			if len(ch.AlpnProtocols) > 0 {
				alpn = ch.AlpnProtocols[0]
			}
			return ch.ServerName, alpn, nil
		}
		logger.Debug("[QUIC] extractSNI: ClientHello parsed but no SNI inside")
		return "", "", fmt.Errorf("SNI not found in TLS ClientHello")
	}

	logger.Debug("[QUIC] extractSNI: no CRYPTO frame found in Initial")
	return "", "", fmt.Errorf("no CRYPTO frame found")
}

func (p *Proxy) sniffInitial(dcidHex string, addr *net.UDPAddr, data []byte) {
	p.unknownMu.Lock()
	defer p.unknownMu.Unlock()

	for k, buf := range p.unknown {
		if time.Since(buf.created) > p.cfg.SniffTTL {
			delete(p.unknown, k)
			p.log.Debug("[sniffInitial] expired buffer", zap.String("dcid", k))
		}
	}

	buf, ok := p.unknown[dcidHex]
	if !ok {
		buf = &peekBuf{created: time.Now()}
		p.unknown[dcidHex] = buf
		p.log.Debug("[sniffInitial] new buffer created", zap.String("dcid", dcidHex))
	}

	if len(buf.pkts) < p.cfg.MaxSniffPkts {
		pktCopy := make([]byte, len(data))
		copy(pktCopy, data)
		buf.pkts = append(buf.pkts, pktCopy)
		p.log.Debug("[sniffInitial] appended packet", zap.String("dcid", dcidHex), zap.Int("packet_len", len(data)), zap.Int("buffered_pkts", len(buf.pkts)))
	} else {
		delete(p.unknown, dcidHex)
		p.log.Debug("[sniffInitial] buffer cleared due to exceeding maxSniffPkts", zap.String("dcid", dcidHex))
		return
	}

	full := make([]byte, 0, len(data)*len(buf.pkts))
	for _, b := range buf.pkts {
		full = append(full, b...)
	}
	p.log.Debug("[sniffInitial] trying extractSNIFromQUICInitial", zap.String("dcid", dcidHex), zap.Int("full_len", len(full)))

	if sni, alpn, err := extractSNIFromQUICInitial(full, p.log); err == nil {
		if v, ok := p.clients.Load(dcidHex); ok {
			info := v.(*clientInfo)
			info.domain = sni
			info.alpn = alpn
			p.clients.Store(dcidHex, info)
		} else {
			p.clients.Store(dcidHex, &clientInfo{
				addr:     addr,
				domain:   sni,
				alpn:     alpn,
				lastSeen: time.Now(),
			})
		}
		p.log.Info("[sniffInitial] SNI/ALPN extracted", zap.String("dcid", dcidHex), zap.String("sni", sni), zap.String("alpn", alpn))
		delete(p.unknown, dcidHex)
	} else {
		p.log.Debug("[sniffInitial] extractSNI error", zap.String("dcid", dcidHex), zap.Error(err))
	}
}

func isQUIC(b []byte) bool {
	return len(b) > 0 && (b[0]&0x80) == 0x80
}

func isQUICInitial(b []byte) bool {
	return isQUIC(b) && ((b[0]&0x30)>>4) == 0
}
