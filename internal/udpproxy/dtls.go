package udpproxy

import (
	"fmt"
	"net"
	"time"

	extension "github.com/pion/dtls/v2/pkg/protocol/extension"
	handshake "github.com/pion/dtls/v2/pkg/protocol/handshake"
	"go.uber.org/zap"
)

func extractSNIFromDTLS(pkt []byte) (string, string, error) {
	if len(pkt) >= handshake.HeaderLength {
		pkt = pkt[handshake.HeaderLength:]
	}

	var ch handshake.MessageClientHello
	if err := ch.Unmarshal(pkt); err != nil {
		return "", "", fmt.Errorf("DTLS unmarshal error: %w", err)
	}

	sni := ""
	alpn := ""
	for _, ext := range ch.Extensions {
		switch e := ext.(type) {
		case *extension.ServerName:
			if len(e.ServerName) > 0 {
				sni = e.ServerName
			}
		case *extension.ALPN:
			if len(e.ProtocolNameList) > 0 {
				alpn = e.ProtocolNameList[0]
			}
		}
	}
	if sni == "" {
		return "", "", fmt.Errorf("SNI not found in DTLS")
	}
	return sni, alpn, nil
}

func (p *Proxy) feedDTLS(addr *net.UDPAddr, rec []byte) (string, bool) {
	if !isDTLSClientHello(rec) {
		return "", false
	}

	hs := rec[13:]
	if len(hs) < 12 {
		p.log.Debug("[UDP] DTLS fragment too short", zap.String("cli", addr.String()))
		return "", false
	}

	totalLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	msgSeq := int(hs[4])<<8 | int(hs[5])
	fragOff := int(hs[6])<<16 | int(hs[7])<<8 | int(hs[8])
	fragLen := int(hs[9])<<16 | int(hs[10])<<8 | int(hs[11])
	if len(hs) < 12+fragLen {
		p.log.Debug("[UDP] DTLS fragment truncated", zap.String("cli", addr.String()), zap.Int("len", len(hs)), zap.Int("expected", 12+fragLen))
		return "", false
	}
	frag := hs[12 : 12+fragLen]

	key := fmt.Sprintf("%s:%d", addr.String(), msgSeq)
	p.dtlsMu.Lock()
	buf, ok := p.dtls[key]
	if !ok {
		buf = &dtlsBuf{
			header:         hs[0:12],
			totalLen:       totalLen,
			messageBodyLen: totalLen,
			frags:          make(map[int][]byte),
			created:        time.Now(),
		}
		p.dtls[key] = buf
	}
	buf.frags[fragOff] = append([]byte(nil), frag...)

	collected := 0
	for _, f := range buf.frags {
		collected += len(f)
	}
	if collected < buf.messageBodyLen {
		p.dtlsMu.Unlock()
		return "", false
	}

	header := append([]byte(nil), buf.header...)
	bodyLen := buf.messageBodyLen
	frags := make(map[int][]byte, len(buf.frags))
	for off, f := range buf.frags {
		frags[off] = append([]byte(nil), f...)
	}
	delete(p.dtls, key)
	p.dtlsMu.Unlock()

	fullBody := make([]byte, bodyLen)
	for off, f := range frags {
		if off+len(f) > bodyLen {
			p.log.Warn("[UDP] DTLS fragment overflow", zap.String("cli", addr.String()), zap.Int("off", off), zap.Int("len", len(f)), zap.Int("total", bodyLen))
			continue
		}
		copy(fullBody[off:], f)
	}
	for i := 0; i < bodyLen; i++ {
		found := false
		for off, f := range frags {
			if i >= off && i < off+len(f) {
				found = true
				break
			}
		}
		if !found {
			p.log.Debug("[UDP] DTLS fragment gap", zap.String("cli", addr.String()), zap.Int("offset", i))
			return "", false
		}
	}
	full := append(header, fullBody...)
	p.log.Debug("[UDP] DTLS message complete", zap.String("cli", addr.String()), zap.Int("totalLen", totalLen))

	sni, alpn, err := extractSNIFromDTLS(full)
	if err != nil {
		p.log.Debug("[UDP] DTLS SNI extraction failed", zap.String("cli", addr.String()), zap.Error(err))
		return "", false
	}
	p.clients.Store(addr.String(), &clientInfo{
		addr:     addr,
		domain:   sni,
		alpn:     alpn,
		lastSeen: time.Now(),
	})
	return sni, true
}

func isDTLS(b []byte) bool {
	return len(b) > 13 &&
		b[0] == 22 &&
		b[1] == 0xfe &&
		(b[2] >= 0xfd && b[2] <= 0xff)
}

func isDTLSClientHello(b []byte) bool {
	return isDTLS(b) && len(b) > 14 && b[13] == 1
}
