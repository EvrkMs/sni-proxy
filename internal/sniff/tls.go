package sniff

import (
	"encoding/binary"
	"fmt"
)

func IsTLS(data []byte) bool {
	return len(data) > 0 && data[0] == 0x16
}

func ExtractSNI(buf []byte) (string, error) {
	if len(buf) < 6 {
		return "", fmt.Errorf("buffer too short (%d bytes)", len(buf))
	}
	if buf[0] != 0x16 {
		return "", fmt.Errorf("not a TLS record (0x%02x)", buf[0])
	}

	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if len(buf) < 5+recordLen {
		return "", fmt.Errorf("incomplete TLS record")
	}

	handshake := buf[5 : 5+recordLen]
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}

	handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+handshakeLen {
		return "", fmt.Errorf("incomplete handshake")
	}

	hello := handshake[4 : 4+handshakeLen]
	pos := 0

	must := func(n int) error {
		if pos+n > len(hello) {
			return fmt.Errorf("ClientHello truncated")
		}
		return nil
	}

	u8 := func() (int, error) {
		if err := must(1); err != nil {
			return 0, err
		}
		value := int(hello[pos])
		pos++
		return value, nil
	}

	u16 := func() (int, error) {
		if err := must(2); err != nil {
			return 0, err
		}
		value := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
		pos += 2
		return value, nil
	}

	skip := func(n int) error {
		if err := must(n); err != nil {
			return err
		}
		pos += n
		return nil
	}

	if err := skip(34); err != nil {
		return "", err
	}

	sessionIDLen, err := u8()
	if err != nil {
		return "", err
	}
	if err := skip(sessionIDLen); err != nil {
		return "", err
	}

	cipherSuiteLen, err := u16()
	if err != nil {
		return "", err
	}
	if err := skip(cipherSuiteLen); err != nil {
		return "", err
	}

	compressionLen, err := u8()
	if err != nil {
		return "", err
	}
	if err := skip(compressionLen); err != nil {
		return "", err
	}

	extensionTotalLen, err := u16()
	if err != nil {
		return "", err
	}
	extensionEnd := pos + extensionTotalLen

	for pos+4 <= extensionEnd {
		extensionType, err := u16()
		if err != nil {
			break
		}

		extensionLen, err := u16()
		if err != nil {
			break
		}
		if pos+extensionLen > extensionEnd {
			break
		}

		data := hello[pos : pos+extensionLen]
		pos += extensionLen

		if extensionType == 0x0000 && len(data) >= 5 && data[2] == 0x00 {
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if len(data) >= 5+nameLen {
				return string(data[5 : 5+nameLen]), nil
			}
		}
	}

	return "", fmt.Errorf("SNI extension not found")
}
