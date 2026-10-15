package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Routed frames (section 6) and session messages (section 7.3): the two binary layouts of the
// protocol, encoded and decoded strictly.

const (
	frameVersion = 1
	frameHeader  = 18
	maxFrame     = 1048576
)

// Routed frame types.
const (
	frameHandshakeInit byte = 0x01
	frameHandshakeResp byte = 0x02
	frameData          byte = 0x03
	frameUnreachable   byte = 0x04
	frameRefused       byte = 0x05
	framePair          byte = 0x06
	frameReset         byte = 0x07
	// As data, carrying a session message other than message; sent only to a relay that
	// lists the control feature, which delivers it as data.
	frameControl byte = 0x08
)

const refusedNotOnRoster = 1

type frame struct {
	typ  byte
	peer [16]byte // a raw node id, or a pairing channel id for pair frames
	body []byte
}

func encodeFrame(typ byte, peer [16]byte, body []byte) ([]byte, error) {
	if frameHeader+len(body) > maxFrame {
		return nil, errors.New("frame exceeds 1 MiB")
	}
	out := make([]byte, frameHeader+len(body))
	out[0] = frameVersion
	out[1] = typ
	copy(out[2:18], peer[:])
	copy(out[frameHeader:], body)
	return out, nil
}

// decodeFrame aliases b: body is a slice of it.
func decodeFrame(b []byte) (frame, error) {
	var f frame
	if len(b) < frameHeader {
		return f, errors.New("frame shorter than its header")
	}
	if len(b) > maxFrame {
		return f, errors.New("frame exceeds 1 MiB")
	}
	if b[0] != frameVersion {
		return f, fmt.Errorf("unknown frame version %d", b[0])
	}
	f.typ = b[1]
	copy(f.peer[:], b[2:18])
	f.body = b[frameHeader:]
	return f, nil
}

func handshakeInitBody(senderIndex uint32, noise []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, senderIndex), noise...)
}

func parseHandshakeInit(body []byte) (senderIndex uint32, noise []byte, err error) {
	if len(body) < 4 {
		return 0, nil, errors.New("truncated handshake-init")
	}
	return binary.BigEndian.Uint32(body), body[4:], nil
}

func handshakeRespBody(senderIndex, receiverIndex uint32, noise []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, senderIndex)
	b = binary.BigEndian.AppendUint32(b, receiverIndex)
	return append(b, noise...)
}

func parseHandshakeResp(body []byte) (senderIndex, receiverIndex uint32, noise []byte, err error) {
	if len(body) < 8 {
		return 0, 0, nil, errors.New("truncated handshake-resp")
	}
	return binary.BigEndian.Uint32(body), binary.BigEndian.Uint32(body[4:]), body[8:], nil
}

func dataBody(receiverIndex uint32, ciphertext []byte) []byte {
	return append(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(ciphertext)), receiverIndex), ciphertext...)
}

func parseData(body []byte) (receiverIndex uint32, ciphertext []byte, err error) {
	if len(body) < 4 {
		return 0, nil, errors.New("truncated data frame")
	}
	return binary.BigEndian.Uint32(body), body[4:], nil
}

// Session message types (section 7.3).
const (
	sessMessage       byte = 0x01
	sessCredit        byte = 0x02
	sessRosterRequest byte = 0x03
	sessRoster        byte = 0x04
	sessResign        byte = 0x05
)

const flagMore = 0x01

type sessionMessage struct {
	typ    byte
	more   bool   // message
	bytes  []byte // message bytes; roster and resign UTF-8 JSON
	credit uint32
}

func (m sessionMessage) name() string {
	switch m.typ {
	case sessMessage:
		return "message"
	case sessCredit:
		return "credit"
	case sessRosterRequest:
		return "roster-request"
	case sessRoster:
		return "roster"
	case sessResign:
		return "resign"
	}
	return "unknown"
}

func encodeSessionMessage(m sessionMessage) []byte {
	switch m.typ {
	case sessMessage:
		out := make([]byte, 2+len(m.bytes))
		out[0] = sessMessage
		if m.more {
			out[1] = flagMore
		}
		copy(out[2:], m.bytes)
		return out
	case sessCredit:
		return binary.BigEndian.AppendUint32([]byte{sessCredit}, m.credit)
	case sessRosterRequest:
		return []byte{sessRosterRequest}
	default: // roster, resign
		return append([]byte{m.typ}, m.bytes...)
	}
}

// decodeSessionMessage aliases p. Roster and resign must be valid UTF-8, as the TypeScript
// client's fatal decoder requires.
func decodeSessionMessage(p []byte) (sessionMessage, error) {
	if len(p) < 1 {
		return sessionMessage{}, errors.New("empty session message")
	}
	rest := p[1:]
	switch p[0] {
	case sessMessage:
		if len(rest) < 1 {
			return sessionMessage{}, errors.New("message without flags")
		}
		return sessionMessage{typ: sessMessage, more: rest[0]&flagMore != 0, bytes: rest[1:]}, nil
	case sessCredit:
		if len(rest) != 4 {
			return sessionMessage{}, errors.New("credit must carry 4 bytes")
		}
		return sessionMessage{typ: sessCredit, credit: binary.BigEndian.Uint32(rest)}, nil
	case sessRosterRequest:
		if len(rest) != 0 {
			return sessionMessage{}, errors.New("roster-request must be empty")
		}
		return sessionMessage{typ: sessRosterRequest}, nil
	case sessRoster, sessResign:
		if !utf8.Valid(rest) {
			return sessionMessage{}, errors.New("session message is not UTF-8")
		}
		return sessionMessage{typ: p[0], bytes: rest}, nil
	}
	return sessionMessage{}, fmt.Errorf("unknown session message type %d", p[0])
}
