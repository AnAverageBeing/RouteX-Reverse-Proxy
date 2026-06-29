package l7

import (
	"bytes"
	"encoding/binary"
	"time"
)

// timeNowUnixNano is the canonical time source for the l7 package.
func timeNowUnixNano() int64 { return time.Now().UnixNano() }

type ProtocolDetector struct {
	mode string
}

func NewProtocolDetector(mode string) *ProtocolDetector {
	return &ProtocolDetector{mode: mode}
}

func (pd *ProtocolDetector) Check(payload []byte) bool {
	switch pd.mode {
	case "minecraft-java":
		return validateMinecraftJava(payload)
	case "minecraft-bedrock":
		return validateMinecraftBedrock(payload)
	case "fivem":
		return validateFiveM(payload)
	case "gmod":
		return validateGMod(payload)
	case "none", "":
		return true
	default:
		return true
	}
}

func (pd *ProtocolDetector) Mode() string { return pd.mode }

func validateMinecraftJava(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}
	length, bytesRead := readVarInt(payload)
	if bytesRead <= 0 || length < 1 {
		return false
	}
	if len(payload) < bytesRead+1 {
		return false
	}
	packetID, _ := readVarInt(payload[bytesRead:])
	return packetID == 0x00 || packetID == 0xFE
}

func validateMinecraftBedrock(payload []byte) bool {
	if len(payload) < 1 {
		return false
	}
	pktID := payload[0]
	switch {
	case pktID == 0x01:
		return len(payload) >= 25 && bytes.Equal(payload[9:25], []byte{
			0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
			0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
		})
	case pktID == 0x05:
		return len(payload) >= 28
	case pktID == 0x07:
		return len(payload) >= 34
	case pktID >= 0x80 && pktID <= 0x8f:
		return len(payload) >= 4
	}
	return false
}

func validateFiveM(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	commonMethods := [][]byte{[]byte("GET "), []byte("POST"), []byte("HEAD")}
	for _, method := range commonMethods {
		if bytes.HasPrefix(payload, method) {
			return true
		}
	}
	if bytes.HasPrefix(payload, []byte("info\n")) {
		return true
	}
	return isTextishPayload(payload)
}

func validateGMod(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	if payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF {
		if len(payload) >= 5 {
			switch payload[4] {
			case 0x54, 0x55, 0x57, 0x56:
				return true
			}
		}
	}
	return isTextishPayload(payload)
}

func readVarInt(data []byte) (int, int) {
	var value int
	var position int
	for i := 0; i < len(data) && i < 5; i++ {
		b := data[i]
		value |= int(b&0x7F) << position
		if b&0x80 == 0 {
			return value, i + 1
		}
		position += 7
	}
	return 0, 0
}

func isTextishPayload(payload []byte) bool {
	printable := 0
	for _, b := range payload {
		if b >= 0x20 && b <= 0x7E || b == '\r' || b == '\n' || b == '\t' {
			printable++
		}
	}
	return len(payload) > 0 && float64(printable)/float64(len(payload)) > 0.7
}

func readBE16(data []byte) uint16 {
	if len(data) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(data[:2])
}
