package l7_test

import (
	"testing"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/l7"
)

func TestMinecraftJavaHandshake(t *testing.T) {
	// Valid Minecraft Java handshake packet:
	// VarInt length = 10, VarInt packetID = 0x00 (handshake),
	// VarInt protocol version = 754, string "localhost", ushort 25565, VarInt 2
	validPayload := []byte{
		0x10,                   // VarInt length = 16
		0x00,                   // VarInt packetID = 0
		0xF2, 0x05,            // VarInt protocol version = 754
		0x09,                   // string length 9
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0x63, 0xDD,            // port 25565 (big endian)
		0x02,                   // VarInt next state = 2
	}
	detector := l7.NewProtocolDetector("minecraft-java")
	if !detector.Check(validPayload) {
		t.Error("valid Minecraft Java handshake should pass")
	}

	// Empty payload should fail
	if detector.Check([]byte{}) {
		t.Error("empty payload should fail Minecraft Java check")
	}

	// Garbage should fail
	if detector.Check([]byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Error("garbage payload should fail Minecraft Java check")
	}
}

func TestMinecraftBedrock(t *testing.T) {
	detector := l7.NewProtocolDetector("minecraft-bedrock")

	// Unconnected ping (packet ID 0x01 + magic)
	ping := []byte{
		0x01,                                           // packet ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
		0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, // magic
		0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78, // magic cont
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // client GUID
	}
	if !detector.Check(ping) {
		t.Error("valid Bedrock unconnected ping should pass")
	}

	// Open conn request 1 (packet ID 0x05)
	oc1 := make([]byte, 28)
	oc1[0] = 0x05
	if !detector.Check(oc1) {
		t.Error("valid Bedrock open conn request 1 should pass")
	}

	// Frame set (0x80-0x8f)
	frame := make([]byte, 4)
	frame[0] = 0x84
	if !detector.Check(frame) {
		t.Error("valid Bedrock frame set should pass")
	}

	// Junk
	if detector.Check([]byte{0xFF}) {
		t.Error("junk should fail Bedrock check")
	}
}

func TestFiveM(t *testing.T) {
	detector := l7.NewProtocolDetector("fivem")

	if !detector.Check([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("GET request should pass FiveM check")
	}
	if !detector.Check([]byte("POST /client HTTP/1.1\r\n")) {
		t.Error("POST request should pass FiveM check")
	}
	if !detector.Check([]byte("info\n")) {
		t.Error("info\\n should pass FiveM check")
	}
	if !detector.Check([]byte("HEAD / HTTP/1.0\r\n")) {
		t.Error("HEAD request should pass FiveM check")
	}

	// Binary junk should fail
	if detector.Check([]byte{0x00, 0x01, 0x02, 0x03}) {
		t.Error("binary junk should fail FiveM check")
	}
}

func TestGMod(t *testing.T) {
	detector := l7.NewProtocolDetector("gmod")

	// A2S_INFO (0x54 = T)
	query := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 'S', 'o', 'u', 'r', 'c', 'e', ' ', 'E', 'n', 'g', 'i', 'n', 'e', ' ', 'Q', 'u', 'e', 'r', 'y', 0x00}
	if !detector.Check(query) {
		t.Error("valid Source query should pass")
	}

	// A2S_PLAYER (0x55 = U)
	playerQuery := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x55, 0xFF, 0xFF, 0xFF, 0xFF}
	if !detector.Check(playerQuery) {
		t.Error("A2S_PLAYER query should pass")
	}

	// Wrong prefix
	bad := []byte{0xFE, 0xFF, 0xFF, 0xFF, 0x54}
	if detector.Check(bad) {
		t.Error("wrong prefix should fail GMod check")
	}

	// Text payload should pass (fallback)
	textPayload := []byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n")
	if !detector.Check(textPayload) {
		t.Error("text payload should pass GMod check via isTextish fallback")
	}
}

func TestNoneMode(t *testing.T) {
	detector := l7.NewProtocolDetector("none")
	if !detector.Check([]byte{}) {
		t.Error("none mode should always pass")
	}
	if !detector.Check([]byte{0x00, 0x01, 0x02}) {
		t.Error("none mode should pass any payload")
	}
}

func TestUnknownMode(t *testing.T) {
	detector := l7.NewProtocolDetector("some-unknown-mode")
	// Unknown modes pass through
	if !detector.Check([]byte{0x00}) {
		t.Error("unknown mode should pass through")
	}
}
