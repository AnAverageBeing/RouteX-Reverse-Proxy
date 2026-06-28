package proxy_test

import (
	"testing"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/proxy"
)

func TestPortmapOneToOne(t *testing.T) {
	r, err := proxy.NewResolver(
		[]int{25565, 25566, 25567},
		[]int{35565, 35566, 35567},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsOneToOne() {
		t.Error("should be one-to-one")
	}

	ports, err := r.DestPortsFor(25565)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0] != 35565 {
		t.Errorf("25565 -> %v, want [35565]", ports)
	}

	ports, err = r.DestPortsFor(25567)
	if err != nil {
		t.Fatal(err)
	}
	if ports[0] != 35567 {
		t.Errorf("25567 -> %v, want [35567]", ports)
	}
}

func TestPortmapOneToOneRangeMismatch(t *testing.T) {
	_, err := proxy.NewResolver(
		[]int{25565, 25566, 25567},
		[]int{35565, 35566},
		true,
	)
	if err == nil {
		t.Fatal("expected error for mismatched range sizes")
	}
}

func TestPortmapFanOut(t *testing.T) {
	r, err := proxy.NewResolver(
		[]int{25565},
		[]int{35565, 35566, 35567},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if r.IsOneToOne() {
		t.Error("should be fan-out mode")
	}

	ports, err := r.DestPortsFor(25565)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 3 {
		t.Errorf("fan-out should return all dest ports, got %d", len(ports))
	}
}

func TestPortmapUnknownOriginPort(t *testing.T) {
	r, _ := proxy.NewResolver(
		[]int{25565},
		[]int{35565},
		true,
	)
	_, err := r.DestPortsFor(99999)
	if err == nil {
		t.Fatal("expected error for unknown origin port in one-to-one mode")
	}
}
