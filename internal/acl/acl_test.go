package acl_test

import (
	"net"
	"testing"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/acl"
)

func TestNewEngine_InvalidCIDR(t *testing.T) {
	_, err := acl.NewEngine("test", acl.Allow, []acl.Rule{
		{Action: acl.Deny, CIDR: "not-a-cidr"},
	}, true)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestNewEngine_SingleIP(t *testing.T) {
	e, err := acl.NewEngine("test", acl.Allow, []acl.Rule{
		{Action: acl.Deny, CIDR: "1.2.3.4"},
	}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Check(net.ParseIP("1.2.3.4")) != "deny" {
		t.Error("exact IP rule should deny")
	}
	if e.Check(net.ParseIP("1.2.3.5")) != "allow" {
		t.Error("non-matching IP should allow by default")
	}
}

func TestACL_Blacklist(t *testing.T) {
	e, _ := acl.NewEngine("blacklist", acl.Allow, []acl.Rule{
		{Action: acl.Deny, CIDR: "10.0.0.0/8", Comment: "block RFC1918"},
	}, true)

	if e.Check(net.ParseIP("10.1.2.3")) != "deny" {
		t.Error("10.x.x.x should be denied")
	}
	if e.Check(net.ParseIP("8.8.8.8")) != "allow" {
		t.Error("public IP should be allowed")
	}
}

func TestACL_Whitelist(t *testing.T) {
	e, _ := acl.NewEngine("whitelist", acl.Deny, []acl.Rule{
		{Action: acl.Allow, CIDR: "192.168.1.0/24"},
	}, true)

	if e.Check(net.ParseIP("192.168.1.50")) != "allow" {
		t.Error("allowed subnet should pass")
	}
	if e.Check(net.ParseIP("192.168.2.1")) != "deny" {
		t.Error("non-allowed IP should be denied by default")
	}
}

func TestACL_FirstMatchWins(t *testing.T) {
	e, _ := acl.NewEngine("order", acl.Allow, []acl.Rule{
		{Action: acl.Deny, CIDR: "5.5.5.0/24"},
		{Action: acl.Allow, CIDR: "5.5.5.5/32"}, // overridden by first deny
	}, true)

	if e.Check(net.ParseIP("5.5.5.5")) != "deny" {
		t.Error("first rule should win — deny before allow")
	}
}

func TestACL_NilIP(t *testing.T) {
	e, _ := acl.NewEngine("test", acl.Deny, nil, true)
	if e.Check(nil) != "allow" {
		t.Error("nil IP should always be allowed (fail open)")
	}
}

func TestACL_Disabled(t *testing.T) {
	e, _ := acl.NewEngine("test", acl.Deny, []acl.Rule{
		{Action: acl.Deny, CIDR: "0.0.0.0/0"},
	}, false) // disabled
	if e.Check(net.ParseIP("1.2.3.4")) != "allow" {
		t.Error("disabled ACL should always allow")
	}
}

func TestACL_AddRemoveRule(t *testing.T) {
	e, _ := acl.NewEngine("test", acl.Allow, nil, true)

	if err := e.AddRule(acl.Deny, "9.9.9.9", "block test"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if e.Check(net.ParseIP("9.9.9.9")) != "deny" {
		t.Error("newly added rule should deny")
	}

	n := e.RemoveRule("9.9.9.9")
	if n != 1 {
		t.Errorf("RemoveRule returned %d, want 1", n)
	}
	if e.Check(net.ParseIP("9.9.9.9")) != "allow" {
		t.Error("removed rule should now allow")
	}
}

func TestACL_ReplaceRules(t *testing.T) {
	e, _ := acl.NewEngine("test", acl.Allow, []acl.Rule{
		{Action: acl.Deny, CIDR: "1.1.1.0/24"},
	}, true)
	if e.Check(net.ParseIP("1.1.1.1")) != "deny" { t.Fatal("pre-replace should deny") }

	e.ReplaceRules([]acl.Rule{
		{Action: acl.Deny, CIDR: "2.2.2.0/24"},
	})
	if e.Check(net.ParseIP("1.1.1.1")) != "allow" { t.Error("old rule should be gone") }
	if e.Check(net.ParseIP("2.2.2.2")) != "deny" { t.Error("new rule should deny") }
}

func TestACL_Stats(t *testing.T) {
	e, _ := acl.NewEngine("test", acl.Allow, []acl.Rule{
		{Action: acl.Deny, CIDR: "3.3.3.0/24"},
	}, true)

	e.Check(net.ParseIP("3.3.3.1")) // denied
	e.Check(net.ParseIP("4.4.4.4")) // allowed
	e.Check(net.ParseIP("4.4.4.5")) // allowed

	allowed, denied := e.Stats()
	if denied != 1 {
		t.Errorf("denied = %d, want 1", denied)
	}
	if allowed != 2 {
		t.Errorf("allowed = %d, want 2", allowed)
	}
}

func TestACL_SetDefaultAction(t *testing.T) {
	e, _ := acl.NewEngine("test", acl.Allow, nil, true)
	if e.Check(net.ParseIP("1.1.1.1")) != "allow" { t.Fatal("initial default should allow") }

	e.SetDefaultAction(acl.Deny)
	if e.Check(net.ParseIP("1.1.1.1")) != "deny" { t.Error("updated default should deny") }
}

func TestACL_SetEnabled(t *testing.T) {
	e, _ := acl.NewEngine("test", acl.Deny, nil, true)
	if e.Check(net.ParseIP("1.1.1.1")) != "deny" { t.Fatal("enabled engine should deny") }

	e.SetEnabled(false)
	if e.Check(net.ParseIP("1.1.1.1")) != "allow" { t.Error("disabled engine should allow") }
}

func TestACL_IPv6(t *testing.T) {
	e, err := acl.NewEngine("ipv6", acl.Allow, []acl.Rule{
		{Action: acl.Deny, CIDR: "2001:db8::/32"},
	}, true)
	if err != nil {
		t.Fatalf("IPv6 CIDR: %v", err)
	}
	if e.Check(net.ParseIP("2001:db8::1")) != "deny" {
		t.Error("IPv6 CIDR deny should work")
	}
	if e.Check(net.ParseIP("2001:db9::1")) != "allow" {
		t.Error("non-matching IPv6 should allow")
	}
}
