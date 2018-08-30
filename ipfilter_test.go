package ipfilter

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSingleIP(t *testing.T) {
	f, err := New(Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestIntervalSingleIP(t *testing.T) {
	var low = time.Now().Truncate(time.Hour * 2)
	var up = time.Now().Add(time.Hour * 2)
	f, err := New(Options{
		//		AllowedIPs:      []string{"222.25.118.1"},
		BlockByDefault:  true,
		AllowedSchedule: []*IPInterval{&IPInterval{AllowedIPs: "222.25.118.1", Lower: &low, Upper: &up}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestIntervalSingleIP2(t *testing.T) {
	var low = time.Now().Add(time.Hour * 2)
	var up = time.Now().Add(time.Hour * 3)
	f, err := New(Options{
		//		AllowedIPs:      []string{"222.25.118.1"},
		BlockByDefault:  true,
		AllowedSchedule: []*IPInterval{&IPInterval{AllowedIPs: "222.25.118.1", Lower: &low, Upper: &up}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Blocked("222.25.118.1"), "[1] should be blocked")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 1}), "[3] should be blocked")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestSubnetIP(t *testing.T) {
	f, err := New(Options{

		AllowedIPs:     []string{"10.0.0.0/16"},
		BlockByDefault: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("10.0.0.1"), "[1] should be allowed")
	assert.True(t, f.Allowed("10.0.42.1"), "[2] should be allowed")
	assert.True(t, f.Blocked("10.42.0.1"), "[3] should be blocked")
}

func TestIntervalSubnetIP(t *testing.T) {
	var low = time.Now().Truncate(time.Hour * 2)
	var up = time.Now().Add(time.Hour * 2)

	f, err := New(Options{
		//	AllowedIPs:     []string{"10.0.0.0/16"},
		AllowedSchedule: []*IPInterval{&IPInterval{AllowedIPs: "10.0.0.0/16", Lower: &low, Upper: &up}},

		BlockByDefault: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("10.0.0.1"), "[1] should be allowed")
	assert.True(t, f.Allowed("10.0.42.1"), "[2] should be allowed")
	assert.True(t, f.Blocked("10.42.0.1"), "[3] should be blocked")
}

func TestManualCountryCode(t *testing.T) {
	f, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, f.IPToCountry("203.25.111.68"), "AU")
	assert.Equal(t, f.IPToCountry("216.58.199.67"), "US")
}

func TestCountryCodeWhiteList(t *testing.T) {
	f, err := New(Options{
		AllowedCountries: []string{"AU"},
		BlockByDefault:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("203.25.111.68"), "[1] should be allowed")
	assert.True(t, f.Blocked("216.58.199.67"), "[2] should be blocked")
}

func TestCountryCodeBlackList(t *testing.T) {
	f, err := New(Options{
		BlockedCountries: []string{"RU", "CN"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("203.25.111.68"), "[1] AU should be allowed")
	assert.True(t, f.Allowed("216.58.199.67"), "[2] US should be allowed")
	assert.True(t, f.Blocked("116.31.116.51"), "[3] CN should be blocked")
}

func TestDynamicList(t *testing.T) {
	f, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("116.31.116.51"), "[1] CN should be allowed")
	f.BlockCountry("CN")
	assert.True(t, f.Blocked("116.31.116.51"), "[1] CN should be blocked")
}

func TestJSONUnmarsharl(t *testing.T) {
	allowedSchedule := `[{"lower":"02 Jan 06 15:04 MST","upper":"02 Jan 06 16:04 MST","allowedips":"116.31.116.51"}]`
	var allowedScheduleO []*IPInterval
	json.Unmarshal([]byte(allowedSchedule), &allowedScheduleO)
	fmt.Printf("IP : %+v", allowedScheduleO[0].AllowedIPs)
	assert.Equal(t, allowedScheduleO[0].AllowedIPs, "116.31.116.51")
	v, _ := time.Parse(time.RFC822, "02 Jan 06 15:04 MST")
	assert.Equal(t, allowedScheduleO[0].Lower, &v)
}

func TestGetAllIP(t *testing.T) {
	ip := "192.168.1.23-192.168.1.54"
	ip1 := "192.168.1.23"
	ip2 := "192.168.1.23-192.158.1.54"
	var ips []string
	var ips1 []string
	var ips2 []string
	ips = getAllIPs(ip)
	ips1 = getAllIPs(ip1)
	ips2 = getAllIPs(ip2)
	assert.Equal(t, 32, len(ips))
	assert.Equal(t, 1, len(ips1))
	assert.Equal(t, 1, len(ips2))
}
