package tunnel

import (
	"bytes"
	"testing"
)

func TestDNSFilterAndNegativeReply(t *testing.T) {
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 11, 'd', 'o', 'u', 'b', 'l', 'e', 'c', 'l', 'i', 'c', 'k', 3, 'n', 'e', 't', 0, 0, 1, 0, 1}
	name, end := dnsQuestion(query)
	if name != "www.doubleclick.net" || end != len(query) || !blockedDNS(name, true, false) || blockedDNS(name, false, true) {
		t.Fatalf("unexpected question or split category: %q, %d", name, end)
	}
	if blockedDNS("notdoubleclick.net", true, true) || !blockedDNS("sub.google-analytics.com", false, true) {
		t.Fatal("domain match crossed a label boundary or missed a tracker")
	}
	answer := negativeDNS(query, 3)
	if answer[2] != 0x81 || answer[3] != 0x83 || !bytes.Equal(answer[:2], query[:2]) || !bytes.Equal(answer[12:], query[12:]) {
		t.Fatalf("invalid NXDOMAIN reply: %x", answer)
	}
	for i := 0; i < len(query); i++ {
		if _, end := dnsQuestion(query[:i]); end != 0 {
			t.Fatalf("truncated question at %d was accepted", i)
		}
	}
}
