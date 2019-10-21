package main

import (
	"crypto/rsa"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStorePemFiles(t *testing.T) {
	var acme acme

	content, err := ioutil.ReadFile(filepath.Join("testdata", "acme.golden"))
	if err != nil {
		t.Failed()
	}

	if err := parseJSON(content, &acme); err != nil {
		t.Failed()
	}

	for _, cert := range acme.Letsencrypt.Certs {
		if err := storePemFiles(cert, "testdata"); err != nil {
			t.Failed()
		}
	}
}

func TestStorePKCS(t *testing.T) {
	var acme acme

	content, err := ioutil.ReadFile(filepath.Join("testdata", "acme.golden"))
	if err != nil {
		t.Failed()
	}

	if err := parseJSON(content, &acme); err != nil {
		t.Failed()
	}

	for _, cert := range acme.Letsencrypt.Certs {
		if err := storePKCS(cert, "testdata"); err != nil {
			t.Failed()
		}
	}
}

func TestParseRsaKey(t *testing.T) {

	keyBytes, err := ioutil.ReadAll(strings.NewReader(rsaKey))
	if err != nil {
		t.Failed()
	}

	key, err := parseRsaKey(keyBytes)
	if err != nil {
		t.Failed()
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		t.Log("Key is of correct type")
	default:
		t.Error("Key format is incorrect")
	}
}

func TestParsex509Certificate(t *testing.T) {

	certBytes, err := ioutil.ReadAll(strings.NewReader(x509Certificate))
	if err != nil {
		t.Failed()
	}

	cert, err := parsex509Certificate(certBytes)
	if err != nil {
		t.Failed()
	}

	assert.Equal(t, cert.Issuer.Organization[0], "Internet Widgits Pty Ltd")
	assert.Equal(t, cert.Issuer.Country[0], "AU")
}

var x509Certificate = `-----BEGIN CERTIFICATE-----
MIIFETCCAvkCFCAEGAk0nPXf3B/Wpy4qvy4OEcLvMA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTkxMDIwMTI0NTAzWhcNMjAxMDE5MTI0
NTAzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIICIjANBgkqhkiG9w0BAQEFAAOC
Ag8AMIICCgKCAgEArKsBYtSjcfgMdpwmmV3KSKymldVjmOa4UfNSRkzsryyh1sdk
kMgdD2L0jNLBMu/E4I7IV3pPuGl41ChTpi4Q9pRHc/KhxZBXxnP9XZ6ESwv1RxM/
+pjzsdt4N+eGiPMzu2oNVzjYpVopelMsfHpi3cF2Uu0oA2Z/6JZZBzKJG6Cl2Zgp
FqGMZhXb/hXtAOtrWkf/C0ps+8dq6zx+t0Y6V0I2fY1taIzwNEhGIeGVEpmAyc4q
gOXOLIzxig6lmNncGhrDRLFQlgEDP2S006IWsBdg0AJO4IRPLYscfEgtrR/bJ3ti
RJeLScyZef9QnUGGsEBZXvH3DEEQPJ4UPbK9Sz6SSxwAF/CG/VW+Raj/CXtdlmjb
ZpdIDsqhNW6aQNx6hPJoTdtNXQnRIRQyvoRFwBxlP5d5m1xZ+0xg0JtEUhQVylUF
3yWfEEJfgpjcfRUFteLug9/AIbXP+53Jnh+5zJY7Jx6n2FqpZRF5oTJOv+JBkSnf
si+QtQFmYWYkxO5CuqtBL9uCVL1dn5jNPJkTaIwiMAH+Ia9TVt7c0yL6TGDJUggH
uqFGORFkROXuqDFPEaC9B8zEfHt9hHC5w+I9jYUiALzMgkvGh0MDK1ipcD6OOVTb
PkvMkaZslAEOqWMMeyRm0XD8r3QdbG5Ql7gCDQmOUfcq8CuvHI1Xi5HHt5UCAwEA
ATANBgkqhkiG9w0BAQsFAAOCAgEAf/TDvThEwdtHkv810azyrvuviX6Y2dc5hYl+
nqiTh1hzh2FjfNMX73r16MJOldfG9ncC1ct8MwO6ITfzSWR627yOB7K8tx3PeH53
U4wQM3rdLhplbhjprKji7WMXS5uX6P66Jr/C8/1PrrdBEfQBNaenX/1g0hGVlbCE
NYtR/CS2tC/7SLLC/ktJ1cw0Rgxt+o+sHzE9vM237U/RxDOStcJUgGo/FywAKERB
NvNPvfumjCGQG4puroIHvkVzqWcX6I9l30j+BdT0wbFjUrzY5raFdTnzB6kzeT9w
yp4e45O/HTkMtTRye2yyJ4u1k+NeizOcS6L/lv34st6cGMS/4DJz5/FCE5qEhTaf
nxae1xecmGmXoH9o69QzV+EKJEXFhqry0VHQH/J3a0eNBWfrfgLoaShGhhbpnuHZ
a5s0ri1oIlkGTTYkhmSUGTGosZK7xaT1i+ZZykg6Xy8T97MSlMBwIEo1/2p2f6Jg
MFjx4H1tS8ABZtKi6bKPhbpeESUrOBSxVyKFQ6AKcY2h47rKbVAU4ybFJzaa9/HI
7NQqfhTu8ZTGOMnD6TG1KhcxVzENWd/91hkyWV1gleLCrg3eXcO+0eUXPax6SHoO
Bs1rSEyIDtPpfJKs1BhxEcSnBDbV8EmTQjGrBvtvjP2nL7eVXhnG4Uoqppdlzyvn
X940H64=
-----END CERTIFICATE-----`

var rsaKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
