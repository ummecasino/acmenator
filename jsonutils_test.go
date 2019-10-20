package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestParseJSON(t *testing.T) {

	content, err := ioutil.ReadFile(filepath.Join("testdata", "acme.golden"))
	if err != nil {
		t.Failed()
	}

	certs := acme{}

	if err := parseJSON(content, &certs); err == nil {

		for _, cert := range certs.Letsencrypt.Certs {
			print("Key: " + cert.Key)
			println()
			print("Cert: " + cert.Certificate)
		}

		//	assert.Equal(t, certs.Letsencrypt.Certs[0].Domain.Main, "baz.foo.bar")
		//	assert.Equal(t, certs.Letsencrypt.Certs[0].Certificate, "cert")
		//	assert.Equal(t, certs.Letsencrypt.Certs[0].Key, "key")
	} else {
		t.Failed()
	}

}

func TestDecodeKeyPairs(t *testing.T) {

	cert := cert{
		Domain:      domain{"foo.bar"},
		Key:         "a2V5",
		Certificate: "Y2VydA==",
	}

	if err := decodeKeyPairs(&cert); err != nil {
		t.Failed()
	}

	assert.Equal(t, cert.Key, "key")
	assert.Equal(t, cert.Certificate, "cert")

}
