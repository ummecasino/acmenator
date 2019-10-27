package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math"
	"path/filepath"
	"testing"
)

func TestParseJSON(t *testing.T) {
	testJSONProcessing(t, filepath.Join("testdata", "acme_v1.golden"))
	testJSONProcessing(t, filepath.Join("testdata", "acme_v2.golden"))
}

func testJSONProcessing(t *testing.T, filename string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	certs := acme{}

	if err := parseJSON(content, &certs); err == nil {
		assert.Equal(t, 2., math.Abs(float64(len(certs.Certs)-len(certs.Letsencrypt.Certs))))
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
