package main

import (
	"gotest.tools/assert"
	"testing"
)

var testCert = []byte(`{"letsencrypt": {"Account":{}, "Certificates": [{"domain": {"main": "baz.foo.bar"},"certificate": "cert","key": "key","Store": "default"}]}}`)

func TestParseJSON(t *testing.T) {

	certs := acme{}
	if err := parseJSON(testCert, &certs); err == nil {
		assert.Equal(t, certs.Letsencrypt.Certs[0].Domain.Main, "baz.foo.bar")
		assert.Equal(t, certs.Letsencrypt.Certs[0].Certificate, "cert")
		assert.Equal(t, certs.Letsencrypt.Certs[0].Key, "key")
	} else {
		t.Failed()
	}

}
