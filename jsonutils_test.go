package main

import (
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
		//	assert.Equal(t, certs.Letsencrypt.Certs[0].Domain.Main, "baz.foo.bar")
		//	assert.Equal(t, certs.Letsencrypt.Certs[0].Certificate, "cert")
		//	assert.Equal(t, certs.Letsencrypt.Certs[0].Key, "key")
	} else {
		t.Failed()
	}

}
