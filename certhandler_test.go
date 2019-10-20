package main

import (
	"io/ioutil"
	"path/filepath"
	"testing"
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

	if err := storePemFiles(acme); err != nil {
		t.Failed()
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
		if err := storePKCS(cert.Domain.Main, []byte(cert.Key), []byte(cert.Certificate)); err != nil {
			t.Failed()
		}
	}

}
