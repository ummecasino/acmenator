package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
)

func storePemFiles(cert cert, dir string) error {
	domain := cert.Domain.Main
	keyBytes := []byte(cert.Key)
	certBytes := []byte(cert.Certificate)

	log.Info("Working on " + domain)
	pathKey := filepath.Join(dir, domain+".key")
	pathCert := filepath.Join(dir, domain+".pem")

	if err := ioutil.WriteFile(pathKey, keyBytes, 0600); err != nil {
		log.Error("Couldn't write "+pathKey, err)
		return err
	}

	if err := ioutil.WriteFile(pathCert, certBytes, 0600); err != nil {
		log.Error("Couldn't write "+pathCert, err)
		return err
	}

	return nil
}

func storePKCS(cert cert, dir string) error {
	domain := cert.Domain.Main
	keyBytes := []byte(cert.Key)
	certBytes := []byte(cert.Certificate)
	pkcsPath := filepath.Join(dir, domain+".pkcs12")
	reader := rand.Reader

	var err error
	var rsaKey interface{}
	var pfxData []byte
	var x509Cert x509.Certificate

	rsaKey, err = parseRsaKey(keyBytes)
	if rsaKey == nil {
		log.Error("Error generating RSA key: ", err)
		return err
	}

	x509Cert, err = parsex509Certificate(certBytes)
	if err != nil {
		log.Error("Error generating x509 cert: ", err)
		return err
	}

	if pfxData, err = pkcs12.Encode(reader, rsaKey, &x509Cert, nil, RunArgs.PKCSPassword); err != nil {
		log.Error("could not create pfx data ", err)
		return err
	}

	if err := ioutil.WriteFile(pkcsPath, pfxData, 0600); err != nil {
		log.Error("Couldn't write "+pkcsPath, err)
		return err
	}

	return nil
}

func parseRsaKey(key []byte) (interface{}, error) {

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
		return rawkey, nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func parsex509Certificate(certPEM []byte) (x509.Certificate, error) {
	var certificate x509.Certificate

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Error("failed to decode certificate PEM")
		return certificate, errors.New("no PEM data found in cert")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Error("failed to parse certficate")
		return certificate, err
	}

	return *cert, nil
}
