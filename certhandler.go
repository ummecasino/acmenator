package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"software.sslmate.com/src/go-pkcs12"
)

func storePemFiles(cert cert) error {
	domain := cert.Domain.Main
	keyBytes := []byte(cert.Key)
	certBytes := []byte(cert.Certificate)

	log.Info("Working on " + domain)

	if err := ioutil.WriteFile(domain+".key", keyBytes, 0600); err != nil {
		log.Error("Couldn't write " + domain + ".key")
	}

	if err := ioutil.WriteFile(domain+".crt", certBytes, 0600); err != nil {
		log.Error("Couldn't write " + domain + ".crt")
	}

	return nil
}

func storePKCS(cert cert) error {
	domain := cert.Domain.Main
	keyBytes := []byte(cert.Key)
	certBytes := []byte(cert.Certificate)

	var err error
	var rsaKey interface{}
	var pfxData []byte
	var x509Cert x509.Certificate

	reader := rand.Reader

	rsaKey, err = parseRsaKey(keyBytes)
	if rsaKey == nil {
		log.Error("Error generating RSA key: ", err)
		return err
	}

	x509Cert, err = parsex509Certificate(certBytes)
	if err != nil {
		return err
	}

	if pfxData, err = pkcs12.Encode(reader, rsaKey, &x509Cert, nil, RunArgs.PKCSPassword); err != nil {
		log.Error("could not create pfx data ", err)
		return err
	}

	if err := ioutil.WriteFile(domain+".pkcs12", pfxData, 0600); err != nil {
		log.Error("Couldn't write " + domain + ".pkcs12")
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
