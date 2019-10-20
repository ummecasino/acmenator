package main

import (
	b64 "encoding/base64"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

type acme struct {
	Letsencrypt letsencrypt `json:"letsencrypt"`
}

type letsencrypt struct {
	Certs []cert `json:"Certificates"`
}

type cert struct {
	Domain      domain `json:"domain"`
	Key         string `json:"key"`
	Certificate string `json:"certificate"`
}

type domain struct {
	Main string `json:"main"`
}

func ProcessFileChange(filename string) {
	var content []byte
	var err error
	jsonContent := acme{}

	content, err = readJSONFile(filename)
	if err != nil {
		log.Error("Wasn't able to read input file", err)
		return
	}

	if err = parseJSON(content, &jsonContent); err != nil {
		log.Error("Wasn't able to parse JSON", err)
		return
	}
}

func readJSONFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)

	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var content []byte
	if content, err = ioutil.ReadAll(file); err != nil {
		return nil, err
	}
	return content, nil
}

func parseJSON(input []byte, jsonContent *acme) error {
	if isJSON(input) {
		if err := json.Unmarshal(input, &jsonContent); err != nil {
			log.Error("Error during JSON unmarshalling!")
			return err
		}

		for i := range jsonContent.Letsencrypt.Certs {
			decodeKeyPairs(&jsonContent.Letsencrypt.Certs[i])
		}

	}
	return nil
}

func isJSON(input []byte) bool {
	var js map[string]interface{}
	return json.Unmarshal(input, &js) == nil
}

func decodeKeyPairs(decodedCert *cert) error {
	var key, cert []byte
	var err error

	if key, err = b64.StdEncoding.DecodeString(decodedCert.Key); err != nil {
		log.Error("Couldn't decode key: ", err)
		return err
	}
	if cert, err = b64.StdEncoding.DecodeString(string(decodedCert.Certificate)); err != nil {
		log.Error("Couldn't decode certificate: ", err)
		return err
	}

	decodedCert.Key = string(key)
	decodedCert.Certificate = string(cert)

	return nil
}
