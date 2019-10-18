package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
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

func isJSON(input []byte) bool {
	var js map[string]interface{}
	return json.Unmarshal(input, &js) == nil
}

func parseJSON(input []byte, jsonContent *acme) error {

	if isJSON(input) {
		if err := json.Unmarshal(input, &jsonContent); err != nil {
			log.Error("Error during JSON unmarshalling!")
			return err
		}
	}
	return nil
}
