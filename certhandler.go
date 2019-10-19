package main

import (
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"software.sslmate.com/src/go-pkcs12"
)

func storePemFiles(certs acme) error {

	for _, c := range certs.Letsencrypt.Certs {
		log.Info("Working on " + c.Domain.Main)

		if err := ioutil.WriteFile(c.Domain.Main+".key", []byte(c.Key), 0600); err != nil {
			log.Error("Couldn't write " + c.Domain.Main + ".key")
		}

		if err := ioutil.WriteFile(c.Domain.Main+".cert", []byte(c.Certificate), 0600); err != nil {
			log.Error("Couldn't write " + c.Domain.Main + ".cert")
		}
	}

	return nil
}

func storePKCS() error {

}
