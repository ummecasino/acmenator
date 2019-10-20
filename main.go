package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
)

// RunArgsStruct ...
type RunArgsStruct struct {
	SourceFile   string
	ProducePEM   bool
	ProducePKCS  bool
	PKCSPassword string
}

// RunArgs ...
var RunArgs RunArgsStruct = RunArgsStruct{}

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {

	flag.StringVar(&RunArgs.SourceFile, "source", "acme.json", "The JSON source produced by Traefik")
	flag.BoolVar(&RunArgs.ProducePEM, "pem", false, "Produce a PEM key/cert pair")
	flag.BoolVar(&RunArgs.ProducePKCS, "pkcs", false, "Produce a PKCS12 keystore")
	flag.StringVar(&RunArgs.PKCSPassword, "p", "changeit", "Password fpr the PKCS keystore")
	flag.Parse()

	if _, err := os.Stat(RunArgs.SourceFile); err == nil {
		log.Debug("Found " + RunArgs.SourceFile + "...")
	} else if os.IsNotExist(err) {
		log.Fatal(RunArgs.SourceFile + " does not exist, exiting!")
		os.Exit(1)
	} else {
		log.Fatal("Something went wrong, exiting")
		os.Exit(1)
	}

	done := make(chan bool)
	listen(RunArgs.SourceFile, done)
	<-done

}
