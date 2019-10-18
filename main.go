package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
)

// Args ...
type Args struct {
	SourceFile   string
	ProducePEM   bool
	ProducePKCS  bool
	PKCSPassword string
}

func main() {

	log.SetOutput(os.Stdout)
	var args = Args{}

	flag.StringVar(&args.SourceFile, "source", "acme.json", "The JSON source produced by Traefik")
	flag.BoolVar(&args.ProducePEM, "pem", false, "Produce a PEM key/cert pair")
	flag.BoolVar(&args.ProducePKCS, "pkcs", false, "Produce a PKCS12 keystore")
	flag.StringVar(&args.PKCSPassword, "p", "changeit", "Password fpr the PKCS keystore")
	flag.Parse()

	if _, err := os.Stat(args.SourceFile); err == nil {
		log.Debug("Found " + args.SourceFile + "...")
	} else if os.IsNotExist(err) {
		log.Fatal(args.SourceFile + " does not exist, exiting!")
		os.Exit(1)
	} else {
		log.Fatal("Something went wrong, exiting")
		os.Exit(1)
	}

	listen(args.SourceFile)

}
