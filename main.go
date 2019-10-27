package main

import (
	"flag"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// RunArgsStruct for storing flag data
type RunArgsStruct struct {
	SourceFile   string
	TargetDir    string
	ProducePEM   bool
	ProducePKCS  bool
	PKCSPassword string
	Watch        bool
	Debug        bool
}

// RunArgs containing commandline flags
var RunArgs = RunArgsStruct{}

func init() {
	flag.StringVar(&RunArgs.SourceFile, "input", "acme.json", "The JSON source produced by Traefik")
	flag.StringVar(&RunArgs.TargetDir, "outdir", "", "The output directory for generated certs")
	flag.BoolVar(&RunArgs.ProducePEM, "pem", false, "Produce a PEM style key/cert pair")
	flag.BoolVar(&RunArgs.ProducePKCS, "pkcs", false, "Produce a PKCS12 keystore")
	flag.StringVar(&RunArgs.PKCSPassword, "p", "changeit", "Password for the PKCS keystore")
	flag.BoolVar(&RunArgs.Watch, "watch", false, "Keep the program running and watch the source for changes")
	flag.BoolVar(&RunArgs.Debug, "debug", false, "Enable debug logging")
}

func initLogger(debug bool) {

	Formatter := new(log.TextFormatter)
	Formatter.TimestampFormat = "02-01-2006 15:04:05"
	Formatter.FullTimestamp = true
	log.SetFormatter(Formatter)
	log.SetOutput(os.Stdout)
	if debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	log.Debug("Logging initialized")
}

func main() {

	flag.Parse()

	initLogger(RunArgs.Debug)
	paramOK(RunArgs.SourceFile)
	paramOK(RunArgs.TargetDir)
	RunArgs.SourceFile, _ = filepath.Abs(RunArgs.SourceFile)
	RunArgs.TargetDir, _ = filepath.Abs(RunArgs.TargetDir)

	var done chan bool
	if RunArgs.Watch {
		done = make(chan bool)
	} else {
		done = make(chan bool, 1)
	}

	listen(RunArgs.SourceFile, done)
	<-done

}

func paramOK(path string) {
	if _, err := os.Stat(path); err == nil {
		log.Debug("Found " + path)
	} else if os.IsNotExist(err) {
		log.Fatal(path + " does not exist!")
	} else {
		log.Fatal("There were problems with " + path)
	}
}
