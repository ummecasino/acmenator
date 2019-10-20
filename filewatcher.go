package main

import (
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

func listen(filename string, done chan bool) {

	// Do an initial run
	log.Info("Doing an initial run...")
	processFileChange(filename)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Info("Detected new change on file ", event.Name)
					processFileChange(filename)
					log.Info("Updated certs")
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error("error:", err)
			}
		}
	}()

	err = watcher.Add(filename)
	if err != nil {
		log.Fatal(err)
	}
	done <- true
}

func processFileChange(filename string) {
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

	for _, cert := range jsonContent.Letsencrypt.Certs {
		if RunArgs.ProducePEM {
			if err := storePemFiles(cert); err != nil {
				log.Error("Error during PEM saving")
			}
		}

		if RunArgs.ProducePKCS {
			if err := storePKCS(cert); err != nil {
				log.Error("Error during PKCS saving")
			}
		}
	}

}
