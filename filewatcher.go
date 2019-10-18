package main

import (
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

func listen(filename string) {

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
				log.Info("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Info("modified file:", event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	done := make(chan bool)

	err = watcher.Add(filename)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}
