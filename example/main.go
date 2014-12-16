package main

import "github.com/nanobox-core/router"
import "github.com/jcelliott/lumber"
import "time"

func main() {
	log := lumber.NewConsoleLogger(lumber.INFO)

	r := router.New(80, log)
	r.AddTarget("/", "http://drawception.com")
	r.AddTarget("/category/", "http://macmagazine.com.br")

	log.Info("start")
	time.Sleep(100 * time.Second)
	log.Info("why")
}
