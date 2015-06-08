package main

import "github.com/pagodabox/nanobox-router"
import "github.com/jcelliott/lumber"
import "time"

func main() {
	log := lumber.NewConsoleLogger(lumber.INFO)

	r := router.New("80", log)
	r.AddTarget("/", "http://drawception.com")
	r.AddTarget("/category/", "http://macmagazine.com.br")

	log.Info("adding tcpforward to google.com:80")
	port, err := r.AddForward("192.168.13.164:22")
	if err != nil {
		log.Error(err.Error())
	}
	log.Info("%d\n", port)

	time.Sleep(100 * time.Second)
	log.Info("port is still : ", r.GetLocalPort("192.168.13.164:22"))
	r.RemoveForward("192.168.13.164:22")
	time.Sleep(100 * time.Second)
}
