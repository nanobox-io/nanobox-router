package main

import "github.com/nanobox-tools/router"
import "github.com/jcelliott/lumber"
import "time"
func main() {
  log := lumber.NewConsoleLogger(lumber.INFO)

  r := router.New(80, log)
  r.SetTarget("http://drawception.com")
  r.Start()
  log.Info("start")
  time.Sleep(10*time.Second)
  log.Info("change")
  r.SetTarget("http://macmagazine.com.br")
  time.Sleep(100*time.Second)
  log.Info("why")
}