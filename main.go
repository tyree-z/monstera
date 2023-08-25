package main

import (
	"flag"
	"log"

	"github.com/tyree-z/monstera/core/server"
)

func main() {
	localMode := flag.Bool("local", false, "Run in local mode with self-signed certificates.")
	flag.Parse()

	go server.StartHTTPUpgradeServer()
	if err := server.StartMainServer(*localMode); err != nil {
		log.Fatal(err)
	}
}
