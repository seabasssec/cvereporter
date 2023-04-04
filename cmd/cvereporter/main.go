package main

import (
	"log"
	"net/http"

	"github.com/seabasssec/cvereporter/internal/handlers"
)

func main() {

	server := handlers.NewServer()

	log.Println(http.ListenAndServe(":8080", server.Router))
}
