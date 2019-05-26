package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

var portFlag = flag.String("port", "8888", "Port number to run server on.")

func main() {
	flag.Parse()
	port := *portFlag

	fs := http.FileServer(http.Dir("."))
	ss := SimpleServer(fs)
	http.Handle("/", ss)
	log.Printf("Started server on port %s\n", port)
	log.Fatalln(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func SimpleServer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		log.Printf("[%s]: %s\n", r.RemoteAddr, r.URL)
		h.ServeHTTP(w, r)
		log.Println("Finished - ", r.URL, time.Since(t))
	})
}
