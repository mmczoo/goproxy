package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/mmczoo/goproxy"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	conf := flag.String("f", "config.json", "config file")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServerWithPx(*conf)
	proxy.Verbose = *verbose
	log.Fatal(http.ListenAndServe(*addr, proxy))
}
