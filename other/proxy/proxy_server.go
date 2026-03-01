package main

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/things-go/go-socks5"
)

const (
	debug      = false
	httpAddr   = ":7080"
	socks5Addr = ":7081"
)

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("opening tunnel to %q", r.Host)
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	log.Printf("responding OK")
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	log.Printf("hijacking HTTP connection")
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	log.Printf("starting data transfer")
	go transfer(">", destConn, clientConn)
	go transfer("<", clientConn, destConn)
}

func transfer(direction string, destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	var buf [2048]byte
	for {
		n, err := source.Read(buf[:])
		if err != nil {
			log.Printf("error: %s", err)
			break
		}
		if debug {
			log.Printf("%s %02x", direction, hex.EncodeToString(buf[:n]))
		}
		destination.Write(buf[:n])
	}
}

func main() {
	log.Printf("starting HTTP proxy server on %s", httpAddr)
	httpServer := &http.Server{
		Addr: httpAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				panic("invalid method, only CONNECT is allowed")
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Printf("starting SOCKS5 proxy server on %s", socks5Addr)
	socks5Server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	go socks5Server.ListenAndServe("tcp", socks5Addr)
	log.Fatal(httpServer.ListenAndServe())
}
