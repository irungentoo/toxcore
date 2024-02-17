// A Go version WebSocket to TCP socket proxy
//
// This is a heavily modified version of this file:
//   https://github.com/novnc/websockify-other/blob/master/golang/websockify.go
//
// Changes include:
// - Fix infinite loop on error.
// - Proper logging.
// - Proper error handling in general.
// - Support both websocket and regular GET requests on /.
//
// Copyright 2022 The TokTok team.
// Copyright 2021 Michael.liu.
// See LICENSE for licensing conditions.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
)

var (
	sourceAddr = flag.String("l", "127.0.0.1:8080", "http service address")
	targetAddr = flag.String("t", "127.0.0.1:5900", "tcp service address")
)

var upgrader = websocket.Upgrader{
	// Should be enough to fit any Tox TCP packets.
	ReadBufferSize:  2048,
	WriteBufferSize: 2048,
	Subprotocols:    []string{"binary"},
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func forwardTCP(wsconn *websocket.Conn, conn net.Conn) {
	var tcpbuffer [2048]byte
	defer wsconn.Close()
	defer conn.Close()
	for {
		n, err := conn.Read(tcpbuffer[0:])
		if err != nil {
			log.Println("TCP READ :", err)
			break
		}
		log.Println("TCP READ :", n, hex.EncodeToString(tcpbuffer[0:n]))

		if err := wsconn.WriteMessage(websocket.BinaryMessage, tcpbuffer[0:n]); err != nil {
			log.Println("WS WRITE :", err)
			break
		}
		log.Println("WS WRITE :", n)
	}
}

func forwardWeb(wsconn *websocket.Conn, conn net.Conn) {
	defer wsconn.Close()
	defer conn.Close()
	for {
		_, buffer, err := wsconn.ReadMessage()
		if err != nil {
			log.Println("WS READ  :", err)
			break
		}
		log.Println("WS READ  :", len(buffer), hex.EncodeToString(buffer))

		m, err := conn.Write(buffer)
		if err != nil {
			log.Println("TCP WRITE:", err)
			break
		}
		log.Println("TCP WRITE:", m)
	}
}

func serveWs(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	vnc, err := net.Dial("tcp", *targetAddr)
	if err != nil {
		log.Println("dial:", err)
		return
	}
	go forwardTCP(ws, vnc)
	go forwardWeb(ws, vnc)

}

func main() {
	flag.Parse()
	log.Println("Starting up websockify endpoint")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			serveWs(w, r)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNotFound)

			fmt.Fprintf(w, "404 Not Found")
		}
	})
	log.Fatal(http.ListenAndServe(*sourceAddr, nil))
}
