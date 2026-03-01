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
// - Write logs in the standard Tox format.
//
// Copyright 2022-2026 The TokTok team.
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
	"os"
	"regexp"
	"strings"

	"github.com/gorilla/websocket"
)

var (
	sourceAddr = flag.String("l", "127.0.0.1:8080", "http service address")
	targetAddr = flag.String("t", "127.0.0.1:5900", "tcp service address")
)

// Should be enough to fit any Tox TCP packets.
const bufferSize = 2048

var upgrader = websocket.Upgrader{
	ReadBufferSize:  bufferSize,
	WriteBufferSize: bufferSize,
	Subprotocols:    []string{"binary"},
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func forwardTCP(wsconn *websocket.Conn, conn net.Conn) {
	var tcpbuffer [bufferSize]byte
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

type logEntry struct {
	time    string
	file    string
	line    string
	message string
}

type logWriter struct{}

// Write implements the io.Writer interface.
//
// This parses the Go log format and outputs it as the standard Tox format.
//
// Go format:
// "15:02:46.433968 websockify.go:106: Starting up websockify endpoint\n"
//
// Standard Tox format:
// "[15:02:46.433 UTC] (websockify) websockify.go:106 : Debug: Starting up websockify endpoint"
func (writer *logWriter) Write(bytes []byte) (int, error) {
	// Parse the Go log format (skipping the last 3 digits of the microseconds).
	re := regexp.MustCompile(`^(\d{2}:\d{2}:\d{2}\.\d{3})\d{3} ([^:]+):(\d+): (.*)$`)
	matches := re.FindStringSubmatch(strings.TrimSuffix(string(bytes), "\n"))
	if len(matches) != 5 {
		// If the log format doesn't match, just print it as is.
		fmt.Fprintf(os.Stderr, "%s (unparsed)", string(bytes))
		return len(bytes), nil
	}

	// Extract the log fields.
	entry := logEntry{
		time:    matches[1],
		file:    matches[2],
		line:    matches[3],
		message: matches[4],
	}

	// Print the Go log format in the standard Tox format to stderr.
	fmt.Fprintf(os.Stderr, "[%s UTC] (websockify) %s:%s : Debug: %s\n", entry.time, entry.file, entry.line, entry.message)

	return len(bytes), nil
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile | log.LUTC | log.Lmicroseconds)
	log.SetOutput(new(logWriter))

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
