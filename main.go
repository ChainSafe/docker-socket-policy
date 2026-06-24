package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ChainSafe/docker-socket-policy/internal/audit"
	"github.com/ChainSafe/docker-socket-policy/internal/middleware"
	"github.com/ChainSafe/docker-socket-policy/internal/policy"
	"github.com/ChainSafe/docker-socket-policy/internal/proxy"
)

var Version = "dev"

func main() {
	listenSocket := flag.String("listen-socket", "/var/run/docker-socket-policy.sock",
		"Unix socket to listen on (or fd://3 for systemd socket activation)")
	listenTCP := flag.String("listen-tcp", "127.0.0.1:2375",
		"TCP address to listen on")
	dockerHost := flag.String("docker-host", "/var/run/docker.sock",
		"Docker daemon socket path")
	configDir := flag.String("config-dir", "/etc/docker-socket-policy/services",
		"Policy config directory")
	logFile := flag.String("log-file", "/var/log/docker-socket-policy.log",
		"Audit log file (JSON)")
	readonly := flag.Bool("readonly", false,
		"Enable read-only mode (deny all POST/PUT/DELETE)")
	flag.Parse()

	auditLog, err := audit.NewLogger(*logFile)
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}
	defer auditLog.Close()

	policyManager, err := policy.NewManager(*configDir)
	if err != nil {
		log.Fatalf("Failed to initialize policy manager: %v", err)
	}
	log.Printf("Loaded %d policies from %s", len(policyManager.List()), *configDir)

	router := proxy.NewRouter(policyManager)
	chain := middleware.NewChain(*readonly)
	transport := proxy.NewTransport(*dockerHost)

	handler := proxy.NewHandler(router, chain, auditLog, transport)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go startSocketListener(*listenSocket, handler, sigChan)

	startTCPListener(*listenTCP, handler, sigChan)
}

func startSocketListener(addr string, handler http.Handler, sigChan chan os.Signal) {
	var listener net.Listener
	var err error

	if addr == "fd://3" {
		listener, err = net.FileListener(os.NewFile(3, "socket"))
		if err != nil {
			log.Fatalf("Failed to create listener from fd://3: %v", err)
		}
	} else {
		_ = os.Remove(addr)
		listener, err = net.Listen("unix", addr)
		if err != nil {
			log.Fatalf("Failed to listen on unix socket %s: %v", addr, err)
		}
	}
	defer listener.Close()

	log.Printf("Listening on Unix socket: %s", addr)
	server := &http.Server{Handler: handler}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Unix socket server error: %v", err)
		}
	}()

	<-sigChan
	log.Println("Shutting down Unix socket listener...")
	server.Close()
}

func startTCPListener(addr string, handler http.Handler, sigChan chan os.Signal) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on TCP %s: %v", addr, err)
	}
	defer listener.Close()

	log.Printf("Listening on TCP: %s", addr)
	server := &http.Server{Handler: handler}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("TCP server error: %v", err)
		}
	}()

	<-sigChan
	log.Println("Shutting down TCP listener...")
	server.Close()
}
