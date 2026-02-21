package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

const banner = `
╔══════════════════════════════════════════════════════════╗
║            █████╗ ██████╗ ██╗███████╗ ██████╗            ║
║            ██╔══██╗██╔══██╗██║██╔════╝██╔════╝           ║
║            ███████║██████╔╝██║███████╗██║                ║
║            ██╔══██║██╔═══╝ ██║╚════██║██║                ║
║            ██║  ██║██║     ██║███████║╚██████╗           ║
║            ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝           ║
║                                                          ║
║               Version: 1.1.1 | Build: 2026               ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
`

type sessionHandler struct {
	clientConn  net.Conn
	upstream    string
	parentCtx   context.Context
}

func initSession(conn net.Conn, upstreamAddr string, ctx context.Context) {
	defer conn.Close()

	dtlsSession, ok := conn.(*dtls.Conn)
	if !ok {
		log.Printf("Connection type mismatch from %v", conn.RemoteAddr())
		return
	}

	log.Printf("Session initiated: %v", conn.RemoteAddr())
	handshakeCtx, cancelHS := context.WithTimeout(ctx, 20*time.Second)
	defer cancelHS()

	if hsErr := dtlsSession.HandshakeContext(handshakeCtx); hsErr != nil {
		log.Printf("Security handshake failed: %v", hsErr)
		return
	}
	log.Printf("Secure channel established: %v", conn.RemoteAddr())

	upstreamConn, dialErr := net.Dial("udp", upstreamAddr)
	if dialErr != nil {
		log.Printf("Upstream connection failed: %v", dialErr)
		return
	}
	defer upstreamConn.Close()

	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()

	var workers sync.WaitGroup
	workers.Add(2)

	transferData := func(source, destination net.Conn, label string) {
		defer workers.Done()
		defer stopSession()
		dataBuffer := make([]byte, 1492)
		
		for {
			select {
			case <-sessionCtx.Done():
				return
			default:
			}
			
			source.SetReadDeadline(time.Now().Add(25 * time.Minute))
			bytesRead, readError := source.Read(dataBuffer)
			if readError != nil {
				log.Printf("Data read error (%s): %v", label, readError)
				return
			}
			
			destination.SetWriteDeadline(time.Now().Add(25 * time.Minute))
			if _, writeError := destination.Write(dataBuffer[:bytesRead]); writeError != nil {
				log.Printf("Data write error (%s): %v", label, writeError)
				return
			}
		}
	}

	go transferData(conn, upstreamConn, "inbound")
	go transferData(upstreamConn, conn, "outbound")

	workers.Wait()
	log.Printf("Session terminated: %v", conn.RemoteAddr())
}

func main() {
	fmt.Print(banner)

	localInterface := flag.String("interface", "0.0.0.0:56000", "Listening interface")
	destinationServer := flag.String("destination", "", "Target server address")
	flag.Parse()

	if *destinationServer == "" {
		log.Fatal("Target server address must be specified")
	}

	mainCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		fmt.Println("\nInitiating graceful shutdown...")
		shutdown()
		<-time.After(3 * time.Second)
		os.Exit(0)
	}()

	listenAddress, resolveErr := net.ResolveUDPAddr("udp", *localInterface)
	if resolveErr != nil {
		log.Fatalf("Address resolution failed: %v", resolveErr)
	}

	securityCert, certErr := selfsign.GenerateSelfSigned()
	if certErr != nil {
		log.Fatalf("Security certificate generation failed: %v", certErr)
	}

	dtlsConfiguration := &dtls.Config{
		Certificates:         []tls.Certificate{securityCert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	listenerInstance, listenErr := dtls.Listen("udp", listenAddress, dtlsConfiguration)
	if listenErr != nil {
		log.Fatalf("Listener initialization failed: %v", listenErr)
	}
	defer listenerInstance.Close()

	context.AfterFunc(mainCtx, func() {
		listenerInstance.Close()
	})

	fmt.Printf("Proxy operational: %s → %s\n", *localInterface, *destinationServer)

	var activeConnections sync.WaitGroup
	accepting := true

	for accepting {
		select {
		case <-mainCtx.Done():
			accepting = false
			continue
		default:
		}

		incomingConnection, acceptErr := listenerInstance.Accept()
		if acceptErr != nil {
			if acceptErr.Error() != "listener closed" {
				log.Printf("Connection acceptance error: %v", acceptErr)
			}
			continue
		}

		activeConnections.Add(1)
		go func(client net.Conn) {
			defer activeConnections.Done()
			initSession(client, *destinationServer, mainCtx)
		}(incomingConnection)
	}

	activeConnections.Wait()
	fmt.Println("Server shutdown completed")
}