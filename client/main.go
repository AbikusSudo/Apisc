package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
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

type credentialFunc func(string) (string, string, string, error)

func vkCredentials(link string) (string, string, string, error) {
	request := func(payload, endpoint string) (map[string]interface{}, error) {
		transport := &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     60 * time.Second,
		}
		httpClient := &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}
		defer httpClient.CloseIdleConnections()

		req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, err
		}
		return data, nil
	}

	step1 := "client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487"
	token1Data, err := request(step1, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", fmt.Errorf("step1: %w", err)
	}
	token1 := token1Data["data"].(map[string]interface{})["access_token"].(string)

	step2 := fmt.Sprintf("access_token=%s", token1)
	token2Data, err := request(step2, "https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=6287487")
	if err != nil {
		return "", "", "", fmt.Errorf("step2: %w", err)
	}
	token2 := token2Data["response"].(map[string]interface{})["payload"].(string)

	step3 := fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", token2)
	token3Data, err := request(step3, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", fmt.Errorf("step3: %w", err)
	}
	token3 := token3Data["data"].(map[string]interface{})["access_token"].(string)

	step4 := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=guest&access_token=%s", link, token3)
	token4Data, err := request(step4, "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return "", "", "", fmt.Errorf("step4: %w", err)
	}
	token4 := token4Data["response"].(map[string]interface{})["token"].(string)

	step5 := fmt.Sprintf("session_data={\"version\":2,\"device_id\":\"%s\",\"client_version\":1.1,\"client_type\":\"SDK_JS\"}&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", uuid.New().String())
	token5Data, err := request(step5, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", fmt.Errorf("step5: %w", err)
	}
	token5 := token5Data["session_key"].(string)

	step6 := fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token4, token5)
	finalData, err := request(step6, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", fmt.Errorf("step6: %w", err)
	}

	server := finalData["turn_server"].(map[string]interface{})
	username := server["username"].(string)
	password := server["credential"].(string)
	rawURL := server["urls"].([]interface{})[0].(string)
	cleanURL := strings.Split(rawURL, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(cleanURL, "turn:"), "turns:")

	return username, password, address, nil
}

func yandexCredentials(link string) (string, string, string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        30,
			MaxIdleConnsPerHost: 30,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	defer client.CloseIdleConnections()

	conferenceURL := fmt.Sprintf("https://cloud-api.yandex.ru/telemost_front/v2/telemost/conferences/https%%3A%%2F%%2Ftelemost.yandex.ru%%2Fj%%2F%s/connection?next_gen_media_platform_allowed=false", link)
	req, err := http.NewRequest("GET", conferenceURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Client-Instance-Id", uuid.New().String())
	req.Header.Set("Referer", "https://telemost.yandex.ru/")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	var conference struct {
		PeerID    string `json:"peer_id"`
		RoomID    string `json:"room_id"`
		AuthToken string `json:"credentials"`
		Server    struct {
			MediaURL string `json:"media_server_url"`
		} `json:"client_configuration"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&conference); err != nil {
		return "", "", "", fmt.Errorf("decode conference: %w", err)
	}

	wsHeaders := http.Header{}
	wsHeaders.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	wsHeaders.Set("Origin", "https://telemost.yandex.ru")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, conference.Server.MediaURL, wsHeaders)
	if err != nil {
		return "", "", "", fmt.Errorf("websocket connect: %w", err)
	}
	defer conn.Close()

	hello := map[string]interface{}{
		"uid": uuid.New().String(),
		"hello": map[string]interface{}{
			"participantMeta": map[string]interface{}{
				"name":        "Guest",
				"role":        "SPEAKER",
				"sendAudio":   false,
				"sendVideo":   false,
			},
			"participantId": conference.PeerID,
			"roomId":        conference.RoomID,
			"credentials":   conference.AuthToken,
			"serviceName":   "telemost",
			"sdkInfo": map[string]interface{}{
				"implementation": "browser",
				"version":        "5.15.0",
				"userAgent":      "Mozilla/5.0",
				"hwConcurrency":  4,
			},
			"sdkInitializationId": uuid.New().String(),
			"capabilitiesOffer": map[string]interface{}{
				"offerAnswerMode":        []string{"SEPARATE"},
				"initialSubscriberOffer": []string{"ON_HELLO"},
				"simulcastMode":          []string{"DISABLED"},
			},
		},
	}
	if err := conn.WriteJSON(hello); err != nil {
		return "", "", "", fmt.Errorf("send hello: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return "", "", "", fmt.Errorf("read message: %w", err)
		}

		var response struct {
			ServerHello struct {
				RTCConfig struct {
					IceServers []struct {
						Urls       []string `json:"urls"`
						Username   string   `json:"username"`
						Credential string   `json:"credential"`
					} `json:"iceServers"`
				} `json:"rtcConfiguration"`
			} `json:"serverHello"`
		}
		if err := json.Unmarshal(msg, &response); err != nil {
			continue
		}

		for _, server := range response.ServerHello.RTCConfig.IceServers {
			for _, url := range server.Urls {
				if strings.HasPrefix(url, "turn:") && !strings.Contains(url, "transport=tcp") {
					clean := strings.Split(url, "?")[0]
					address := strings.TrimPrefix(clean, "turn:")
					return server.Username, server.Credential, address, nil
				}
			}
		}
	}
}

func establishDTLS(ctx context.Context, baseConn net.PacketConn, target *net.UDPAddr) (net.Conn, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}

	config := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}

	dtlsCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	dtlsConn, err := dtls.Client(baseConn, target, config)
	if err != nil {
		return nil, err
	}
	if err := dtlsConn.HandshakeContext(dtlsCtx); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func handleDTLSSession(ctx context.Context, target *net.UDPAddr, listener net.PacketConn, outputChan chan<- net.PacketConn, readyChan chan<- struct{}, errChan chan<- error) {
	defer func() { errChan <- nil }()

	dtlsCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsCtx.Done():
				return
			case outputChan <- conn2:
			}
		}
	}()

	dtlsConn, err := establishDTLS(dtlsCtx, conn1, target)
	if err != nil {
		errChan <- fmt.Errorf("dtls handshake: %w", err)
		return
	}
	defer dtlsConn.Close()

	if readyChan != nil {
		select {
		case readyChan <- struct{}{}:
		case <-dtlsCtx.Done():
		}
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	context.AfterFunc(dtlsCtx, func() {
		listener.SetDeadline(time.Now())
		dtlsConn.SetDeadline(time.Now())
	})

	var remoteAddr atomic.Value

	go func() {
		defer wg.Done()
		defer cancel()
		buffer := make([]byte, 1500)
		for {
			select {
			case <-dtlsCtx.Done():
				return
			default:
			}
			n, addr, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			remoteAddr.Store(addr)
			if _, err := dtlsConn.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		buffer := make([]byte, 1500)
		for {
			select {
			case <-dtlsCtx.Done():
				return
			default:
			}
			n, err := dtlsConn.Read(buffer)
			if err != nil {
				return
			}
			addr := remoteAddr.Load().(net.Addr)
			if _, err := listener.WriteTo(buffer[:n], addr); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	listener.SetDeadline(time.Time{})
	dtlsConn.SetDeadline(time.Time{})
}

type linkedUDPConn struct{ *net.UDPConn }

func (c *linkedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type serverConfig struct {
	hostOverride string
	portOverride string
	meetingLink  string
	useUDP       bool
	credentialFn credentialFunc
}

func handleTURNSession(ctx context.Context, config *serverConfig, target *net.UDPAddr, inboundConn net.PacketConn, errChan chan<- error) {
	defer func() { errChan <- nil }()

	username, password, serverAddr, err := config.credentialFn(config.meetingLink)
	if err != nil {
		errChan <- fmt.Errorf("credentials: %w", err)
		return
	}

	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		errChan <- fmt.Errorf("parse address: %w", err)
		return
	}
	if config.hostOverride != "" {
		host = config.hostOverride
	}
	if config.portOverride != "" {
		port = config.portOverride
	}
	finalAddr := net.JoinHostPort(host, port)

	udpAddr, err := net.ResolveUDPAddr("udp", finalAddr)
	if err != nil {
		errChan <- fmt.Errorf("resolve turn: %w", err)
		return
	}

	var transportConn net.PacketConn
	if config.useUDP {
		udpConn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			errChan <- fmt.Errorf("udp dial: %w", err)
			return
		}
		defer udpConn.Close()
		transportConn = &linkedUDPConn{udpConn}
	} else {
		tcpConn, err := net.Dial("tcp", finalAddr)
		if err != nil {
			errChan <- fmt.Errorf("tcp dial: %w", err)
			return
		}
		defer tcpConn.Close()
		transportConn = turn.NewSTUNConn(tcpConn)
	}

	var addrFamily turn.RequestedAddressFamily
	if target.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	turnClient, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         finalAddr,
		TURNServerAddr:         finalAddr,
		Conn:                   transportConn,
		Username:               username,
		Password:               password,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		errChan <- fmt.Errorf("turn client: %w", err)
		return
	}
	defer turnClient.Close()

	if err := turnClient.Listen(); err != nil {
		errChan <- fmt.Errorf("turn listen: %w", err)
		return
	}

	relayConn, err := turnClient.Allocate()
	if err != nil {
		errChan <- fmt.Errorf("allocate relay: %w", err)
		return
	}
	defer relayConn.Close()

	turnCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg := &sync.WaitGroup{}
	wg.Add(2)

	context.AfterFunc(turnCtx, func() {
		relayConn.SetDeadline(time.Now())
		inboundConn.SetDeadline(time.Now())
	})

	var relayAddr atomic.Value

	go func() {
		defer wg.Done()
		defer cancel()
		buffer := make([]byte, 1500)
		for {
			select {
			case <-turnCtx.Done():
				return
			default:
			}
			n, addr, err := inboundConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			relayAddr.Store(addr)
			if _, err := relayConn.WriteTo(buffer[:n], target); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		buffer := make([]byte, 1500)
		for {
			select {
			case <-turnCtx.Done():
				return
			default:
			}
			n, _, err := relayConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			addr := relayAddr.Load().(net.Addr)
			if _, err := inboundConn.WriteTo(buffer[:n], addr); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	relayConn.SetDeadline(time.Time{})
	inboundConn.SetDeadline(time.Time{})
}

func dtlsManager(ctx context.Context, target *net.UDPAddr, inputChan <-chan net.PacketConn, outputChan chan<- net.PacketConn, readyChan chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case listener := <-inputChan:
			errChan := make(chan error)
			go handleDTLSSession(ctx, target, listener, outputChan, readyChan, errChan)
			if err := <-errChan; err != nil {
				log.Printf("DTLS session error: %v", err)
			}
		}
	}
}

func turnManager(ctx context.Context, config *serverConfig, target *net.UDPAddr, connChan <-chan net.PacketConn, interval <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn := <-connChan:
			select {
			case <-interval:
				errChan := make(chan error)
				go handleTURNSession(ctx, config, target, conn, errChan)
				if err := <-errChan; err != nil {
					log.Printf("TURN session error: %v", err)
				}
			default:
			}
		}
	}
}

func main() {
	fmt.Print(banner)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		stop()
		<-time.After(3 * time.Second)
		os.Exit(0)
	}()

	turnHost := flag.String("turn", "", "TURN server host override")
	turnPort := flag.String("port", "", "TURN server port override")
	listenAddr := flag.String("listen", "127.0.0.1:9000", "Local bind address")
	vkLink := flag.String("vk", "", "VK call join link")
	yaLink := flag.String("yandex", "", "Yandex telemost join link")
	peerAddr := flag.String("peer", "", "Target server address")
	connCount := flag.Int("connections", 0, "Number of connections")
	useUDP := flag.Bool("udp", false, "Use UDP transport")
	noDTLS := flag.Bool("no-dtls", false, "Disable DTLS encryption")
	flag.Parse()

	if *peerAddr == "" {
		log.Fatal("Target address required")
	}
	target, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		log.Fatalf("Invalid target: %v", err)
	}

	if (*vkLink == "") == (*yaLink == "") {
		log.Fatal("Specify either VK or Yandex link")
	}

	var link string
	var credFn credentialFunc
	if *vkLink != "" {
		parts := strings.Split(*vkLink, "join/")
		link = parts[len(parts)-1]
		credFn = vkCredentials
		if *connCount <= 0 {
			*connCount = 16
		}
	} else {
		parts := strings.Split(*yaLink, "j/")
		link = parts[len(parts)-1]
		credFn = yandexCredentials
		if *connCount <= 0 {
			*connCount = 1
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	config := &serverConfig{
		hostOverride: *turnHost,
		portOverride: *turnPort,
		meetingLink:  link,
		useUDP:       *useUDP,
		credentialFn: credFn,
	}

	listener, err := net.ListenPacket("udp", *listenAddr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	context.AfterFunc(ctx, func() {
		listener.Close()
	})

	listenChan := make(chan net.PacketConn)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenChan <- listener:
			}
		}
	}()

	wg := &sync.WaitGroup{}
	ticker := time.Tick(100 * time.Millisecond)

	if *noDTLS {
		for i := 0; i < *connCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				turnManager(ctx, config, target, listenChan, ticker)
			}()
		}
	} else {
		readyChan := make(chan struct{})
		dtlsChan := make(chan net.PacketConn)

		wg.Add(2)
		go func() {
			defer wg.Done()
			dtlsManager(ctx, target, listenChan, dtlsChan, readyChan)
		}()
		go func() {
			defer wg.Done()
			turnManager(ctx, config, target, dtlsChan, ticker)
		}()

		select {
		case <-readyChan:
		case <-ctx.Done():
		}

		for i := 0; i < *connCount-1; i++ {
			dtlsChan := make(chan net.PacketConn)
			wg.Add(2)
			go func() {
				defer wg.Done()
				dtlsManager(ctx, target, listenChan, dtlsChan, nil)
			}()
			go func() {
				defer wg.Done()
				turnManager(ctx, config, target, dtlsChan, ticker)
			}()
		}
	}

	wg.Wait()
}