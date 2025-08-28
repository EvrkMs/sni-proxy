package websocket

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type WebSocketServer struct {
	logger  *zap.Logger
	logChan chan string
	clients map[*websocket.Conn]bool
	mu      sync.RWMutex
	done    chan struct{}
}

func NewWebSocketServer(logger *zap.Logger) *WebSocketServer {
	return &WebSocketServer{
		logger:  logger,
		logChan: make(chan string, 1000),
		clients: make(map[*websocket.Conn]bool),
		done:    make(chan struct{}),
	}
}

func (s *WebSocketServer) Start(ctx context.Context, ln net.Listener) {
	s.logger.Info("[WS] server started", zap.String("addr", ln.Addr().String()))
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ws" {
				s.handleWebSocket(w, r)
			} else {
				http.NotFound(w, r)
			}
		}),
	}
	go s.broadcastLogs()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve(ln)
	}()

	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("[WS] server error", zap.Error(err))
		}
	case <-ctx.Done():
		s.logger.Info("[WS] shutting down")
		s.Close()
		if err := server.Shutdown(context.Background()); err != nil {
			s.logger.Error("[WS] shutdown error", zap.Error(err))
		}
	}
}

func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("[WS] upgrade error", zap.Error(err))
		return
	}
	s.mu.Lock()
	s.clients[conn] = true
	count := len(s.clients)
	s.mu.Unlock()
	s.logger.Info("[WS] client connected", zap.String("addr", r.RemoteAddr), zap.Int("clients", count))

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			s.mu.Lock()
			delete(s.clients, conn)
			count := len(s.clients)
			s.mu.Unlock()
			conn.Close()
			s.logger.Info("[WS] client disconnected", zap.String("addr", r.RemoteAddr), zap.Int("clients", count))
			break
		}
	}
}

func (s *WebSocketServer) broadcastLogs() {
	for logMsg := range s.logChan {
		s.mu.RLock()
		conns := make([]*websocket.Conn, 0, len(s.clients))
		for c := range s.clients {
			conns = append(conns, c)
		}
		s.mu.RUnlock()

		for _, conn := range conns {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(logMsg)); err != nil {
				s.mu.Lock()
				conn.Close()
				delete(s.clients, conn)
				s.mu.Unlock()
				s.logger.Error("[WS] write error", zap.Error(err))
			}
		}
	}
}

func (s *WebSocketServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.clients {
		conn.Close()
	}
	s.clients = make(map[*websocket.Conn]bool)
	close(s.logChan)
	close(s.done)
}
