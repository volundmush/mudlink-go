package mudlink

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"time"
)

const (
	Telnet    uint8 = 0
	WebSocket       = 1
)

const (
	NoColor   uint8 = 0
	ANSI16          = 1
	XTERM256        = 2
	TRUECOLOR       = 3
)

type MudCapabilities struct {
	ClientID          string
	Protocol          uint8
	Address           net.Addr
	Tls               bool
	Client_name       string
	Client_version    string
	Width             uint16
	Height            uint16
	Color             uint8
	Gmcp              bool
	Msdp              bool
	Mssp              bool
	Mccp2             bool
	Mccp2_active      bool
	Mccp3             bool
	Mccp3_active      bool
	Naws              bool
	Screen_reader     bool
	Linemode          bool
	Force_endline     bool
	Suppress_ga       bool
	Mouse_tracking    bool
	Utf8              bool
	Vt100             bool
	Osc_color_palette bool
	Proxy             bool
	Mnes              bool
	Terminal_type     string
	Keepalive         bool
	Mtts              bool
	Mxp               bool
}

const (
	Pending uint8 = 0
	Running       = 1
	Closed        = 2
)

type MudConnection interface {
	Start()
	Close()
	Capabilities() *MudCapabilities
	SendMSSP(data map[string]string)
	SendLine(data string)
	SendText(data string)
	SendPrompt(data string)
	Status() uint8
	SetManager(m *MudLinkManager)
}

type MudListener interface {
	Start()
	Stop() error
	Addr() net.Addr
	Tls() *tls.Config
	Name() string
	SetManager(*MudLinkManager)
}

type MudConnectionHandler interface {
	OnConnect(c MudConnection)
	OnLine(c MudConnection, line string)
	OnDisconnect(c MudConnection)
	OnUpdate(c MudConnection)
	SetManager(m *MudLinkManager)
}

type MudLinkManager struct {
	listeners   map[string]MudListener
	Connections map[string]MudConnection
	Handler     MudConnectionHandler
	Outchan     chan json.RawMessage
	Inchan      chan json.RawMessage
}

func NewMudLinkManager(h MudConnectionHandler) (*MudLinkManager, error) {
	if h == nil {
		return nil, errors.New("MudLinkManager must have a valid MudConnectionHandler")
	}
	out := new(MudLinkManager)
	out.Handler = h
	out.Handler.SetManager(out)
	out.listeners = make(map[string]MudListener)
	out.Connections = make(map[string]MudConnection)
	return out, nil
}

func (m *MudLinkManager) RegisterListener(l MudListener) (bool, error) {
	n := l.Name()
	if m.listeners[n] != nil {
		return false, errors.New("A Listener is already using this name.")
	}
	m.listeners[n] = l
	l.SetManager(m)
	return true, nil
}

func (m *MudLinkManager) RegisterConnection(c MudConnection) {
	m.Connections[c.Capabilities().ClientID] = c
	go c.Start()
}

func (m *MudLinkManager) GenerateConnId(prefix string, length uint) string {
	return prefix + "_" + time.Now().String()
}

func (m *MudLinkManager) Start() {
	for _, val := range m.listeners {
		val.Start()
	}
}
