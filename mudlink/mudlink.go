package mudlink

import (
	"crypto/tls"
	"errors"
	"net"
	"time"
)

type MudCapabilities struct {
	Protocol          string
	Address           net.Addr
	Tls               bool
	Width             uint16
	Height            uint16
	Ansi              bool
	Xterm256          bool
	Truecolor         bool
	Gmcp              bool
	Msdp              bool
	Mssp              bool
	Mccp2             bool
	Mccp3             bool
	Ttype             bool
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
	Client_name       string
	Client_version    string
	Terminal_type     string
	Keepalive         bool
	Mtts              bool
}

type MudConnection interface {
	Ready() bool
	Start()
	Close()
	Name() string
	Capabilities() *MudCapabilities
	SendStatus(data map[string]string)
	SendLine(data string)
	SendText(data string)
	SendPrompt(data string)
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
	n := c.Name()
	m.Connections[n] = c
	go c.Start()
}

func (m *MudLinkManager) GenerateConnId(prefix string, length uint) string {
	t := time.Now().String()
	name := prefix + "_" + t
	return name
}

func (m *MudLinkManager) init() {
	m.listeners = make(map[string]MudListener)
	m.Connections = make(map[string]MudConnection)
}

func (m *MudLinkManager) Start() {
	for _, val := range m.listeners {
		val.Start()
	}
}

func NewMudLinkManager(h MudConnectionHandler) (*MudLinkManager, error) {
	if h == nil {
		return nil, errors.New("MudLinkManager must have a valid MudConnectionHandler")
	}
	var out MudLinkManager
	out.init()
	out.Handler = h
	h.SetManager(&out)
	return &out, nil
}
