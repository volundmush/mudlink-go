package telnet

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/Masterminds/semver/v3"
	"github.com/volundmush/mudlink-go/mudlink"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var XTERM_CLIENTS = map[string]bool{"ATLANTIS": true, "CMUD": true, "KILDCLIENT": true, "MUDLET": true, "MUSHCLIENT": true,
	"PUTTY": true, "BEIP": true, "POTATO": true, "TINYFUGUE": true}

type OpCode byte

const (
	NUL        OpCode = 0
	BEL               = 7
	CR                = 13
	LF                = 10
	SGA               = 3
	TELOPT_EOR        = 25
	NAWS              = 31
	LINEMODE          = 34
	EOR               = 239
	SE                = 240
	NOP               = 241
	GA                = 249
	SB                = 250
	WILL              = 251
	WONT              = 252
	DO                = 253
	DONT              = 254
	IAC               = 255

	// MNES Mud New-Environ Standard
	MNES = 39

	// MXP Mud eXtension Protocol
	MXP = 91

	// MSSP Mud Server Status Protocol
	MSSP = 70

	// MCCP2 MCCP - Mud Client Compression Protocol
	MCCP2 = 86
	MCCP3 = 87

	// GMCP Generic Mud Communication Protocol
	GMCP = 201

	// MSDP Mud Server Data Protocol
	MSDP = 69

	// TTYPE Terminal Type
	TTYPE = 24
)

type OpHandler interface {
	OpCode() byte
	StartWill() bool
	StartDo() bool
	SupportLocal() bool
	SupportRemote() bool
	Init(t *TelnetMudConnection)
	RegisterHandshakes(t *TelnetMudConnection)
	OnLocalEnable(t *TelnetMudConnection)
	OnRemoteEnable(t *TelnetMudConnection)
	OnLocalDisable(t *TelnetMudConnection)
	OnRemoteDisable(t *TelnetMudConnection)
	SubNegotiate(t *TelnetMudConnection, data []byte)
}

type DefaultOpHandler struct{}

func (h *DefaultOpHandler) OpCode() byte                                     { return 0 }
func (h *DefaultOpHandler) StartWill() bool                                  { return false }
func (h *DefaultOpHandler) StartDo() bool                                    { return false }
func (h *DefaultOpHandler) SupportLocal() bool                               { return false }
func (h *DefaultOpHandler) SupportRemote() bool                              { return false }
func (h *DefaultOpHandler) Init(t *TelnetMudConnection)                      {}
func (h *DefaultOpHandler) OnLocalEnable(t *TelnetMudConnection)             {}
func (h *DefaultOpHandler) OnRemoteEnable(t *TelnetMudConnection)            {}
func (h *DefaultOpHandler) OnLocalDisable(t *TelnetMudConnection)            {}
func (h *DefaultOpHandler) OnRemoteDisable(t *TelnetMudConnection)           {}
func (h *DefaultOpHandler) SubNegotiate(t *TelnetMudConnection, data []byte) {}
func (h *DefaultOpHandler) RegisterHandshakes(t *TelnetMudConnection)        {}

type NAWSHandler struct {
	DefaultOpHandler
}

func (h *NAWSHandler) OpCode() byte        { return NAWS }
func (h *NAWSHandler) StartDo() bool       { return true }
func (h *NAWSHandler) SupportRemote() bool { return true }
func (h *NAWSHandler) SubNegotiate(t *TelnetMudConnection, data []byte) {
	if len(data) < 4 {
		return
	}
	t.capabilities.Width = binary.BigEndian.Uint16(data[:2])
	t.capabilities.Height = binary.BigEndian.Uint16(data[2:2])
	if t.ready {
		t.OnUpdate()
	}
}

func (h *NAWSHandler) OnRemoteEnable(t *TelnetMudConnection) {
	t.capabilities.Naws = true
	if t.ready {
		t.OnUpdate()
	}
}

func (h *NAWSHandler) OnRemoteDisable(t *TelnetMudConnection) {
	t.capabilities.Naws = false
	if t.ready {
		t.OnUpdate()
	}
}

func (h *NAWSHandler) RegisterHandshakes(t *TelnetMudConnection) {
	t.hs.remote[NAWS] = true
}

type SGAHandler struct {
	DefaultOpHandler
}

func (h *SGAHandler) OpCode() byte       { return SGA }
func (h *SGAHandler) StartWill() bool    { return true }
func (h *SGAHandler) SupportLocal() bool { return true }
func (h *SGAHandler) OnLocalEnable(t *TelnetMudConnection) {
	t.capabilities.Suppress_ga = true
	if t.ready {
		t.OnUpdate()
	}
}
func (h *SGAHandler) OnLocalDisable(t *TelnetMudConnection) {
	t.capabilities.Suppress_ga = false
	if t.ready {
		t.OnUpdate()
	}
}

type MSSPHandler struct {
	DefaultOpHandler
}

func (h *MSSPHandler) OpCode() byte       { return MSSP }
func (h *MSSPHandler) StartWill() bool    { return true }
func (h *MSSPHandler) SupportLocal() bool { return true }
func (h *MSSPHandler) OnLocalEnable(t *TelnetMudConnection) {
	t.capabilities.Mssp = true
	if t.ready {
		t.OnUpdate()
	}
}

func (h *MSSPHandler) OnLocalDisable(t *TelnetMudConnection) {
	t.capabilities.Mssp = false
	if t.ready {
		t.OnUpdate()
	}
}

type LinemodeHandler struct {
	DefaultOpHandler
}

func (h *LinemodeHandler) OpCode() byte        { return LINEMODE }
func (h *LinemodeHandler) StartDo() bool       { return true }
func (h *LinemodeHandler) SupportRemote() bool { return true }
func (h *LinemodeHandler) OnRemoteEnable(t *TelnetMudConnection) {
	t.capabilities.Linemode = true
	if t.ready {
		t.OnUpdate()
	}
}

func (h *LinemodeHandler) OnRemoteDisable(t *TelnetMudConnection) {
	t.capabilities.Linemode = false
	if t.ready {
		t.OnUpdate()
	}
}

type TTYPEHandler struct {
	DefaultOpHandler
	previous []byte
	state    uint8
}

func (h *TTYPEHandler) OpCode() byte        { return TTYPE }
func (h *TTYPEHandler) StartDo() bool       { return true }
func (h *TTYPEHandler) SupportRemote() bool { return true }
func (h *TTYPEHandler) RegisterHandshakes(t *TelnetMudConnection) {
	t.hs.remote[TTYPE] = true
	t.hs.special[0] = true
	t.hs.special[1] = true
	t.hs.special[2] = true
}

func (h *TTYPEHandler) OnRemoteEnable(t *TelnetMudConnection) {
	t.outbox <- &OutMessage{data: []byte{IAC, SB, TTYPE, 1, IAC, SE}}
}

func (h *TTYPEHandler) SubNegotiate(t *TelnetMudConnection, data []byte) {
	if h.previous == nil {
		h.previous = make([]byte, 0)
		h.state = 0
	}

	if bytes.Compare(h.previous, data) == 0 {
		// We're not going to learn anything new by asking this again.
		t.hs.special = make(map[byte]bool)
		if !t.ready {
			t.CheckReady()
		}
		return
	}

	h.previous = make([]byte, 0)
	copy(data, h.previous)

	if data[0] != 0 {
		// this is malformed data. discarding.
		return
	}

	msg := data[1:]
	if len(msg) == 0 {
		// no message to do anything with.
		return
	}

	info := string(msg)
	fmt.Println("TTYPE Info ", h.state, " IS: ", info)

	switch h.state {
	case 0:
		h.receive_stage_0(t, info)
		h.state = 1
		h.OnRemoteEnable(t)
		delete(t.hs.special, 0)
	case 1:
		h.receive_stage_1(t, info)
		h.state = 2
		h.OnRemoteEnable(t)
		delete(t.hs.special, 1)
	case 2:
		h.receive_stage_2(t, info)
		h.state = 3
		delete(t.hs.special, 2)
	}
	if !t.ready {
		t.CheckReady()
	}

	if t.ready {
		t.OnUpdate()
	}
}

func (h *TTYPEHandler) receive_stage_0(t *TelnetMudConnection, info string) {
	client_name := strings.ToUpper(info)
	client_ver := ""
	if strings.Contains(client_name, " ") {
		split := strings.SplitN(client_name, " ", 1)
		client_name, client_ver = split[0], split[1]
	}
	t.capabilities.Client_name = client_name
	t.capabilities.Client_version = client_ver

	ver, canver := semver.NewVersion(client_ver)

	if strings.HasPrefix(client_name, "MUDLET") {
		if canver != nil {
			constraint, _ := semver.NewConstraint(">= 1.1")
			if constraint != nil {
				if constraint.Check(ver) {
					t.capabilities.Force_endline = false
				}
			}
		}
	}

	if strings.HasPrefix(client_name, "TINTIN++") {
		t.capabilities.Force_endline = true
	}

	if strings.HasPrefix(client_name, "XTERM") || strings.HasSuffix(client_name, "-256COLOR") || XTERM_CLIENTS[client_name] {
		t.capabilities.Xterm256 = true
	}

	t.capabilities.Ansi = true

}

func (h *TTYPEHandler) receive_stage_1(t *TelnetMudConnection, info string) {
	tupper := strings.ToUpper(info)
	xterm := (strings.HasSuffix(tupper, "-256COLOR") || strings.HasSuffix(tupper, "XTERM")) && !strings.HasSuffix(tupper, "-COLOR")

	if xterm {
		t.capabilities.Ansi = true
		t.capabilities.Xterm256 = true
	}
	t.capabilities.Terminal_type = tupper
}

func (h *TTYPEHandler) receive_stage_2(t *TelnetMudConnection, info string) {
	data := strings.ToUpper(info)
	if !strings.HasPrefix(data, "MTTS") {
		return
	}
	mask, err := strconv.ParseUint(data[5:], 10, 8)
	if err != nil {
		return
	}

	if (mask & 128) == 128 {
		t.capabilities.Proxy = true
	}

	if (mask & 64) == 64 {
		t.capabilities.Screen_reader = true
	}

	if (mask & 32) == 32 {
		t.capabilities.Osc_color_palette = true
	}

	if (mask & 16) == 16 {
		t.capabilities.Mouse_tracking = true
	}

	if (mask & 8) == 8 {
		t.capabilities.Xterm256 = true
	}

	if (mask & 4) == 4 {
		t.capabilities.Utf8 = true
	}

	if (mask & 2) == 2 {
		t.capabilities.Vt100 = true
	}

	if (mask & 1) == 1 {
		t.capabilities.Ansi = true
	}
}

type OutMessage struct {
	close bool
	mccp2 bool
	data  []byte
}

type OpPerspective struct {
	enabled     bool
	negotiating bool
	asked       bool
	answered    bool
}

type OpState struct {
	local  OpPerspective
	remote OpPerspective
}

type HandShakes struct {
	local   map[byte]bool
	remote  map[byte]bool
	special map[byte]bool
}

func (h *HandShakes) Init() {
	h.local = make(map[byte]bool)
	h.remote = make(map[byte]bool)
	h.special = make(map[byte]bool)
}

func (h *HandShakes) IsEmpty() bool {
	return (len(h.local) + len(h.remote) + len(h.special)) == 0
}

func (h *HandShakes) Clear() {
	h.Init()
}

func (h *HandShakes) OnLocal(t *TelnetMudConnection, b byte) {
	delete(h.local, b)
	if h.IsEmpty() {
		t.CheckReady()
	}
}

func (h *HandShakes) OnRemote(t *TelnetMudConnection, b byte) {
	delete(h.remote, b)
	if h.IsEmpty() {
		t.CheckReady()
	}
}

func (h *HandShakes) OnSpecial(t *TelnetMudConnection, b byte) {
	delete(h.special, b)
	if h.IsEmpty() {
		t.CheckReady()
	}
}

type TelnetMudConnection struct {
	name         string
	conn         net.Conn
	listener     *TelnetMudListener
	manager      *mudlink.MudLinkManager
	ready        bool
	handlers     map[byte]OpHandler
	states       map[byte]OpState
	hs           HandShakes
	outbox       chan *OutMessage
	inbox        *bytes.Buffer
	cmdbox       *bytes.Buffer
	pending_cmds []string
	running      bool
	capabilities mudlink.MudCapabilities
}

func (t *TelnetMudConnection) Init() {
	t.outbox = make(chan *OutMessage, 20)
	t.handlers = make(map[byte]OpHandler)
	t.states = make(map[byte]OpState)
	t.inbox = bytes.NewBuffer(nil)
	t.cmdbox = bytes.NewBuffer(nil)
	t.pending_cmds = make([]string, 0)
	t.hs.Init()
	t.capabilities.Protocol = "telnet"
	t.capabilities.Address = t.conn.RemoteAddr()
	if t.listener.tls != nil {
		t.capabilities.Tls = true
	}

	t.handlers[NAWS] = &NAWSHandler{}
	t.handlers[TTYPE] = &TTYPEHandler{}
	t.handlers[LINEMODE] = &LinemodeHandler{}
	t.handlers[SGA] = &SGAHandler{}
	t.handlers[MSSP] = &MSSPHandler{}

	for key, _ := range t.handlers {
		t.states[key] = OpState{}
	}

	for _, val := range t.handlers {
		val.Init(t)
		val.RegisterHandshakes(t)
	}

	for k, v := range t.handlers {
		if v.StartDo() {
			t.outbox <- &OutMessage{data: []byte{IAC, DO, k}}
		}
		if v.StartWill() {
			t.outbox <- &OutMessage{data: []byte{IAC, WILL, k}}
		}
	}

}

func (t *TelnetMudConnection) Capabilities() *mudlink.MudCapabilities {
	return &t.capabilities
}

func (t *TelnetMudConnection) Ready() bool {
	return t.ready
}

func (t *TelnetMudConnection) CheckReady() {
	if t.ready {
		return
	}
	if !t.hs.IsEmpty() {
		return
	}
	go t.FinishNegotiation()
}

func (t *TelnetMudConnection) FinishNegotiation() {
	if t.ready {
		return
	}

	t.ready = true
	t.manager.Handler.OnConnect(t)
	// if any commands have built up before negotiation finished, they're sent now.
	for _, c := range t.pending_cmds {
		t.manager.Handler.OnLine(t, c)
	}
}

func (t *TelnetMudConnection) RunTimer() {
	// This should be ample time for Telnet negotiation to complete.
	time.Sleep(time.Millisecond * 300)
	t.FinishNegotiation()
}

func (t *TelnetMudConnection) RunKeepalive() {
	for t.running == true {
		time.Sleep(time.Second * 20)
		if t.capabilities.Keepalive {
			t.outbox <- &OutMessage{data: []byte{IAC, NOP}}
		}
	}
}

func (t *TelnetMudConnection) RunOutBox() {
	for msg := range t.outbox {
		if !t.running {
			// if we're not running anymore, then terminate.
			return
		}
		written, err := t.conn.Write(msg.data)
		if err != nil {
			fmt.Println("Error on: ", t.name, ": ", err.Error())
			fmt.Println("Okay something went wrong here... only wrote: ", written)
		}
	}
}

func (t *TelnetMudConnection) RunInbox() {
	buff := make([]byte, 256)
	for t.running == true {
		count, err := t.conn.Read(buff)
		if count > 0 {
			t.inbox.Write(buff[:count])
			t.ParseTelnet()
		}
		if err == io.EOF {
			t.running = false
			close(t.outbox)
			t.manager.Handler.OnDisconnect(t)
		}
	}
}

func (t *TelnetMudConnection) ParseTelnet() {
	for t.inbox.Len() > 0 {
		data := t.inbox.Bytes()

		if data[0] == IAC {
			if t.inbox.Len() < 2 {
				// There is nothing more we can do with only 1 byte as an IAC.
				return
			}

			// WILL, WONT, DO, or DONT as the second byte means this is a negotiation.
			if data[1] == WILL || data[1] == WONT || data[1] == DO || data[1] == DONT {
				if t.inbox.Len() >= 3 {
					neg := t.inbox.Next(3)
					t.Negotiate(neg[1], neg[2])
					continue
				} else {
					// need more data to process a negotiation.
					return
				}
			}

			// second byte SB means this is a subnegotiation.
			if data[1] == SB {
				if t.inbox.Len() >= 5 {
					indx := bytes.Index(data, []byte{IAC, SE})
					if indx != -1 {
						subneg := t.inbox.Next(indx + 1)
						t.SubNegotiate(subneg[2], subneg[3:indx])
						continue
					} else {
						// subnegotiation unfinished.
						return
					}
				} else {
					// need more data to process a sub-negotiation.
					return
				}
			}

			// this is an escaped IAC - just pass it along.
			if data[1] == IAC {
				t.cmdbox.WriteByte(IAC)
				t.inbox.Next(2)
				t.ParseAppData()
				continue
			} else {
				// and if it's anything else, pass it to DoAppCmd.
				discarded := t.inbox.Next(2)
				t.DoAppCmd(discarded[1])
				continue
			}

		} else {
			// We are not looking at an IAC. look ahead until we see one and delim there.
			idx := bytes.IndexByte(data, IAC)
			if idx != -1 {
				t.cmdbox.Write(t.inbox.Next(idx))
				t.ParseAppData()
				continue
			} else {
				// If there was no IAC, then append EVERYTHING to the cmdbox.
				t.cmdbox.Write(t.inbox.Next(t.inbox.Len()))
				t.ParseAppData()
				return
			}

		}
	}
}

func (t *TelnetMudConnection) OnUpdate() {
	if t.ready {
		t.manager.Handler.OnUpdate(t)
	}
}

func (t *TelnetMudConnection) DoAppCmd(command byte) {
	// these are pretty much ignored for the moment.
}

func (t *TelnetMudConnection) Negotiate(command, option byte) {
	handler, found := t.handlers[option]
	if !found {
		switch command {
		case WILL:
			t.outbox <- &OutMessage{data: []byte{IAC, DONT, option}}
		case DO:
			t.outbox <- &OutMessage{data: []byte{IAC, WONT, option}}
		}
		return
	}
	state, found2 := t.states[option]
	if !found2 {
		return
	}

	switch command {
	case WILL:
		if handler.SupportRemote() {
			if state.remote.negotiating {
				state.remote.negotiating = false
				if !state.remote.enabled {
					state.remote.enabled = true
					handler.OnRemoteEnable(t)
					if !state.remote.answered {
						state.remote.answered = true
						t.hs.OnRemote(t, option)
					}
				}
			} else {
				state.remote.enabled = true
				t.outbox <- &OutMessage{data: []byte{IAC, DO, option}}
				handler.OnRemoteEnable(t)
				if !state.remote.answered {
					state.remote.answered = true
					t.hs.OnRemote(t, option)
				}
			}
		} else {
			t.outbox <- &OutMessage{data: []byte{IAC, DONT, option}}
		}

	case DO:
		if handler.SupportLocal() {
			if state.local.negotiating {
				state.local.negotiating = false
				if !state.local.enabled {
					state.local.enabled = true
					handler.OnLocalEnable(t)
					if !state.local.answered {
						state.local.answered = true
						t.hs.OnLocal(t, option)
					}
				}
			} else {
				state.local.enabled = true
				t.outbox <- &OutMessage{data: []byte{IAC, DO, option}}
				handler.OnLocalEnable(t)
				if !state.local.answered {
					state.local.answered = true
					t.hs.OnLocal(t, option)
				}
			}
		} else {
			t.outbox <- &OutMessage{data: []byte{IAC, WONT, option}}
		}

	case WONT:
		if state.remote.enabled {
			handler.OnRemoteDisable(t)
			state.remote.enabled = false
		}
		if state.remote.negotiating {
			state.remote.negotiating = false
			if !state.remote.answered {
				state.remote.answered = true
				t.hs.OnRemote(t, option)
			}
		}

	case DONT:
		if state.local.enabled {
			handler.OnLocalDisable(t)
			state.local.enabled = false
		}
		if state.local.negotiating {
			state.local.negotiating = false
			if !state.local.answered {
				state.local.answered = true
				t.hs.OnLocal(t, option)
			}
		}
	}

}

func (t *TelnetMudConnection) SubNegotiate(option byte, data []byte) {
	handler, exists := t.handlers[option]
	if exists {
		handler.SubNegotiate(t, data)
	}
}

func (t *TelnetMudConnection) ParseAppData() {
	for t.cmdbox.Len() > 0 {
		data := t.cmdbox.Bytes()
		idx := bytes.IndexByte(data, LF)
		if idx != -1 {
			// we have a line! Error cannot occur in this situation so ignoring it.
			line, _ := t.cmdbox.ReadBytes(LF)
			if t.ready {
				t.HandleLine(bytes.TrimSpace(line))
			} else {
				t.SuspendLine(bytes.TrimSpace(line))
			}
		} else {
			// no lines to process...
			return
		}
	}
}

func (t *TelnetMudConnection) HandleLine(line []byte) {
	if utf8.Valid(line) {
		t.manager.Handler.OnLine(t, string(line))
	}
}

func (t *TelnetMudConnection) SuspendLine(line []byte) {
	if utf8.Valid(line) {
		t.pending_cmds = append(t.pending_cmds, string(line))
	}
}

func (t *TelnetMudConnection) Start() {
	t.running = true
	go t.RunTimer()
	go t.RunKeepalive()
	go t.RunOutBox()
	go t.RunInbox()
}

func (t *TelnetMudConnection) Stop() {

}

func (t *TelnetMudConnection) Name() string {
	return t.name
}

func (t *TelnetMudConnection) Close() {

}

func (t *TelnetMudConnection) SendStatus(data map[string]string) {

}

func (t *TelnetMudConnection) SendLine(data string) {

}

func (t *TelnetMudConnection) SendText(data string) {

}

func (t *TelnetMudConnection) SendPrompt(data string) {

}

type TelnetMudListener struct {
	manager  *mudlink.MudLinkManager
	name     string
	listener net.Listener
	tls      *tls.Config
	running  bool
}

func (t *TelnetMudListener) RunLoop() {
	for t.running == true {
		c, err := t.listener.Accept()
		if err != nil {
			fmt.Println("Error, ", err.Error())
			t.running = false
			return
		}
		name := t.manager.GenerateConnId(t.name, 20)
		tmp := TelnetMudConnection{name: name, conn: c, manager: t.manager, listener: t}
		tmp.Init()
		t.manager.RegisterConnection(&tmp)
	}
}

func (t *TelnetMudListener) Start() {
	if t.running == true {
		return
	}
	t.running = true
	go t.RunLoop()
}

func (t *TelnetMudListener) Stop() error {
	if t.running == false {
		return nil
	}
	err := t.listener.Close()
	if err == nil {
		t.running = false
	}
	return err
}

func (t *TelnetMudListener) Addr() net.Addr {
	return t.listener.Addr()
}

func (t *TelnetMudListener) Tls() *tls.Config {
	return t.tls
}

func (t *TelnetMudListener) SetManager(m *mudlink.MudLinkManager) {
	t.manager = m
}

func (t *TelnetMudListener) Name() string {
	return t.name
}

func Listen(name, network, address string) (mudlink.MudListener, error) {
	t, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	out := TelnetMudListener{name: name, listener: t, tls: nil}
	return &out, nil
}

func ListenTLS(name, network, address string, config *tls.Config) (mudlink.MudListener, error) {
	t, err := tls.Listen(network, address, config)
	if err != nil {
		return nil, err
	}
	out := TelnetMudListener{name: name, listener: t, tls: config}
	return &out, nil
}
