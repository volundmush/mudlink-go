package telnet

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/semver"
	"github.com/volundmush/mudlink-go/mudlink"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

var XTERM_CLIENTS = map[string]bool{"ATLANTIS": true, "CMUD": true, "KILDCLIENT": true, "MUDLET": true, "MUSHCLIENT": true,
	"PUTTY": true, "BEIP": true, "POTATO": true, "TINYFUGUE": true}

const (
	NUL        byte = 0
	BEL             = 7
	CR              = 13
	LF              = 10
	SGA             = 3
	TELOPT_EOR      = 25
	NAWS            = 31
	LINEMODE        = 34
	EOR             = 239
	SE              = 240
	NOP             = 241
	GA              = 249
	SB              = 250
	WILL            = 251
	WONT            = 252
	DO              = 253
	DONT            = 254
	IAC             = 255

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

	// MTTS Terminal Type
	MTTS = 24
)

var Negotiators = map[byte]byte{
	WILL: DO,
	DO:   WILL,
	DONT: WONT,
	WONT: DONT,
}

var Reversed = map[byte]byte{
	WILL: DONT,
	DO:   WONT,
	DONT: WONT,
	WONT: DONT,
}

func TelnetSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	available := len(data)

	// If no bytes, don't bother.
	if available < 1 {
		return 0, nil, nil
	}

	if data[0] == IAC {
		// Need at least 2 bytes to do anything with an IAC message.
		if available < 2 {
			return 0, nil, nil
		}
		_, ok := Negotiators[data[1]]
		switch {
		case data[1] == IAC:
			// This is a literal escaped byte 255. We have to return it alone, lest further parsing confuse it with
			// an IAC <command>
			return 2, data[1:1], nil
		case ok:
			// This handles DO/DONT/WILL/WONT
			if available < 3 {
				return 0, nil, nil
			}
			return 3, data[:3], nil
		case data[1] == SB:
			// This pattern is IAC SB <OPCODE> <BYTES> IAC SE, it requires at least 5 bytes to make sense.
			if available < 5 {
				return 0, nil, nil
			}
			escaped := false
			for i, c := range data[3:] {
				if escaped {
					if c == SE {
						// We can finally return some data!
						return 4 + i, data[:4+i], nil
					}
					escaped = false
					continue
				}
				if c == IAC {
					escaped = true
				}
			}
			// if we reached this point, then we haven't received an IAC SE terminator yet.
			return 0, nil, nil
		default:
			// This is an IAC <command>
			return 2, data[:1], nil
		}

	} else {
		// If the buffer doesn't begin with IAC, we gobble up everything up until the next IAC.
		for i, c := range data {
			if c == IAC {
				return i, data[:i], nil
			}
		}
		return available, data, nil
	}
}

type TelnetPerspective struct {
	negotiating bool
	enabled     bool
}

type TelnetOption struct {
	remote TelnetPerspective
	local  TelnetPerspective
}

type TelnetStream struct {
	reader       io.Reader
	writer       io.WriteCloser
	outchan      chan []byte
	inchan       chan []byte
	appdata      bytes.Buffer
	op_sga       TelnetOption
	op_telopteor TelnetOption
	op_naws      TelnetOption
	op_linemode  TelnetOption
	op_mnes      TelnetOption
	op_mxp       TelnetOption
	op_mssp      TelnetOption
	op_mccp2     TelnetOption
	op_mccp3     TelnetOption
	op_gmcp      TelnetOption
	op_msdp      TelnetOption
	op_mtts      TelnetOption
	mccp2_active bool
	mccp3_active bool
	dirty        bool
	mtts_temp    []byte
	mtts_state   uint8
	capabilities mudlink.MudCapabilities
	status       uint8
	manager      *mudlink.MudLinkManager
}

var mccp2_sequence = []byte{IAC, SB, MCCP2, IAC, SE}
var mccp3_sequence = []byte{IAC, SB, MCCP3, IAC, SE}

var start_sequence = []byte{
	IAC, DO, LINEMODE,
	IAC, WILL, SGA,
	IAC, DO, NAWS,
	IAC, DO, MTTS,
	IAC, WILL, MCCP2,
	IAC, DO, MCCP3,
	IAC, WILL, MSSP,
	IAC, WILL, MSDP,
	IAC, WILL, GMCP,
	IAC, WILL, MXP,
}

func (t *TelnetStream) Start() {
	t.outchan <- start_sequence
	t.op_linemode.remote.negotiating = true
	t.op_naws.remote.negotiating = true
	t.op_mtts.remote.negotiating = true
	t.op_mccp2.local.negotiating = true
	t.op_mccp3.remote.negotiating = true
	t.op_mssp.local.negotiating = true
	t.op_msdp.local.negotiating = true
	t.op_gmcp.local.negotiating = true
	t.op_mxp.local.negotiating = true
	go t.runWriter()
	go t.runReader()
	go t.runGetReady()
}

func (t *TelnetStream) Close() {
	close(t.outchan)
	close(t.inchan)
	t.writer.Close()
}

func (t *TelnetStream) getReady() {
	t.status = mudlink.Running
	if t.manager != nil {
		j, err := json.Marshal(map[string]interface{}{
			"MsgType":      "ClientReady",
			"ClientID":     t.capabilities.ClientID,
			"Capabilities": t.capabilities,
		})
		if err != nil {
			// handle error somehow.
		}
		t.manager.Outchan <- j
	}

	// TODO: make it send a Ready message.

	// This will force handleAppData to flush itself now
	// that we're ready.
	t.handleAppData(make([]byte, 0))
}

func (t *TelnetStream) runGetReady() {
	ops := []*TelnetOption{&t.op_sga, &t.op_telopteor, &t.op_naws, &t.op_mnes,
		&t.op_mxp, &t.op_mssp, &t.op_mccp2, &t.op_mccp3, &t.op_gmcp, &t.op_msdp,
		&t.op_mtts}

	tries := 0
	for range time.NewTicker(time.Millisecond * 30).C {
		tries++
		if tries > 10 {
			break
		}
		pending := false
		for _, cur := range ops {
			if cur.local.negotiating || cur.remote.negotiating {
				pending = true
				break
			}
		}
		if !pending {
			t.getReady()
			break
		}
	}
	// Negotiation timed out...
	t.getReady()
}

func (t *TelnetStream) handleAppData(p []byte) {
	t.inchan <- p
}

var delim = []byte{LF}

func (t *TelnetStream) runAppData() {
	for data := range t.inchan {
		t.appdata.Write(data)

		if t.status != mudlink.Running {
			continue
		}

		if t.dirty {
			// generate a new status update.
			// send it here.
			t.dirty = false
		}

		// now gather newlines from t.appdata until none remain
		for bytes.Contains(t.appdata.Bytes(), delim) {
			b, _ := t.appdata.ReadString(LF)
			b = strings.ReplaceAll(b, "\r", "")
			fmt.Println("COMMAND:", b)
			if t.manager != nil {
				j, err := json.Marshal(map[string]interface{}{
					"MsgType":  "ClientCommand",
					"ClientID": t.capabilities.ClientID,
					"Command":  b,
				})
				if err != nil {
					// do something with this error.
				}
				t.manager.Outchan <- j
			}
		}
	}
}

func (t *TelnetStream) Capabilities() *mudlink.MudCapabilities {
	return &t.capabilities
}

func (t *TelnetStream) Status() uint8 {
	return t.status
}

func (t *TelnetStream) SendMSSP(data map[string]string) {
	// TODO!
}

func (t *TelnetStream) SendLine(data string) {
	if strings.HasSuffix(data, "\r\n") {
		t.SendText(data)
	} else {
		t.SendText(data + "\r\n")
	}
}

func (t *TelnetStream) SendText(data string) {
	msg := strings.ReplaceAll(data, "\r", "")
	msg = strings.ReplaceAll(data, "\n", "\r\n")
	t.outchan <- []byte(msg)
}

func (t *TelnetStream) SendPrompt(data string) {
	t.SendLine(data)
}

var local_supported = map[byte]bool{
	MCCP2: true,
	MSSP:  true,
	MSDP:  true,
	GMCP:  true,
	MXP:   true,
}

var remote_supported = map[byte]bool{
	LINEMODE: true,
	NAWS:     true,
	MTTS:     true,
	MCCP3:    true,
}

func (t *TelnetStream) onEnableLocal(option byte) {
	switch option {
	case MCCP2:
		fmt.Println("MCCP2 DETECTED")
		t.capabilities.Mccp2 = true
		// activate compression immediately after the writer sees this
		t.outchan <- mccp2_sequence
	case MSSP:
		// TODO: send a MSSP request to the backend...
		t.capabilities.Mssp = true
	case MSDP:
		t.capabilities.Msdp = true
	case GMCP:
		t.capabilities.Gmcp = true
	case MXP:
		t.capabilities.Mxp = true
	}
	t.dirty = true
}

func (t *TelnetStream) onEnableRemote(option byte) {
	switch option {
	case LINEMODE:
		t.capabilities.Linemode = true
	case NAWS:
		t.capabilities.Naws = true
	case MTTS:
		t.capabilities.Mtts = true
		t.outchan <- mtts_sequence
	case MCCP3:
		t.capabilities.Mccp3 = true
	}
}

func (t *TelnetStream) onDisableLocal(option byte) {

}

func (t *TelnetStream) onDisableRemote(option byte) {

}

func (t *TelnetStream) handleNegotiate(operation, option byte) {
	var op *TelnetOption = nil
	var per *TelnetPerspective = nil

	var options map[byte]bool

	var enabler bool
	var local bool

	switch operation {
	case WILL:
		fmt.Println("IAC WILL", option)
		enabler = true
		local = false
	case DO:
		fmt.Println("IAC DO", option)
		enabler = true
		local = true
	case WONT:
		fmt.Println("IAC WONT", option)
		enabler = false
		local = false
	case DONT:
		fmt.Println("IAC DONT", option)
		enabler = false
		local = true
	}

	if local {
		options = local_supported
	} else {
		options = remote_supported
	}

	supported, ok := options[option]

	if (!ok || !supported) && enabler {
		t.outchan <- []byte{IAC, Reversed[operation], option}
		return
	}

	switch option {
	case LINEMODE:
		op = &t.op_linemode
	case NAWS:
		op = &t.op_naws
	case MTTS:
		op = &t.op_mtts
	case MCCP3:
		op = &t.op_mccp3
	case MCCP2:
		op = &t.op_mccp2
	case MSSP:
		op = &t.op_mssp
	case MSDP:
		op = &t.op_msdp
	case GMCP:
		op = &t.op_gmcp
	case MXP:
		op = &t.op_mxp
	}

	if op == nil {
		t.outchan <- []byte{IAC, Reversed[operation], option}
		return
	}

	if local {
		per = &op.local
	} else {
		per = &op.remote
	}

	if per.enabled {
		if !enabler {
			per.enabled = false
			if local {
				t.onDisableLocal(option)
			} else {
				t.onDisableRemote(option)
			}
		}
		return
	}

	if per.negotiating {
		// We were already negotiating, and just got confirmation.
		per.enabled = true
		per.negotiating = false
		if local {
			t.onEnableLocal(option)
		} else {
			t.onEnableRemote(option)
		}
	} else {
		// Time to start negotiation.
		per.negotiating = true
		t.outchan <- []byte{IAC, Negotiators[operation], option}
	}

}

var mtts_sequence = []byte{IAC, SB, MTTS, 1, IAC, SE}

func (t *TelnetStream) handleMTTS(p []byte) {
	if t.mtts_temp == nil {
		t.mtts_temp = make([]byte, 0)
		t.mtts_state = 0
	}

	if bytes.Equal(p, t.mtts_temp) {
		// The client has stopped sending unique data. Ignore.
		return
	}

	t.mtts_temp = make([]byte, 0)
	copy(p, t.mtts_temp)

	if p[0] != 0 {
		// malformed data, discard
		return
	}

	msg := p[1:]
	if len(msg) == 0 {
		// no message to parse.
		return
	}

	info := string(msg)
	fmt.Println("MTTS STATE", t.mtts_state, ":", info)

	switch t.mtts_state {
	case 0:
		t.handleMTTS_0(info)
	case 1:
		t.handleMTTS_1(info)
	case 2:
		t.handleMTTS_2(info)
	}
	t.mtts_state += 1
	if t.mtts_state < 3 {
		t.outchan <- mtts_sequence
	}
}

func (t *TelnetStream) handleMTTS_0(info string) {
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
		t.capabilities.Color = uint8(math.Max(float64(t.capabilities.Color), 2))
	}

	t.capabilities.Color = uint8(math.Max(float64(t.capabilities.Color), 1))
	t.dirty = true
}

func (t *TelnetStream) handleMTTS_1(info string) {
	tupper := strings.ToUpper(info)
	xterm := (strings.HasSuffix(tupper, "-256COLOR") || strings.HasSuffix(tupper, "XTERM")) && !strings.HasSuffix(tupper, "-COLOR")

	if xterm {
		t.capabilities.Color = uint8(math.Max(float64(t.capabilities.Color), 2))
	}
	t.capabilities.Terminal_type = tupper
	t.dirty = true
}

func (t *TelnetStream) handleMTTS_2(info string) {
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
		t.capabilities.Color = uint8(math.Max(float64(t.capabilities.Color), 2))
	}

	if (mask & 4) == 4 {
		t.capabilities.Utf8 = true
	}

	if (mask & 2) == 2 {
		t.capabilities.Vt100 = true
	}

	if (mask & 1) == 1 {
		t.capabilities.Color = uint8(math.Max(float64(t.capabilities.Color), 1))
	}
	t.dirty = true
}

func (t *TelnetStream) handleSub(option byte, p []byte) {
	fmt.Println("HANDLE SUB:", option, ":", string(p))
	switch option {
	case NAWS:
		if len(p) == 4 {
			t.capabilities.Width = binary.BigEndian.Uint16(p[:2])
			t.capabilities.Height = binary.BigEndian.Uint16(p[3:])
			t.dirty = true
		}
	case MTTS:
		t.handleMTTS(p)
	}
}

func (t *TelnetStream) handleCommand(command byte) {
	// for now, this does absolutely nothing.
	fmt.Println("TEST COMMAND:", command)
}

func (t *TelnetStream) handleTelnetMessage(p []byte) {
	fmt.Println("GOT TELNET MESSAGE: ", p)
	if len(p) == 1 {
		// This can only be appdata - it's either a random character, or an escaped IAC.
		t.handleAppData(p)
		return
	}

	if p[0] == IAC {
		// determine the nature of the message next. This is an IAC sequence after all.
		_, ok := Negotiators[p[1]]
		switch {
		case ok:
			t.handleNegotiate(p[1], p[2])
		case p[1] == SB:
			t.handleSub(p[2], p[3:len(p)-2])
		default:
			t.handleCommand(p[2])
		}
	} else {
		// This is appdata.
		t.handleAppData(p)
	}

}

func (t *TelnetStream) runReader() {
	//orig := t.reader
	var inbuf bytes.Buffer
	zcom, _ := zlib.NewReader(&inbuf)
	zreader := bufio.NewReader(zcom)
	var zbuf bytes.Buffer

	for {
		tbuf := make([]byte, 2048)
		num, err := t.reader.Read(tbuf)
		fmt.Println("Read ", num, " bytes", tbuf[:num])
		if err != nil {
			// gotta do something with this error.
		}
		inbuf.Write(tbuf[:num])
		var buf *bytes.Buffer = nil

		if t.capabilities.Mccp3_active {
			buf = &zbuf
			zreader.WriteTo(buf)
		} else {
			buf = &inbuf
		}

		for {
			consumed, data, _ := TelnetSplit(buf.Bytes(), false)

			if data == nil {
				break
			}
			fmt.Println("Consumed", consumed, "bytes:", data)
			buf.Next(consumed)

			t.handleTelnetMessage(data)
			if !t.capabilities.Mccp3_active && bytes.Equal(mccp3_sequence, data) {
				t.capabilities.Mccp3_active = true
				t.dirty = true
				buf = &zbuf
				zreader.WriteTo(buf)
			}
		}
	}
}

func (t *TelnetStream) runWriter() {
	var outbuf bytes.Buffer
	// Storing this in case we need to replace it.
	orig := t.writer
	var zwriter *zlib.Writer = nil

	for data := range t.outchan {
		outbuf.Write(data)
		fmt.Println("Flushing to outbuf:", data)

		for outbuf.Len() > 0 {
			written, err := t.writer.Write(outbuf.Bytes())
			if written > 0 {
				outbuf.Next(written)
				if t.capabilities.Mccp2_active {
					err := zwriter.Flush()
					if err != nil {
						// do something with this...
					}
				}
			}
			if err != nil {
				// Do something with the error..
			}
		}

		// if we just sent a mccp2_sequence, enable compression if it isn't already enabled.
		if !t.capabilities.Mccp2_active && bytes.Equal(data, mccp2_sequence) {
			// Enable MCCP2 outgoing compression.
			t.capabilities.Mccp2_active = true
			fmt.Println("MCCP2 FULLY ACTIVATED")
			t.dirty = true
			zwriter = zlib.NewWriter(orig)
			t.writer = zwriter
		}
	}
}

func NewTelnetStream(reader io.Reader, writer io.WriteCloser) *TelnetStream {
	t := new(TelnetStream)
	t.reader = reader
	t.writer = writer
	t.capabilities.Protocol = mudlink.Telnet
	t.capabilities.Client_name = "UNKNOWN"
	t.capabilities.Client_version = "UNKNOWN"
	t.capabilities.Width = 78
	t.capabilities.Height = 24
	t.outchan = make(chan []byte, 10)
	t.inchan = make(chan []byte, 10)

	return t
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
			fmt.Println("Error:", err.Error())
			t.running = false
			return
		}
		name := t.manager.GenerateConnId(t.name, 20)
		tmp := NewTelnetStream(c, c)
		tmp.capabilities.ClientID = name
		tmp.capabilities.Address = c.RemoteAddr()
		if t.tls != nil {
			tmp.capabilities.Tls = true
		}
		t.manager.RegisterConnection(tmp)
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
