package main

import (
	"fmt"
	"github.com/volundmush/mudlink-go/mudlink"
	"github.com/volundmush/mudlink-go/telnet"
)

type TestHandler struct {
	manager *mudlink.MudLinkManager
}

func (h *TestHandler) SetManager(m *mudlink.MudLinkManager) {
	h.manager = m
}

func (h *TestHandler) OnConnect(c mudlink.MudConnection) {
	fmt.Println("Got a connection: ", c)
	fmt.Println(c.Capabilities())
}

func (h *TestHandler) OnLine(c mudlink.MudConnection, line string) {
	fmt.Println("Connection ", c.Name(), " sent: ", line)
}

func (h *TestHandler) OnDisconnect(c mudlink.MudConnection) {

}

func (h *TestHandler) OnUpdate(c mudlink.MudConnection) {

}

func main() {
	c := TestHandler{}
	a, err := mudlink.NewMudLinkManager(&c)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	b, err2 := telnet.Listen("telnet", "tcp", "0.0.0.0:7999")
	if err2 != nil {
		fmt.Println(err2.Error())
		return
	}
	_, err3 := a.RegisterListener(b)
	if err3 != nil {
		fmt.Println(err3.Error())
		return
	}
	a.Start()
	fmt.Printf("A is: %+v\n", a)
	fmt.Printf("B is: %+v\n", b)
	fmt.Scanln()
	fmt.Println("done")
}
