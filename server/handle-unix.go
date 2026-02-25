//go:build darwin || freebsd || openbsd || netbsd

package server

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

func (l *listener6) Serve() error {
	// log.Printf("Listen %s", l.LocalAddr())
	// for {
	// 	b := *bufpool.Get().(*[]byte)
	// 	b = b[:MaxDatagram] //Reslice to max capacity in case the buffer in pool was resliced smaller

	// 	n, oob, peer, err := l.ReadFrom(b)
	// 	if errors.Is(err, net.ErrClosed) {
	// 		// Server is quitting
	// 		return nil
	// 	} else if err != nil {
	// 		log.Printf("Error reading from connection: %v", err)
	// 		return err
	// 	}
	// 	go l.HandleMsg6(b[:n], oob, peer.(*net.UDPAddr))
	return errors.New("IPv6 on Unix implementation untested")
}

func (l *listener4) Serve() error {
	handle, err := pcap.OpenLive(l.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp and dst port 67"); err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			udpLayer := packet.Layer(layers.LayerTypeUDP)

			if ipLayer != nil && udpLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				udp, _ := udpLayer.(*layers.UDP)

				synthesizedAddr := &net.UDPAddr{
					IP:   ip.SrcIP,
					Port: int(udp.SrcPort),
				}
				synthesizedOOB := &ipv4.ControlMessage{
					IfIndex: l.Interface.Index,
				}

				go l.HandleMsg4(udp.Payload, synthesizedOOB, synthesizedAddr)
			}
		}
	}
	return nil
}
