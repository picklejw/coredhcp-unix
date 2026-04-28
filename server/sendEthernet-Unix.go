// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build darwin || freebsd || openbsd || netbsd

package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

type pcapSender struct {
	ifName string
	handle *pcap.Handle
	mu     sync.Mutex
}

func newPcapSender(ifName string) (*pcapSender, error) {
	h, err := pcap.OpenLive(ifName, 65536, true, pcap.BlockForever)
	if err != nil {
		if isPermissionError(err) {
			return nil, fmt.Errorf("newPcapSender: cannot open pcap handle on %s: %w (permission denied; try running as root or grant capture permissions)", ifName, err)
		}
		return nil, fmt.Errorf("newPcapSender: cannot open pcap handle on %s: %w", ifName, err)
	}
	return &pcapSender{ifName: ifName, handle: h}, nil
}

func (s *pcapSender) Close() {
	s.mu.Lock()
	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}
	s.mu.Unlock()
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := err.Error()
	if msg == "operation not permitted" || msg == "permission denied" {
		return true
	}
	// pcap may return strings like "pcap_open_live: permission denied"
	if len(msg) >= 10 && (containsIgnoreCase(msg, "permission") || containsIgnoreCase(msg, "operation not permitted")) {
		return true
	}
	return false
}

func containsIgnoreCase(s, sub string) bool {
	return len(s) >= len(sub) && (stringIndexIgnoreCase(s, sub) >= 0)
}

func stringIndexIgnoreCase(s, sub string) int {
	ls := []byte(s)
	lsub := []byte(sub)
	for i := range ls {
		if ls[i] >= 'A' && ls[i] <= 'Z' {
			ls[i] = ls[i] + ('a' - 'A')
		}
	}
	for i := range lsub {
		if lsub[i] >= 'A' && lsub[i] <= 'Z' {
			lsub[i] = lsub[i] + ('a' - 'A')
		}
	}

	return bytesIndex(ls, lsub)
}

func bytesIndex(s, sep []byte) int {
	if len(sep) == 0 {
		return 0
	}
	for i := 0; i+len(sep) <= len(s); i++ {
		match := true
		for j := range sep {
			if s[i+j] != sep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func (s *pcapSender) Send(pkt []byte) error {
	s.mu.Lock()
	h := s.handle
	s.mu.Unlock()

	if h == nil {
		return fmt.Errorf("pcapSender.Send: handle closed for %s", s.ifName)
	}
	if err := h.WritePacketData(pkt); err != nil {
		if isPermissionError(err) {
			s.mu.Lock()
			if s.handle != nil {
				s.handle.Close()
				s.handle = nil
			}
			s.mu.Unlock()

			nh, err2 := pcap.OpenLive(s.ifName, 65536, true, pcap.BlockForever)
			if err2 != nil {
				if isPermissionError(err2) {
					return fmt.Errorf("pcapSender.Send: write failed (%v) and cannot reopen handle on %s: %w (permission denied; run as root or grant capture permissions)", err, s.ifName, err2)
				}
				return fmt.Errorf("pcapSender.Send: write failed (%v) and cannot reopen handle on %s: %w", err, s.ifName, err2)
			}
			s.mu.Lock()
			s.handle = nh
			s.mu.Unlock()

			if writeErr := nh.WritePacketData(pkt); writeErr != nil {
				if isPermissionError(writeErr) {
					return fmt.Errorf("pcapSender.Send: write failed after reopen on %s: %w (permission denied; run as root or grant capture permissions)", s.ifName, writeErr)
				}
				return fmt.Errorf("pcapSender.Send: write failed after reopen on %s: %w", s.ifName, writeErr)
			}
			return nil
		}

		s.mu.Lock()
		if s.handle != nil {
			s.handle.Close()
			s.handle = nil
		}
		s.mu.Unlock()

		nh, err2 := pcap.OpenLive(s.ifName, 65536, true, pcap.BlockForever)
		if err2 != nil {
			if isPermissionError(err2) {
				return fmt.Errorf("pcapSender.Send: write failed (%v) and cannot reopen handle on %s: %w (permission denied; run as root or grant capture permissions)", err, s.ifName, err2)
			}
			return fmt.Errorf("pcapSender.Send: write failed (%v) and cannot reopen handle on %s: %w", err, s.ifName, err2)
		}
		s.mu.Lock()
		s.handle = nh
		s.mu.Unlock()

		if writeErr := nh.WritePacketData(pkt); writeErr != nil {
			if isPermissionError(writeErr) {
				return fmt.Errorf("pcapSender.Send: write failed after reopen on %s: %w (permission denied; run as root or grant capture permissions)", s.ifName, writeErr)
			}
			return fmt.Errorf("pcapSender.Send: write failed after reopen on %s: %w", s.ifName, writeErr)
		}
	}
	return nil
}

var (
	sendersMu sync.Mutex
	senders   = make(map[string]*pcapSender)
)

func getOrCreateSender(ifName string) (*pcapSender, error) {
	sendersMu.Lock()
	defer sendersMu.Unlock()
	if s, ok := senders[ifName]; ok {
		return s, nil
	}
	s, err := newPcapSender(ifName)
	if err != nil {
		return nil, err
	}
	senders[ifName] = s
	return s, nil
}

func CloseAllSenders() {
	sendersMu.Lock()
	defer sendersMu.Unlock()
	for _, s := range senders {
		s.Close()
	}
	senders = make(map[string]*pcapSender)
}

func sendEthernet(iface net.Interface, resp *dhcpv4.DHCPv4) error {
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       resp.ClientHWAddr,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    resp.ServerIPAddr,
		DstIP:    resp.YourIPAddr,
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := layers.UDP{
		SrcPort: dhcpv4.ServerPort,
		DstPort: dhcpv4.ClientPort,
	}

	if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
		return fmt.Errorf("sendEthernet: couldn't set network layer for checksum: %w", err)
	}

	packet := gopacket.NewPacket(resp.ToBytes(), layers.LayerTypeDHCPv4, gopacket.NoCopy)
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return fmt.Errorf("sendEthernet: failed to decode DHCPv4 layer")
	}
	dhcp, ok := dhcpLayer.(gopacket.SerializableLayer)
	if !ok {
		return fmt.Errorf("sendEthernet: layer %s is not serializable", dhcpLayer.LayerType().String())
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, dhcp); err != nil {
		return fmt.Errorf("sendEthernet: cannot serialize layers: %w", err)
	}

	sender, err := getOrCreateSender(iface.Name)
	if err != nil {
		return fmt.Errorf("sendEthernet: cannot get pcap sender for %s: %w", iface.Name, err)
	}

	if err := sender.Send(buf.Bytes()); err != nil {
		return fmt.Errorf("sendEthernet: cannot write packet on %s: %w", iface.Name, err)
	}
	return nil
}
