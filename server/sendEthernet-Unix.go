//go:build darwin || freebsd || openbsd || netbsd

package server

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func sendEthernet(iface net.Interface, resp *dhcpv4.DHCPv4) error {
	f, err := findBPFDevice()
	if err != nil {
		return fmt.Errorf("BPF open failed: %v", err)
	}
	defer f.Close()

	var ifr [32]byte
	copy(ifr[:], iface.Name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.BIOCSETIF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return fmt.Errorf("ioctl BIOCSETIF failed: %v", errno)
	}

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
		return err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	payload := gopacket.Payload(resp.ToBytes())
	err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, payload)
	if err != nil {
		return fmt.Errorf("serialization failed: %v", err)
	}

	_, err = f.Write(buf.Bytes())
	return err
}

func findBPFDevice() (*os.File, error) {
	f, err := os.OpenFile("/dev/bpf", os.O_RDWR, 0)
	if err == nil {
		return f, nil
	}

	for i := 0; i < 99; i++ {
		f, err = os.OpenFile(fmt.Sprintf("/dev/bpf%d", i), os.O_RDWR, 0)
		if err == nil {
			return f, nil
		}
	}
	return nil, fmt.Errorf("no available BPF devices found (check root permissions)")
}
