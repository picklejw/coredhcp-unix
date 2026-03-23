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

func getInterfaceIPv4(iface net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		// addr is typically a *net.IPNet or *net.IPAddr
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		// Check if it's a valid IPv4 address (not IPv6) and not loopback
		if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
			return ip.To4(), nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for interface %s", iface.Name)
}

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

	if resp.ServerIPAddr == nil || resp.ServerIPAddr.IsUnspecified() {
		// I think this is the hacky way of doing this but sometimes the `SrcIP:    resp.ServerIPAddr,`
		// is correct for the interface and sometimes it is 0.0.0.0:68 causing issues with DHCP clients that
		// want this presion. So lets hack it in here to make it relible, which is better then a bad fix this might be
		localIP, err := getInterfaceIPv4(iface) // Use the helper function from earlier
		if err != nil {
			return err
		}
		resp.ServerIPAddr = localIP
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
