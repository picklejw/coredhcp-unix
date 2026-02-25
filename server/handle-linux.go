//go:build linux
// +build linux

package server

import (
	"errors"
	"net"
)

func (l *listener6) Serve() error {
	log.Printf("Listen %s", l.LocalAddr())
	for {
		b := *bufpool.Get().(*[]byte)
		b = b[:MaxDatagram] //Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := l.ReadFrom(b)
		if errors.Is(err, net.ErrClosed) {
			// Server is quitting
			return nil
		} else if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		go l.HandleMsg6(b[:n], oob, peer.(*net.UDPAddr))
	}
}

func (l *listener4) Serve() error {
	log.Printf("Listen %s", l.LocalAddr())
	for {
		b := *bufpool.Get().(*[]byte)
		b = b[:MaxDatagram] //Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := l.ReadFrom(b)
		if errors.Is(err, net.ErrClosed) {
			// Server is quitting
			return nil
		} else if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		go l.HandleMsg4(b[:n], oob, peer.(*net.UDPAddr))
	}
}
