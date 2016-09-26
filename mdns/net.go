package mdns

import (
	"log"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type multicastConn struct {
	conn *net.UDPConn
	addr net.Addr
}

func newConn(addr *net.UDPAddr) (*multicastConn, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	if addr.IP.To4() != nil {
		pc := ipv4.NewPacketConn(c)
		pc.SetMulticastTTL(255)

		for _, iface := range ifaces {
			if (iface.Flags&net.FlagUp == 0) || (iface.Flags&net.FlagMulticast == 0) {
				continue
			}
			err := pc.JoinGroup(&iface, addr)
			if err != nil {
				log.Println("Unable to join IPv4 mDNS multicast group", iface, err)
			}
		}
	} else {
		pc := ipv6.NewPacketConn(c)

		for _, iface := range ifaces {
			if (iface.Flags&net.FlagUp == 0) || (iface.Flags&net.FlagMulticast == 0) {
				continue
			}
			err := pc.JoinGroup(&iface, addr)
			if err != nil {
				log.Println("Unable to join IPv6 mDNS multicast group", iface, err)
			}
		}
	}

	return &multicastConn{conn: c, addr: addr}, nil
}

func (c *multicastConn) send(b []byte, addr net.Addr) error {
	_, err := c.conn.WriteTo(b, addr)
	return err
}

func (c *multicastConn) sendMulticast(b []byte) error {
	_, err := c.conn.WriteTo(b, c.addr)
	return err
}

func (c *multicastConn) recv(b []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(b)
}
