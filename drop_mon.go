package dropspy

import (
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// these constants were all pulled out of 5.6 mainline
// include/uapi/linux/net_dropmon.h

const (
	CMD_UNSPEC = iota
	CMD_ALERT  // 1
	CMD_CONFIG
	CMD_START
	CMD_STOP
	CMD_PACKET_ALERT // 5
	CMD_CONFIG_GET
	CMD_CONFIG_NEW
	CMD_STATS_GET
	CMD_STATS_NEW
)

const (
	ATTR_UNSPEC     = iota
	ATTR_ALERT_MODE /* u8 */ // 1
	ATTR_PC         /* u64 */
	ATTR_SYMBOL     /* string */
	ATTR_IN_PORT    /* nested */
	ATTR_TIMESTAMP  /* u64 */ // 5
	ATTR_PROTO      /* u16 */
	ATTR_PAYLOAD    /* binary */
	ATTR_PAD
	ATTR_TRUNC_LEN          /* u32 */
	ATTR_ORIG_LEN           /* u32 */ // 10
	ATTR_QUEUE_LEN          /* u32 */
	ATTR_STATS              /* nested */
	ATTR_HW_STATS           /* nested */
	ATTR_ORIGIN             /* u16 */
	ATTR_HW_TRAP_GROUP_NAME /* string */ // 15
	ATTR_HW_TRAP_NAME       /* string */
	ATTR_HW_ENTRIES         /* nested */
	ATTR_HW_ENTRY           /* nested */
	ATTR_HW_TRAP_COUNT      /* u32 */
	ATTR_SW_DROPS           /* flag */ // 20
	ATTR_HW_DROPS           /* flag */
)

const (
	GRP_ALERT = 1

	// i don't know how to parse SUMMARY mode so we just
	// always use PACKET, which gives us payloads (but requires
	// privileges)
	ALERT_MODE_SUMMARY = 0
	ALERT_MODE_PACKET  = 1

	NATTR_PORT_NETDEV_IFINDEX = 0 /* u32 */
	NATTR_PORT_NETDEV_NAME    = 1 /* string */

	NATTR_STATS_DROPPED = 0

	ORIGIN_SW = 0
	ORIGIN_HW = 1

	CFG_ALERT_COUNT = 1
	CFG_ALERT_DELAY = 2
)

// Session wraps a genetlink.Conn and looks up the DM_NET family
// from the generic netlink registry
type Session struct {
	conn  *genetlink.Conn
	fam   uint16
	group uint32
}

// NewSession connects to generic netlink and looks up the DM_NET
// family so we can issue requests
func NewSession() (*Session, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	s := &Session{
		conn: conn,
	}

	f, g, err := s.dropMonitorLookup()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	s.fam = f
	s.group = g

	return s, nil
}

func (s *Session) dropMonitorLookup() (famid uint16, group uint32, err error) {
	fam, err := s.conn.GetFamily("NET_DM")
	if err != nil {
		return 0, 0, fmt.Errorf("lookup: %w", err)
	}

	if len(fam.Groups) != 1 {
		return 0, 0, fmt.Errorf("lookup: martian NET_DM family (%d groups)", len(fam.Groups))
	}

	return fam.ID, fam.Groups[0].ID, nil
}

func decodeConfig(raw []byte) (map[int]interface{}, error) {
	dec, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ret := map[int]interface{}{}

	for dec.Next() {
		switch dec.Type() {
		case ATTR_ALERT_MODE:
			ret[ATTR_ALERT_MODE] = dec.Uint8()
		case ATTR_TRUNC_LEN:
			ret[ATTR_TRUNC_LEN] = dec.Uint32()
		case ATTR_QUEUE_LEN:
			ret[ATTR_QUEUE_LEN] = dec.Uint32()
		}
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}

// Config returns a raw bundle of attrs (see ATTR_ constants)
// holding the current DM_NET configuration (which is just the
// alert mode and the packet snap length and queue length)
func (s *Session) Config() (map[int]interface{}, error) {
	err := s.req(CMD_CONFIG_GET, nil, false)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	ms, _, err := s.conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	conf, err := decodeConfig(ms[0].Data)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return conf, nil
}

func (s *Session) req(cmd uint8, data []byte, ack bool) error {
	flags := netlink.Request
	if ack {
		flags |= netlink.Acknowledge
	}

	_, err := s.conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: cmd,
		},
		Data: data,
	}, s.fam, flags)
	return err
}

// Start puts DM_NET into packet alerting mode (so we get per-packet
// alerts, and the raw contents of dropped packets), issues
// an acknowledged CMD_START to start monitoring, and then
// joins the GRP_ALERT netlink multicast group to read alerts. DM_NET alerting needs
// to be stopped for this to work.
//
// `sw` and `hw` enable/disable software and hardware drop monitoring,
// respectively; hardware drops are done by offload hardware rather than
// kernel software.
func (s *Session) Start(sw, hw bool) error {
	enc := netlink.NewAttributeEncoder()
	enc.Flag(ATTR_SW_DROPS, sw)
	enc.Flag(ATTR_HW_DROPS, hw)
	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	err = s.setPacketMode()
	if err != nil {
		return fmt.Errorf("packet mode: %w", err)
	}

	err = s.req(CMD_START, raw, true)
	if err != nil {
		return fmt.Errorf("req: %w", err)
	}

	// past here, Stop() alerting if anything fails.

	_, _, err = s.conn.Receive()
	if err != nil {
		s.Stop(sw, hw)
		return fmt.Errorf("req ack: %w", err)
	}

	err = s.conn.JoinGroup(GRP_ALERT)
	if err != nil {
		s.Stop(sw, hw)
		return fmt.Errorf("join: %w", err)
	}

	return nil
}

// Stop issues an ack'd CMD_STOP to turn off DM_NET alerting (`sw` is true
// to disable software drops, and `hw` for hardware), and also leaves
// the GRP_ALERT multicast group for the socket.
func (s *Session) Stop(sw, hw bool) error {
	_ = s.conn.LeaveGroup(GRP_ALERT)

	// BUG(tqbf): log this or something, but if we ask this code to
	// Stop(), I really want it to try to stop. Most of the time, we
	// leave the multicast group simply by closing the connection.

	enc := netlink.NewAttributeEncoder()
	enc.Flag(ATTR_SW_DROPS, sw)
	enc.Flag(ATTR_HW_DROPS, hw)
	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	err = s.req(CMD_STOP, raw, false)
	if err != nil {
		return fmt.Errorf("req: %w", err)
	}

	return nil
}

func decodeAlert(raw []byte) (map[int]interface{}, error) {
	dec, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ret := map[int]interface{}{}

	for dec.Next() {
		switch dec.Type() {
		case ATTR_PC:
			ret[ATTR_PC] = dec.Uint64()
		case ATTR_SYMBOL:
			ret[ATTR_SYMBOL] = dec.String()
		case ATTR_IN_PORT:
			a := map[int]interface{}{}
			dec.Nested(func(d *netlink.AttributeDecoder) error {
				for d.Next() {
					switch d.Type() {
					case NATTR_PORT_NETDEV_IFINDEX:
						a[NATTR_PORT_NETDEV_IFINDEX] = d.Uint32()
					case NATTR_PORT_NETDEV_NAME:
						a[NATTR_PORT_NETDEV_NAME] = d.String()
					}
				}

				return nil
			})
			ret[ATTR_IN_PORT] = a
		case ATTR_TIMESTAMP:
			ret[ATTR_TIMESTAMP] = dec.Uint64()
		case ATTR_PROTO:
			ret[ATTR_PROTO] = dec.Uint16()
		case ATTR_PAYLOAD:
			ret[ATTR_PAYLOAD] = dec.Bytes()
		case ATTR_ORIG_LEN:
			ret[ATTR_ORIG_LEN] = dec.Uint32()
		case ATTR_ORIGIN:
			ret[ATTR_ORIGIN] = dec.Uint16()
		case ATTR_HW_TRAP_GROUP_NAME:
		case ATTR_HW_TRAP_NAME:
		case ATTR_HW_ENTRIES:
		case ATTR_HW_ENTRY:
		case ATTR_HW_TRAP_COUNT:
		}
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Session) setPacketMode() error {
	enc := netlink.NewAttributeEncoder()
	enc.Uint8(ATTR_ALERT_MODE, ALERT_MODE_PACKET)
	enc.Uint32(ATTR_TRUNC_LEN, 100)
	enc.Uint32(ATTR_QUEUE_LEN, 4096)

	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	err = s.req(CMD_CONFIG, raw, true)
	if err != nil {
		return fmt.Errorf("req: %w", err)
	}

	_, _, err = s.conn.Receive()
	if err != nil {
		return fmt.Errorf("req ack: %w", err)
	}

	return nil
}

// PacketAlertFunc returns false if we should stop reading drops now.
type PacketAlertFunc func(PacketAlert) bool

// ReadUntil reads packet alerts until the deadline has elapsed, calling
// `f` on each; read indefinitely if deadline is zero.
func (s *Session) ReadUntil(deadline time.Time, f PacketAlertFunc) error {
	// BUG(tqbf): voodoo; i have no idea if this matters
	s.conn.SetReadBuffer(4096)

	for {
		if !deadline.IsZero() {
			s.conn.SetReadDeadline(deadline)
		}
		ms, _, err := s.conn.Receive()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				// we're done reading
				return nil
			}

			return fmt.Errorf("recv: %w", err)
		}

		for _, m := range ms {
			if m.Header.Command != CMD_PACKET_ALERT {
				continue
			}

			pa, err := PacketAlertFromRaw(m.Data)
			if err != nil {
				return fmt.Errorf("parse alert packet: %w", err)
			}

			if !f(pa) {
				return nil
			}
		}
	}
}

// PacketAlert wraps the Netlink attributes parsed from a CMD_ALERT message
type PacketAlert struct {
	attrs map[int]interface{}
}

// PacketAlertFromRaw creates a PacketAlert from the raw bytes of a CMD_ALERT
// message.
func PacketAlertFromRaw(raw []byte) (PacketAlert, error) {
	attrs, err := decodeAlert(raw)
	if err != nil {
		return PacketAlert{}, fmt.Errorf("decode: %w", err)
	}

	return PacketAlert{
		attrs: attrs,
	}, nil
}

// Packet returns the (truncated) raw bytes of a dropped packet, starting
// from the link layer header (which is ethernet-y?).
func (pa *PacketAlert) Packet() []byte {
	payload, ok := pa.attrs[ATTR_PAYLOAD]
	if !ok {
		return nil
	}

	return payload.([]byte)
}

// L3Packet returns the (truncated) raw bytes of a dropped packet, skipping
// the link layer header (ie: starting at the IP header of an IP packet)
func (pa *PacketAlert) L3Packet() []byte {
	packet := pa.Packet()
	if len(packet) <= 14 {
		return nil
	}

	return packet[14:]
}

// Symbol returns the kernel function where this drop occurred, when available.
func (pa *PacketAlert) Symbol() string {
	sym, ok := pa.attrs[ATTR_SYMBOL]
	if !ok {
		return ""
	}

	return sym.(string)
}

// PC returns $RIP of the CPU when the drop occurred, for later resolution as a
// symbol.
func (pa *PacketAlert) PC() uint64 {
	pc, ok := pa.attrs[ATTR_PC]
	if !ok {
		return 0
	}

	return pc.(uint64)
}

// Proto returns the layer 3 protocol of the dropped packet.
func (pa *PacketAlert) Proto() uint16 {
	proto, ok := pa.attrs[ATTR_PROTO]
	if !ok {
		return 0
	}

	return proto.(uint16)
}

// Is4 is true if the dropped packet is an IPv4 packet.
func (pa *PacketAlert) Is4() bool {
	return pa.Proto() == 0x0800
}

// Is16 is true if the dropped packet is an IPv6 packet.
func (pa *PacketAlert) Is16() bool {
	return pa.Proto() == 0x86DD
}

// Length returns the original, non-truncated length of the dropped
// packet.
func (pa *PacketAlert) Length() uint32 {
	l, ok := pa.attrs[ATTR_ORIG_LEN]
	if !ok {
		return 0
	}

	return l.(uint32)
}

// Link returns the interface index on which the packet was dropped
func (pa *PacketAlert) Link() uint32 {
	l, ok := pa.attrs[ATTR_IN_PORT]
	if !ok {
		return 0
	}

	a := l.(map[int]interface{})
	lidx, ok := a[0]
	if !ok {
		return 0
	}

	return lidx.(uint32)
}
