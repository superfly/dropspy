package dropspy

import (
	"fmt"
	"log"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const (
	CMD_UNSPEC = iota
	CMD_ALERT
	CMD_CONFIG
	CMD_START
	CMD_STOP
	CMD_PACKET_ALERT
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
	ATTR_TRUNC_LEN          /* u32 */ // 9
	ATTR_ORIG_LEN           /* u32 */
	ATTR_QUEUE_LEN          /* u32 */
	ATTR_STATS              /* nested */
	ATTR_HW_STATS           /* nested */ // 13
	ATTR_ORIGIN             /* u16 */
	ATTR_HW_TRAP_GROUP_NAME /* string */
	ATTR_HW_TRAP_NAME       /* string */
	ATTR_HW_ENTRIES         /* nested */
	ATTR_HW_ENTRY           /* nested */ // 18
	ATTR_HW_TRAP_COUNT      /* u32 */
	ATTR_SW_DROPS           /* flag */
	ATTR_HW_DROPS           /* flag */
)

const (
	GRP_ALERT = 1

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

type Session struct {
	conn  *genetlink.Conn
	fam   uint16
	group uint32
}

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

	return ret, nil
}

func (s *Session) Config() (map[int]interface{}, error) {
	err := s.req(CMD_CONFIG_GET, nil)
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

func (s *Session) req(cmd uint8, data []byte) error {
	_, err := s.conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: cmd,
		},
		Data: data,
	}, s.fam, netlink.Request)
	return err
}

func (s *Session) Start(sw, hw bool) error {
	enc := netlink.NewAttributeEncoder()
	enc.Flag(ATTR_SW_DROPS, sw)
	enc.Flag(ATTR_HW_DROPS, hw)
	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return s.req(CMD_START, raw)
}

func (s *Session) Stop(sw, hw bool) error {
	enc := netlink.NewAttributeEncoder()
	enc.Flag(ATTR_SW_DROPS, sw)
	enc.Flag(ATTR_HW_DROPS, hw)
	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return s.req(CMD_STOP, raw)
}

func decodeAlert(raw []byte) (map[int]interface{}, error) {
	dec, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ret := map[int]interface{}{}

	for dec.Next() {
		log.Printf("%d %s", dec.Type(), dec.Err())

		switch dec.Type() {
		case ATTR_PC:
			ret[ATTR_PC] = dec.Uint64()
		case ATTR_SYMBOL:
			ret[ATTR_SYMBOL] = dec.String()
		case ATTR_IN_PORT:
			println("eep")
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
			ret[ATTR_TIMESTAMP] = dec.Uint64
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

	return ret, nil
}
