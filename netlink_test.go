package dropspy

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/mdlayher/genetlink"
)

func TestHello(t *testing.T) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}

	fams, err := conn.ListFamilies()
	if err != nil {
		t.Fatalf("list: %s", err)
	}

	for _, fam := range fams {
		t.Logf("%+v", fam)
	}
}

func TestSession(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatalf("init: %s", err)
	}

	conf, err := s.Config()
	if err != nil {
		t.Fatalf("config: %s", err)
	}

	t.Logf("%+v", conf)
}

func TestWatch(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatalf("init: %s", err)
	}

	err = s.Start(true, false)
	if err != nil {
		t.Fatalf("start: %s", err)
	}

	defer func() {
		s.Stop(true, true)
	}()

	err = s.conn.JoinGroup(GRP_ALERT)
	if err != nil {
		t.Fatalf("join: %s", err)
	}

	deadline := time.Now().Add(5 * time.Second)

	for {
		s.conn.SetReadDeadline(deadline)
		ms, _, err := s.conn.Receive()
		if err != nil {
			t.Fatalf("recv: %s", err)
		}

		for _, m := range ms {
			t.Logf("%d\n%s", m.Header.Command, hex.Dump(m.Data))
			alert, err := decodeAlert(m.Data)
			if err != nil {
				t.Fatalf("decode: %s", err)
			}
			t.Logf("%+v", alert)
		}
	}
}
