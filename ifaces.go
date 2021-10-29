package dropspy

import (
	"fmt"

	"github.com/jsimonetti/rtnetlink"
)

func LinkList() (map[uint32]string, error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("link list: %w", err)
	}
	defer conn.Close()

	msg, err := conn.Link.List()
	if err != nil {
		return nil, fmt.Errorf("link list: %w", err)
	}

	ret := map[uint32]string{}

	for _, link := range msg {
		ret[link.Index] = link.Attributes.Name
	}

	return ret, nil
}
