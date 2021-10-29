package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/superfly/dropspy"
)

type filter struct {
	ifaces     map[uint32]bool
	min, max   uint
	xSym, iSym []*regexp.Regexp
	bpf        *pcap.BPF
}

func (f *filter) Match(pa *dropspy.PacketAlert) bool {
	if len(f.ifaces) > 0 {
		if !f.ifaces[pa.Link()] {
			return false
		}
	}

	plen := uint(pa.Length())

	if f.min != 0 && plen < f.min {
		return false
	}

	if f.max != 0 && plen > f.max {
		return false
	}

	sym := pa.Symbol()

	if len(f.xSym) != 0 {
		for _, rx := range f.xSym {
			if rx.MatchString(sym) {
				return false
			}
		}
	}

	if len(f.iSym) != 0 {
		for _, rx := range f.iSym {
			if !rx.MatchString(sym) {
				return false
			}
		}
	}

	if f.bpf != nil {
		packet := pa.Packet()

		ci := gopacket.CaptureInfo{
			CaptureLength: len(packet),
			Length:        int(plen),
		}

		if !f.bpf.Matches(ci, packet) {
			return false
		}
	}

	return true
}

type sliceArg []string

func (sa *sliceArg) String() string {
	return strings.Join([]string(*sa), ",")
}

func (sa *sliceArg) Set(arg string) error {
	*sa = append(*sa, arg)
	return nil
}

var (
	packetModeTruncation int = 100
)

func main() {
	var (
		printHex bool
		ifaces   sliceArg
		xsyms    sliceArg
		isyms    sliceArg
		maxDrops uint64
		timeout  string
		hw, sw   bool

		filter filter

		err error
	)

	flag.Var(&ifaces, "iface", "show only drops on this interface (may be repeated)")
	flag.Var(&xsyms, "xsym", "exclude drops from syms matching regexp (may be repeated)")
	flag.Var(&isyms, "isym", "include drops from syms matching regexp (may be repeated)")
	flag.UintVar(&filter.min, "minlen", 0, "minimum packet length for drops")
	flag.UintVar(&filter.max, "maxlen", 0, "maximum packet length for drops")
	flag.Uint64Var(&maxDrops, "count", 0, "maximum drops to record")
	flag.StringVar(&timeout, "timeout", "", "duration to capture for (300ms, 2h15m, &c)")
	flag.BoolVar(&hw, "hw", true, "record hardware drops")
	flag.BoolVar(&sw, "sw", true, "record software drops")
	flag.BoolVar(&printHex, "hex", false, "print hex dumps of matching packets")

	flag.Parse()

	pcapExpr := strings.Join(flag.Args(), " ")
	if pcapExpr != "" {
		filter.bpf, err = pcap.NewBPF(layers.LinkTypeEthernet, packetModeTruncation, pcapExpr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcap expression: %s\n", err)
			os.Exit(1)
		}
	}

	if len([]string(xsyms)) > 0 && len([]string(isyms)) > 0 {
		fmt.Fprintf(os.Stderr, "-xsym and -isym are mutually exclusive\n")
		os.Exit(1)
	}

	for _, symexpr := range []string(xsyms) {
		rx, err := regexp.Compile(symexpr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "regexp compile %s: %s\n", symexpr, err)
			os.Exit(1)
		}

		filter.xSym = append(filter.xSym, rx)
	}

	for _, symexpr := range []string(isyms) {
		rx, err := regexp.Compile(symexpr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "regexp compile %s: %s\n", symexpr, err)
			os.Exit(1)
		}

		filter.iSym = append(filter.iSym, rx)
	}

	links, err := dropspy.LinkList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "retrieve links: %s\n", err)
		os.Exit(1)
	}

	filter.ifaces = map[uint32]bool{}

	for _, iface := range []string(ifaces) {
		var rx *regexp.Regexp

		if strings.HasPrefix(iface, "/") && strings.HasSuffix(iface, "/") {
			rx, err = regexp.Compile(iface[1 : len(iface)-2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "compile interface regexp for %s: %s\n", iface[1:len(iface)-2], err)
				os.Exit(1)
			}
		} else {
			rx, err = regexp.Compile("^" + iface + "$")
			if err != nil {
				fmt.Fprintf(os.Stderr, "compile interface regexp for %s: %s\n", iface, err)
				os.Exit(1)
			}
		}

		found := false
		for k, v := range links {
			if v == iface {
				if rx.MatchString(v) {
					filter.ifaces[k] = true
					found = true
					break
				}
			}
		}

		if !found {
			fmt.Fprintf(os.Stderr, "no such interface '%s'\n", iface)
			os.Exit(1)
		}
	}

	session, err := dropspy.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to drop_mon: %s\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		_ = <-sigCh
		fmt.Fprintf(os.Stderr, "got C-c: cleaning up and exiting\n")
		session.Stop(true, true)
		os.Exit(1)
	}()

	defer func() {
		session.Stop(true, true)
	}()

	session.Stop(true, true)

	err = session.Start(sw, hw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enable drop_mon alerts: %s\n", err)
		os.Exit(1)
	}

	var deadline time.Time

	if timeout != "" {
		dur, err := time.ParseDuration(timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't parse timeout: %s\n", err)
			os.Exit(1)
		}

		deadline = time.Now().Add(dur)
	}

	dropCount := uint64(0)

	for {
		err = session.ReadUntil(deadline, func(pa dropspy.PacketAlert) bool {
			if filter.Match(&pa) {
				dropCount += 1

				log.Printf("drop on iface:%s at %s:%016x", links[pa.Link()], pa.Symbol(), pa.PC())
				if printHex {
					fmt.Println(hex.Dump(pa.L3Packet()))
				}

				if maxDrops != 0 && dropCount == maxDrops {
					fmt.Fprintf(os.Stderr, "maximum drops reached, exiting\n")
					return false
				}
			}

			return true
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "read: %s\n", err)
			time.Sleep(250 * time.Millisecond)
		} else {
			return
		}
	}
}
