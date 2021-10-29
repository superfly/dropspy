# dropspy

dropspy is a (POC-quality) reworking of the C-language `dropwatch` tool in Go, with some extra features.

This is currently potato code and I make no promises that it works at all.

## Installation

```bash
git clone https://github.com/superfly/dropspy.git
cd dropspy
go install ./cmd/dropspy
```

## Usage

```bash
Usage of ./dropspy:
  -count uint
    	maximum drops to record
  -hw
    	record hardware drops (default true)
  -iface value
    	show only drops on this interface (may be repeated)
  -isym value
    	include drops from syms matching regexp (may be repeated)
  -maxlen uint
    	maximum packet length for drops
  -minlen uint
    	minimum packet length for drops
  -sw
    	record software drops (default true)
  -timeout string
    	duration to capture for (300ms, 2h15m, &c)
  -xsym value
    	exclude drops from syms matching regexp (may be repeated)
```

## License
[MIT](https://choosealicense.com/licenses/mit/)
