package maven

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// IsSnapshot reports whether v is a SNAPSHOT version.
func IsSnapshot(v string) bool { return strings.HasSuffix(v, snapshotSfx) }

// Timestamped is a deployed SNAPSHOT version such as "1.0-20261123.101010-3".
type Timestamped struct {
	Base      string // "1.0"
	Timestamp string // "20261123.101010"
	Build     int    // 3
}

var timestampedRE = regexp.MustCompile(`^(.+)-(\d{8}\.\d{6})-(\d+)$`)

// ParseTimestamped splits a timestamped SNAPSHOT version into its parts.
func ParseTimestamped(v string) (Timestamped, bool) {
	m := timestampedRE.FindStringSubmatch(v)
	if m == nil {
		return Timestamped{}, false
	}
	build, err := strconv.Atoi(m[3])
	if err != nil {
		return Timestamped{}, false
	}
	return Timestamped{Base: m[1], Timestamp: m[2], Build: build}, true
}

// CompareVersions orders Maven versions as
// org.apache.maven.artifact.versioning.ComparableVersion (Maven 3.10) does,
// returning -1, 0 or 1. Only ASCII letters are case-folded and only ASCII
// digits form numbers; tspackages accepts only printable ASCII versions.
func CompareVersions(a, b string) int {
	return sign(parseVersion(a).compare(parseVersion(b)))
}

func sign(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	}
	return 0
}

type itemKind int

const (
	itemNumber itemKind = iota
	itemString
	itemList
)

// Number sizes, in ComparableVersion's order: IntItem < LongItem <
// BigIntegerItem whatever the values.
const (
	sizeInt = iota
	sizeLong
	sizeBig
)

// qualifiers are the known string items in ascending order; "" is a release.
var qualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

var qualifierAliases = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}

// releaseIndex is comparableQualifier("").
var releaseIndex = comparableQualifier("")

type item struct {
	kind itemKind
	num  string // itemNumber: decimal digits without leading zeros ("0" for zero)
	size int    // itemNumber: sizeInt, sizeLong or sizeBig
	str  string // itemString: the qualifier after aliasing
	list []*item
}

var zeroItem = &item{kind: itemNumber, num: "0", size: sizeInt}

func newNumber(digits string) *item {
	// ComparableVersion strips leading zeros but keeps an all-zero string
	// whole, and picks the item type from the remaining length.
	stripped := strings.TrimLeft(digits, "0")
	if stripped == "" {
		stripped = digits
	}
	size := sizeBig
	switch {
	case len(stripped) <= 9:
		size = sizeInt
	case len(stripped) <= 18:
		size = sizeLong
	}
	num := strings.TrimLeft(stripped, "0")
	if num == "" {
		num = "0"
	}
	return &item{kind: itemNumber, num: num, size: size}
}

func newString(s string, followedByDigit bool) *item {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	if alias, ok := qualifierAliases[s]; ok {
		s = alias
	}
	return &item{kind: itemString, str: s}
}

func parseItem(isDigit bool, s string) *item {
	if isDigit {
		return newNumber(s)
	}
	return newString(s, false)
}

func comparableQualifier(q string) string {
	if i := slices.Index(qualifiers, q); i >= 0 {
		return strconv.Itoa(i)
	}
	return strconv.Itoa(len(qualifiers)) + "-" + q
}

func (it *item) isNull() bool {
	switch it.kind {
	case itemNumber:
		return it.num == "0"
	case itemString:
		return comparableQualifier(it.str) == releaseIndex
	default:
		return len(it.list) == 0
	}
}

// normalize removes trailing null items, looking past nested lists.
func (it *item) normalize() {
	for i, last := range slices.Backward(it.list) {
		if last.isNull() {
			it.list = slices.Delete(it.list, i, i+1)
		} else if last.kind != itemList {
			break
		}
	}
}

// compare orders it against o; a nil o is the padding of a shorter list.
func (it *item) compare(o *item) int {
	switch it.kind {
	case itemNumber:
		if o == nil {
			if it.num == "0" {
				return 0
			}
			return 1
		}
		switch o.kind {
		case itemNumber:
			if it.size != o.size {
				return it.size - o.size
			}
			if len(it.num) != len(o.num) {
				return len(it.num) - len(o.num)
			}
			return strings.Compare(it.num, o.num)
		default:
			return 1 // 1.1 > 1-sp, 1.1 > 1-1
		}
	case itemString:
		if o == nil {
			return strings.Compare(comparableQualifier(it.str), releaseIndex)
		}
		if o.kind == itemString {
			return strings.Compare(comparableQualifier(it.str), comparableQualifier(o.str))
		}
		return -1 // 1.any < 1.1, 1.any < 1-1
	default:
		if o == nil {
			for _, i := range it.list {
				if c := i.compare(nil); c != 0 {
					return c
				}
			}
			return 0
		}
		switch o.kind {
		case itemNumber:
			return -1 // 1-1 < 1.0.x
		case itemString:
			return 1 // 1-1 > 1-sp
		default:
			for i := 0; i < len(it.list) || i < len(o.list); i++ {
				var c int
				switch {
				case i >= len(it.list):
					c = -o.list[i].compare(nil)
				case i >= len(o.list):
					c = it.list[i].compare(nil)
				default:
					c = it.list[i].compare(o.list[i])
				}
				if c != 0 {
					return c
				}
			}
			return 0
		}
	}
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// parseVersion is ComparableVersion.parseVersion.
func parseVersion(version string) *item {
	version = asciiLower(version)
	root := &item{kind: itemList}
	list := root
	stack := []*item{root}
	push := func() {
		next := &item{kind: itemList}
		list.list = append(list.list, next)
		list = next
		stack = append(stack, next)
	}
	digit := false
	start := 0
	for i := 0; i < len(version); i++ {
		c := version[i]
		switch {
		case c == '.' || c == '-':
			if i == start {
				list.list = append(list.list, zeroItem)
			} else {
				list.list = append(list.list, parseItem(digit, version[start:i]))
			}
			start = i + 1
			if c == '-' {
				push()
			}
		case isDigit(c):
			if !digit && i > start {
				// 1.0.0.X1 < 1.0.0-X2: treat .X as -X for any string qualifier X.
				if len(list.list) > 0 {
					push()
				}
				list.list = append(list.list, newString(version[start:i], true))
				start = i
				push()
			}
			digit = true
		default:
			if digit && i > start {
				list.list = append(list.list, parseItem(true, version[start:i]))
				start = i
				push()
			}
			digit = false
		}
	}
	if len(version) > start {
		if !digit && len(list.list) > 0 {
			push()
		}
		list.list = append(list.list, parseItem(digit, version[start:]))
	}
	for _, l := range slices.Backward(stack) {
		l.normalize()
	}
	return root
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
