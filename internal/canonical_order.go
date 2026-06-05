package internal

import (
	"bytes"
	"strings"
	"unicode"

	"github.com/miekg/dns"
)

// CanonicalDNSSECNameCompare orders owner names as specified by RFC 4034
// section 6.1: labels are compared from the root toward the leaf, and label
// octets are compared in canonical lowercase wire form.
func CanonicalDNSSECNameCompare(a, b string) int {
	aLabels := canonicalDNSSECOrderLabels(a)
	bLabels := canonicalDNSSECOrderLabels(b)

	limit := len(aLabels)
	if len(bLabels) < limit {
		limit = len(bLabels)
	}
	for i := 0; i < limit; i++ {
		if cmp := bytes.Compare(aLabels[i], bLabels[i]); cmp != 0 {
			if cmp < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(aLabels) < len(bLabels):
		return -1
	case len(aLabels) > len(bLabels):
		return 1
	default:
		return 0
	}
}

func canonicalDNSSECOrderLabels(name string) [][]byte {
	wire := canonicalDNSSECWireName(name)
	labels := wireLabels(wire)
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
}

func canonicalDNSSECWireName(name string) []byte {
	fqdn := canonicalDNSSECPresentationName(name)
	msg := make([]byte, 256)
	off, err := dns.PackDomainName(fqdn, msg, 0, nil, false)
	if err != nil {
		fqdn = dns.Fqdn(strings.ToLower(strings.TrimSpace(name)))
		off, err = dns.PackDomainName(fqdn, msg, 0, nil, false)
		if err != nil {
			return []byte{0}
		}
	}

	wire := append([]byte(nil), msg[:off]...)
	for i := 0; i < len(wire); {
		l := int(wire[i])
		if l == 0 {
			break
		}
		i++
		for j := 0; j < l && i+j < len(wire); j++ {
			if 'A' <= wire[i+j] && wire[i+j] <= 'Z' {
				wire[i+j] += 'a' - 'A'
			}
		}
		i += l
	}
	return wire
}

func canonicalDNSSECPresentationName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		return "."
	}

	absolute := strings.HasSuffix(name, ".")
	trimmed := strings.TrimSuffix(name, ".")
	labels := splitPresentationLabels(trimmed)
	for i, label := range labels {
		if label == "" || label == "*" || strings.Contains(label, `\`) {
			labels[i] = strings.ToLower(label)
			continue
		}
		labels[i] = dnssecLabelToASCII(label)
	}

	out := strings.Join(labels, ".")
	if absolute || out != "" {
		out = dns.Fqdn(out)
	}
	return out
}

func splitPresentationLabels(name string) []string {
	var labels []string
	var current strings.Builder
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch == '\\' {
			current.WriteByte(ch)
			if i+3 < len(name) && isDigit(name[i+1]) && isDigit(name[i+2]) && isDigit(name[i+3]) {
				current.WriteString(name[i+1 : i+4])
				i += 3
				continue
			}
			if i+1 < len(name) {
				i++
				current.WriteByte(name[i])
			}
			continue
		}
		if ch == '.' {
			labels = append(labels, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}
	labels = append(labels, current.String())
	return labels
}

func wireLabels(wire []byte) [][]byte {
	var labels [][]byte
	for i := 0; i < len(wire); {
		l := int(wire[i])
		if l == 0 {
			break
		}
		i++
		if i+l > len(wire) {
			break
		}
		labels = append(labels, append([]byte(nil), wire[i:i+l]...))
		i += l
	}
	return labels
}

func isDigit(b byte) bool {
	return '0' <= b && b <= '9'
}

func dnssecLabelToASCII(label string) string {
	if label == "" {
		return label
	}

	var mapped []rune
	asciiOnly := true
	for _, r := range label {
		lower := unicode.ToLower(r)
		if lower > 0x7f {
			asciiOnly = false
		}
		mapped = append(mapped, lower)
	}
	if asciiOnly {
		return string(mapped)
	}
	return "xn--" + punycodeEncode(mapped)
}

func punycodeEncode(input []rune) string {
	const (
		base        = 36
		tMin        = 1
		tMax        = 26
		skew        = 38
		damp        = 700
		initialBias = 72
		initialN    = 128
	)

	var out []byte
	for _, r := range input {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}

	basicLen := len(out)
	handled := basicLen
	if basicLen > 0 {
		out = append(out, '-')
	}

	n := initialN
	delta := 0
	bias := initialBias
	for handled < len(input) {
		m := int(^uint(0) >> 1)
		for _, r := range input {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}

		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range input {
			switch {
			case int(r) < n:
				delta++
			case int(r) == n:
				q := delta
				for k := base; ; k += base {
					t := k - bias
					if t < tMin {
						t = tMin
					} else if t > tMax {
						t = tMax
					}
					if q < t {
						break
					}
					out = append(out, encodeDigit(t+(q-t)%(base-t)))
					q = (q - t) / (base - t)
				}
				out = append(out, encodeDigit(q))
				bias = adaptPunycodeBias(delta, handled+1, handled == basicLen, base, tMin, tMax, skew, damp)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}

	return string(out)
}

func adaptPunycodeBias(delta, numPoints int, firstTime bool, base, tMin, tMax, skew, damp int) int {
	if firstTime {
		delta /= damp
	} else {
		delta /= 2
	}
	delta += delta / numPoints

	k := 0
	for delta > ((base-tMin)*tMax)/2 {
		delta /= base - tMin
		k += base
	}
	return k + (((base - tMin + 1) * delta) / (delta + skew))
}

func encodeDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
