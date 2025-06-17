package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	cmd := exec.Command("go", "tool", "cover", "-func=coverage.out")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to run go tool cover: %v", err)
	}

	var pct float64
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "total:") {
			parts := strings.Fields(line)
			if len(parts) < 3 {
				log.Fatalf("unexpected total line format: %q", line)
			}
			percentStr := strings.TrimSuffix(parts[len(parts)-1], "%")
			pct, err = strconv.ParseFloat(percentStr, 64)
			if err != nil {
				log.Fatalf("failed to parse coverage percent: %v", err)
			}
			break
		}
	}
	if pct == 0 {
		log.Fatalf("could not find total coverage percent")
	}

	color := "#e05d44" // red
	switch {
	case pct > 90:
		color = "#4c1"
	case pct > 75:
		color = "#97CA00"
	case pct > 55:
		color = "#dfb317"
	}

	svg := fmt.Sprintf(`
<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20">
  <linearGradient id="b" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="130" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <rect width="70" height="20" fill="#555"/>
    <rect x="70" width="60" height="20" fill="%s"/>
    <rect width="130" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle"
     font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="35" y="14">coverage</text>
    <text x="99" y="14">%.1f%%</text>
  </g>
</svg>
`, color, pct)

	if err := os.WriteFile("docs/images/coverage_badge.svg", []byte(strings.TrimSpace(svg)), 0644); err != nil {
		log.Fatalf("failed to write badge.svg: %v", err)
	}

	fmt.Printf("✅ Coverage badge generated: %.1f%%\n", pct)
}
