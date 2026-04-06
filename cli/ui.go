// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
)

const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cBlue    = "\033[34m"
	cMagenta = "\033[35m"
	cCyan    = "\033[36m"
	cWhite   = "\033[37m"
	cGray    = "\033[90m"

	panelW = 57
)

// ── Banner ──────────────────────────────────────────────

func uiBanner() {
	w := panelW
	line := strings.Repeat("━", w)
	fmt.Printf("%s┏%s┓%s\n", cMagenta, line, cReset)
	uiBannerLine("NSHUNTER — DNSSEC ZONE RECON", w)
	uiBannerLine("NSEC · NSEC3 · AXFR · Registries · Brute-force", w)
	fmt.Printf("%s┗%s┛%s\n", cMagenta, line, cReset)
	uiBannerLegal(w)
}

func uiBannerLegal(w int) {
	printCenteredDim(legalCopyright, w)
	printCenteredDim(legalSPDX, w)
}

func printCenteredDim(text string, w int) {
	tw := runewidth.StringWidth(text)
	pad := w - tw
	if pad < 0 {
		pad = 0
	}
	left := pad / 2
	right := pad - left
	fmt.Printf("%s%s%s%s%s\n", cDim, strings.Repeat(" ", left), text, strings.Repeat(" ", right), cReset)
}

func uiBannerLine(text string, w int) {
	textW := runewidth.StringWidth(text)
	pad := w - textW
	if pad < 0 {
		pad = 0
	}
	left := pad / 2
	right := pad - left
	fmt.Printf("%s┃%s%s%s%s%s%s┃%s\n",
		cMagenta, cReset,
		strings.Repeat(" ", left), cBold+cMagenta+text+cReset,
		strings.Repeat(" ", right),
		"", cMagenta, cReset)
}

// ── Tags (single-line output) ───────────────────────────

func uiTag(tag, msg string) {
	fmt.Printf(" %s►%s %s%-8s%s %s\n", cCyan, cReset, cCyan, tag, cReset, msg)
}

func uiTagWarn(tag, msg string) {
	fmt.Printf(" %s►%s %s%-8s%s %s\n", cYellow, cReset, cYellow, tag, cReset, msg)
}

func uiTagDanger(tag, msg string) {
	fmt.Printf(" %s►%s %s%-8s%s %s%s%s\n", cRed, cReset, cRed, tag, cReset, cRed, msg, cReset)
}

func uiTagOK(tag, msg string) {
	fmt.Printf(" %s✓%s %s%-8s%s %s\n", cGreen, cReset, cGreen, tag, cReset, msg)
}

func uiTagStar(tag, msg string) {
	fmt.Printf(" %s★%s %s%-8s%s %s\n", cYellow, cReset, cBold+cWhite, tag, cReset, msg)
}

func uiTagSuper(tag, msg string) {
	fmt.Printf(" %s⚡%s %s%-8s%s %s\n", cMagenta, cReset, cMagenta, tag, cReset, msg)
}

func uiTimer(msg string) {
	fmt.Printf(" %s⏱  %s%s\n", cGray, msg, cReset)
}

// ── Phase separators ────────────────────────────────────

func uiPhase(title string) {
	fill := panelW - len(title) - 3
	if fill < 4 {
		fill = 4
	}
	fmt.Printf("\n%s── %s %s%s\n\n", cDim, title, strings.Repeat("─", fill), cReset)
}

// ── Panel (box with key-value rows) ─────────────────────

func uiPanelOpen(title string) {
	// Inner width is panelW (between ┌ and ┐). Prefix "── %s " uses 4 + len(title) cells before the rule.
	fill := panelW - len(title) - 4
	if fill < 0 {
		fill = 0
	}
	fmt.Printf("%s┌── %s %s┐%s\n", cBlue, title, strings.Repeat("─", fill), cReset)
}

func uiPanelSep(title string) {
	fill := panelW - len(title) - 4
	if fill < 0 {
		fill = 0
	}
	fmt.Printf("%s├── %s %s┤%s\n", cBlue, title, strings.Repeat("─", fill), cReset)
}

func uiPanelClose() {
	fmt.Printf("%s└%s┘%s\n", cBlue, strings.Repeat("─", panelW), cReset)
}

// stripANSI removes terminal escape sequences so display width matches padding.
func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func visibleWidth(s string) int {
	return runewidth.StringWidth(stripANSI(s))
}

func uiPanelRow(key, value string) {
	inner := panelW - 2
	const keyCols = 18

	k := key
	if visibleWidth(k) > keyCols {
		k = truncateToDisplayWidth(k, keyCols-runewidth.StringWidth("…")) + "…"
	}
	keyPart := k
	padKey := keyCols - visibleWidth(keyPart)
	if padKey < 0 {
		padKey = 0
	}
	keyField := keyPart + strings.Repeat(" ", padKey)

	v := value
	maxVal := inner - 1 - keyCols
	if maxVal < 3 {
		maxVal = 3
	}
	if visibleWidth(v) > maxVal {
		v = truncateToDisplayWidth(v, maxVal-runewidth.StringWidth("…")) + "…"
	}

	line := keyField + " " + v
	pad := inner - visibleWidth(line)
	if pad < 0 {
		pad = 0
	}

	fmt.Printf("%s│%s %s%s %s│%s\n", cBlue, cReset, line, strings.Repeat(" ", pad), cBlue, cReset)
}

// truncateToDisplayWidth returns a prefix of s whose visible width (excluding ANSI) is ≤ maxCells.
func truncateToDisplayWidth(s string, maxCells int) string {
	if maxCells <= 0 {
		return ""
	}
	if runewidth.StringWidth(stripANSI(s)) <= maxCells {
		return s
	}
	var b strings.Builder
	cells := 0
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				b.WriteString(s[i : j+1])
				i = j + 1
				continue
			}
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && sz == 1 {
			if cells+1 > maxCells {
				break
			}
			b.WriteByte(s[i])
			cells++
			i++
			continue
		}
		w := runewidth.RuneWidth(r)
		if cells+w > maxCells {
			break
		}
		b.WriteString(s[i : i+sz])
		cells += w
		i += sz
	}
	return b.String()
}

func uiPanelRowToggle(key string, on bool) {
	// ASCII only (no U+2713/U+2717): width is identical in all terminals.
	if on {
		uiPanelRow(key, cGreen+"[ON]"+cReset)
	} else {
		uiPanelRow(key, cRed+"[OFF]"+cReset)
	}
}
