package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ANSI styles. Disabled when NO_COLOR is set or output is not a terminal.
const (
	styleReset  = "\033[0m"
	styleBold   = "\033[1m"
	styleDim    = "\033[2m"
	styleRed    = "\033[31m"
	styleGreen  = "\033[32m"
	styleYellow = "\033[33m"
	styleCyan   = "\033[36m"
)

const timeLayout = "2006-01-02 15:04:05 MST"

type printer struct {
	w     io.Writer
	color bool
}

func newPrinter(w io.Writer, isTTY bool) *printer {
	_, noColor := os.LookupEnv("NO_COLOR")
	return &printer{w: w, color: isTTY && !noColor}
}

func (p *printer) paint(style, s string) string {
	if !p.color {
		return s
	}
	return style + s + styleReset
}

func (p *printer) println(format string, args ...any) {
	fmt.Fprintf(p.w, format+"\n", args...)
}

func (p *printer) success(format string, args ...any) {
	p.println("%s %s", p.paint(styleGreen, "✔"), fmt.Sprintf(format, args...))
}

func (p *printer) fail(format string, args ...any) {
	p.println("%s %s", p.paint(styleRed, "✖"), fmt.Sprintf(format, args...))
}

func (p *printer) warn(format string, args ...any) {
	p.println("%s %s", p.paint(styleYellow, "!"), fmt.Sprintf(format, args...))
}

func (p *printer) info(format string, args ...any) {
	p.println("%s", p.paint(styleDim, fmt.Sprintf(format, args...)))
}

// table prints aligned "label: value" rows.
func (p *printer) table(rows [][2]string) {
	width := 0
	for _, r := range rows {
		if len(r[0]) > width {
			width = len(r[0])
		}
	}
	for _, r := range rows {
		label := r[0] + ":" + strings.Repeat(" ", width-len(r[0]))
		p.println("  %s  %s", p.paint(styleBold, label), r[1])
	}
}

func formatTime(t time.Time) string {
	return t.Local().Format(timeLayout)
}

// humanDuration renders d rounded to seconds, e.g. "29m58s".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return d.Round(time.Second).String()
}

// groupSecret splits a base32 secret into blocks of 4 for easier typing.
func groupSecret(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
