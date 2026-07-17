package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
)

type UI struct {
	Out          io.Writer
	Err          io.Writer
	Input        io.Reader
	TTY          bool
	In           *bufio.Reader
	info         lipgloss.Style
	warn         lipgloss.Style
	ok           lipgloss.Style
	err          lipgloss.Style
	head         lipgloss.Style
	dim          lipgloss.Style
	PendingTitle string
	PendingDim   string
}

func New(out, err io.Writer, in io.Reader) *UI {
	u := &UI{
		Out:   out,
		Err:   err,
		Input: in,
		TTY:   isatty.IsTerminal(1),
		In:    bufio.NewReader(in),
	}

	u.info = lipgloss.NewStyle().Foreground(lipgloss.Color("4")).Bold(true)
	u.warn = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	u.ok = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	u.err = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	u.head = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	u.dim = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	if !u.TTY {
		u.info = lipgloss.NewStyle()
		u.warn = lipgloss.NewStyle()
		u.ok = lipgloss.NewStyle()
		u.err = lipgloss.NewStyle()
		u.head = lipgloss.NewStyle()
		u.dim = lipgloss.NewStyle()
	}

	return u
}

func (u *UI) HR() {
	fmt.Fprintln(u.Out, u.dim.Render(strings.Repeat("-", 60)))
}

func (u *UI) Title(s string) {
	u.PendingTitle = s
}

func (u *UI) Dim(s string) {
	u.PendingDim = s
}

func (u *UI) Clear() {
	// 由 huh 自动处理渲染周期
}

func (u *UI) ClearLines(n int) {
	// 废弃
}

func (u *UI) Info(s string) {
	fmt.Fprintf(u.Out, "%s %s\n", u.info.Render("[INFO]"), s)
}

func (u *UI) Warn(s string) {
	fmt.Fprintf(u.Out, "%s %s\n", u.warn.Render("[WARN]"), s)
}

func (u *UI) Ok(s string) {
	fmt.Fprintf(u.Out, "%s %s\n", u.ok.Render("[OK]"), s)
}

func (u *UI) Error(s string) {
	fmt.Fprintf(u.Err, "%s %s\n", u.err.Render("[ERR]"), s)
}

func (u *UI) ReadLine() (string, error) {
	line, err := u.In.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
