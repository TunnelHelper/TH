package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	ansi "github.com/charmbracelet/x/ansi"
)

// Button is the shared visual representation for mutually exclusive actions.
type Button struct {
	Label       string
	Destructive bool
}

var (
	buttonStyle            = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
	buttonDimStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	buttonFocusStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("6")).Bold(true)
	buttonDestructiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("1")).Bold(true)
)

// RenderButtons keeps actions on one row when possible and wraps only when the
// terminal is too narrow to contain the full button group.
func RenderButtons(buttons []Button, selected, width int) string {
	if len(buttons) == 0 {
		return ""
	}
	if selected < 0 || selected >= len(buttons) {
		selected = 0
	}
	rendered := make([]string, len(buttons))
	total := 0
	for index, button := range buttons {
		labelText := button.Label
		if width > 4 {
			labelText = ansi.Truncate(labelText, width-4, "...")
		}
		label := "[ " + labelText + " ]"
		if width > 0 && lipgloss.Width(label) > width {
			label = ansi.Truncate(label, width, "")
		}
		total += lipgloss.Width(label)
		if index > 0 {
			total += 2
		}
		style := buttonStyle
		if index != selected {
			style = buttonDimStyle
		} else if button.Destructive {
			style = buttonDestructiveStyle
		} else {
			style = buttonFocusStyle
		}
		rendered[index] = style.Render(label)
	}
	separator := "  "
	if width > 0 && total > width {
		separator = "\n"
	}
	return strings.Join(rendered, separator)
}
