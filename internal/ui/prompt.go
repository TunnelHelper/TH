package ui

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var ErrUserAborted = errors.New("user aborted")

type Prompter struct {
	ui  *UI
	out io.Writer
}

func NewPrompter(ui *UI) *Prompter {
	return &Prompter{ui: ui, out: ui.Out}
}

type Option struct {
	Label       string
	Value       string
	Dimmed      bool
	Destructive bool
}

type promptKind uint8

const (
	promptSelect promptKind = iota
	promptInput
	promptDecision
)

const promptMaxVisibleOptions = 10

type promptModel struct {
	ui          *UI
	kind        promptKind
	title       string
	description string
	options     []Option
	selected    int
	text        textinput.Model
	validate    func(string) error
	value       string
	err         error
	width       int
	done        bool
	aborted     bool
}

func newSelectPrompt(output *UI, kind promptKind, title, description string, options []Option, value string) promptModel {
	selected := 0
	for index := range options {
		if options[index].Value == value {
			selected = index
			break
		}
	}
	return promptModel{
		ui: output, kind: kind, title: title, description: description,
		options: append([]Option(nil), options...), selected: selected, width: 80,
	}
}

func newInputPrompt(output *UI, title, description, value string, secret bool, validate func(string) error) promptModel {
	input := textinput.New()
	input.Prompt = "> "
	input.PromptStyle = output.head
	input.TextStyle = output.info
	input.PlaceholderStyle = output.dim
	input.Cursor.Style = output.ok
	input.Width = 76
	input.SetValue(value)
	input.CursorEnd()
	if secret {
		input.EchoMode = textinput.EchoPassword
	}
	_ = input.Focus()
	return promptModel{
		ui: output, kind: promptInput, title: title, description: description,
		text: input, validate: validate, value: value, width: 80,
	}
}

func (m promptModel) Init() tea.Cmd {
	if m.kind == promptInput {
		return textinput.Blink
	}
	return nil
}

func (m promptModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if size, ok := message.(tea.WindowSizeMsg); ok {
		m.width = max(20, size.Width)
		if m.kind == promptInput {
			m.text.Width = max(10, m.width-2)
		}
		return m, nil
	}
	key, ok := message.(tea.KeyMsg)
	if !ok {
		if m.kind == promptInput {
			var command tea.Cmd
			m.text, command = m.text.Update(message)
			return m, command
		}
		return m, nil
	}
	switch key.String() {
	case "ctrl+c", "ctrl+z", "esc":
		m.aborted = true
		m.text.Blur()
		return m, tea.Quit
	}

	if m.kind == promptInput {
		if key.String() == "enter" {
			value := strings.TrimSpace(m.text.Value())
			if m.validate != nil {
				if err := m.validate(value); err != nil {
					m.err = err
					return m, nil
				}
			}
			m.value = value
			m.done = true
			m.text.Blur()
			return m, tea.Quit
		}
		m.err = nil
		var command tea.Cmd
		m.text, command = m.text.Update(message)
		return m, command
	}

	if len(m.options) == 0 {
		return m, nil
	}
	switch key.String() {
	case "up", "left", "k", "shift+tab":
		m.selected = (m.selected - 1 + len(m.options)) % len(m.options)
	case "down", "right", "j", "tab":
		m.selected = (m.selected + 1) % len(m.options)
	case "home":
		m.selected = 0
	case "end":
		m.selected = len(m.options) - 1
	case "enter", " ":
		m.value = m.options[m.selected].Value
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func (m promptModel) View() string {
	width := max(20, m.width)
	lines := make([]string, 0, 14)
	for _, line := range strings.Split(m.title, "\n") {
		lines = append(lines, m.ui.head.Render(fitPrompt(line, width)))
	}
	if m.description != "" {
		lines = append(lines, m.ui.dim.Render(fitPrompt(m.description, width)))
	}

	switch m.kind {
	case promptInput:
		lines = append(lines, m.text.View())
	case promptDecision:
		buttons := make([]Button, len(m.options))
		for index, option := range m.options {
			buttons[index] = Button{Label: option.Label, Destructive: option.Destructive}
		}
		lines = append(lines, RenderButtons(buttons, m.selected, width))
	default:
		start, end := promptVisibleRange(len(m.options), m.selected)
		if start > 0 {
			lines = append(lines, m.ui.dim.Render(fmt.Sprintf("  %d more above", start)))
		}
		for index := start; index < end; index++ {
			marker := "  "
			style := lipgloss.NewStyle()
			if m.options[index].Dimmed {
				style = m.ui.dim
			}
			if index == m.selected {
				marker = "> "
				style = m.ui.ok.Copy().Bold(true)
			}
			lines = append(lines, style.Render(fitPrompt(marker+m.options[index].Label, width)))
		}
		if end < len(m.options) {
			lines = append(lines, m.ui.dim.Render(fmt.Sprintf("  %d more below", len(m.options)-end)))
		}
	}

	if m.err != nil {
		lines = append(lines, m.ui.err.Render(fitPrompt(m.err.Error(), width)))
	}
	if !m.done && !m.aborted {
		hint := "arrows/tab  Select    enter  Apply    esc  Cancel"
		if m.kind == promptInput {
			hint = "enter  Apply    esc  Cancel"
		}
		lines = append(lines, m.ui.dim.Render(fitPrompt(hint, width)))
	}
	return strings.Join(lines, "\n")
}

func promptVisibleRange(length, selected int) (int, int) {
	if length <= promptMaxVisibleOptions {
		return 0, length
	}
	start := selected - promptMaxVisibleOptions/2
	if start < 0 {
		start = 0
	}
	if start+promptMaxVisibleOptions > length {
		start = length - promptMaxVisibleOptions
	}
	return start, start + promptMaxVisibleOptions
}

func fitPrompt(value string, width int) string {
	if width <= 0 || lipgloss.Width(value) <= width {
		return value
	}
	return lipgloss.NewStyle().MaxWidth(width).Render(value)
}

func (p *Prompter) run(model promptModel) (promptModel, error) {
	program := tea.NewProgram(model,
		tea.WithInput(p.ui.Input),
		tea.WithOutput(p.out),
	)
	final, err := program.Run()
	if err != nil {
		return model, err
	}
	result, ok := final.(promptModel)
	if !ok {
		return model, errors.New("unexpected prompt state")
	}
	if result.aborted {
		return result, ErrUserAborted
	}
	if !result.done {
		return result, ErrUserAborted
	}
	return result, nil
}

func (p *Prompter) Select(title string, options []Option, value *string) error {
	if value == nil || len(options) == 0 {
		return errors.New("invalid selection configuration")
	}
	if p.ui.TTY {
		fieldTitle, description := p.consumePending(title)
		result, err := p.run(newSelectPrompt(p.ui, promptSelect, fieldTitle, description, options, *value))
		if err != nil {
			return err
		}
		*value = result.value
		return nil
	}

	p.printPending()
	fmt.Fprintln(p.out, title)
	for i, opt := range options {
		fmt.Fprintf(p.out, "  %d) %s\n", i+1, opt.Label)
	}
	fmt.Fprint(p.out, "> ")
	line, err := p.ui.ReadLine()
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return errors.New("no selection")
	}
	i, err := strconv.Atoi(line)
	if err != nil || i < 1 || i > len(options) {
		return errors.New("invalid selection")
	}
	*value = options[i-1].Value
	return nil
}

func (p *Prompter) Input(title string, value *string, validate func(string) error) error {
	return p.input(title, value, false, validate)
}

func (p *Prompter) Secret(title string, value *string, validate func(string) error) error {
	return p.input(title, value, true, validate)
}

func (p *Prompter) input(title string, value *string, secret bool, validate func(string) error) error {
	if value == nil {
		return errors.New("invalid input configuration")
	}
	if p.ui.TTY {
		fieldTitle, description := p.consumePending(title)
		result, err := p.run(newInputPrompt(p.ui, fieldTitle, description, *value, secret, validate))
		if err != nil {
			return err
		}
		*value = result.value
		return nil
	}

	p.printPending()
	prompt := title
	if !secret && strings.TrimSpace(*value) != "" {
		prompt = fmt.Sprintf("%s [%s]", title, *value)
	}
	fmt.Fprintf(p.out, "%s: ", prompt)
	line, err := p.ui.ReadLine()
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		line = strings.TrimSpace(*value)
	}
	if validate != nil {
		if err := validate(line); err != nil {
			return err
		}
	}
	*value = line
	return nil
}

// Decision renders two mutually exclusive actions as horizontal buttons.
func (p *Prompter) Decision(title string, primary, secondary Option, value *string) error {
	if value == nil || strings.TrimSpace(primary.Label) == "" || strings.TrimSpace(secondary.Label) == "" ||
		primary.Value == secondary.Value || (primary.Value != *value && secondary.Value != *value) {
		return errors.New("invalid decision configuration")
	}
	if p.ui.TTY {
		fieldTitle, description := p.consumePending(title)
		result, err := p.run(newSelectPrompt(p.ui, promptDecision, fieldTitle, description, []Option{primary, secondary}, *value))
		if err != nil {
			return err
		}
		*value = result.value
		return nil
	}

	p.printPending()
	fmt.Fprintln(p.out, title)
	fmt.Fprintf(p.out, "  1) %s\n  2) %s\n", primary.Label, secondary.Label)
	defaultChoice := 1
	if *value == secondary.Value {
		defaultChoice = 2
	}
	fmt.Fprintf(p.out, "> [%d] ", defaultChoice)
	line, err := p.ui.ReadLine()
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		line = strconv.Itoa(defaultChoice)
	}
	switch line {
	case "1":
		*value = primary.Value
	case "2":
		*value = secondary.Value
	default:
		return errors.New("invalid decision")
	}
	return nil
}

func (p *Prompter) consumePending(title string) (string, string) {
	if p.ui.PendingTitle != "" {
		title = p.ui.PendingTitle + "\n" + title
	}
	description := p.ui.PendingDim
	p.ui.PendingTitle = ""
	p.ui.PendingDim = ""
	return title, description
}

func (p *Prompter) printPending() {
	if p.ui.PendingTitle != "" {
		fmt.Fprintln(p.out, p.ui.PendingTitle)
	}
	if p.ui.PendingDim != "" {
		fmt.Fprintln(p.out, p.ui.PendingDim)
	}
	p.ui.PendingTitle = ""
	p.ui.PendingDim = ""
}
