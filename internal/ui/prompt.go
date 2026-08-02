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
	Disabled    bool
	Destructive bool
}

type promptKind uint8

const (
	promptSelect promptKind = iota
	promptInput
	promptDecision
	promptSlider
)

type promptModel struct {
	ui           *UI
	kind         promptKind
	title        string
	description  string
	options      []Option
	selected     int
	text         textinput.Model
	validate     func(string) error
	liveValidate func(string) error
	value        string
	err          error
	warning      error
	hint         string
	width        int
	done         bool
	aborted      bool

	sliderValue  float64
	sliderMin    float64
	sliderMax    float64
	sliderStep   float64
	sliderRender func(float64) string
}

func newSelectPrompt(output *UI, kind promptKind, title, description string, options []Option, value string) promptModel {
	selected := 0
	for index := range options {
		if options[index].Value == value {
			selected = index
			break
		}
	}
	if len(options) > 0 && options[selected].Disabled {
		for index := range options {
			if !options[index].Disabled {
				selected = index
				break
			}
		}
	}
	return promptModel{
		ui: output, kind: kind, title: title, description: description,
		options: append([]Option(nil), options...), selected: selected, width: 80,
		hint: "arrows/tab  Select    enter  Apply    esc  Cancel",
	}
}

func newSliderPrompt(output *UI, title, description string, min, max, step float64, value float64, render func(float64) string) promptModel {
	return promptModel{
		ui: output, kind: promptSlider, title: title, description: description,
		sliderValue: value, sliderMin: min, sliderMax: max, sliderStep: step,
		sliderRender: render, value: strconv.FormatFloat(value, 'g', -1, 64), width: 80,
	}
}

func newInputPrompt(output *UI, title, description, value string, secret bool, validate func(string) error) promptModel {
	return newInputPromptWithPrefix(output, title, description, "", value, secret, validate)
}

func newInputPromptWithPrefix(output *UI, title, description, prefix, value string, secret bool, validate func(string) error) promptModel {
	return newInputPromptWithPrefixLimit(output, title, description, prefix, 0, value, secret, validate)
}

func newInputPromptWithPrefixLimit(output *UI, title, description, prefix string, maxTotal int, value string, secret bool, validate func(string) error) promptModel {
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
	if prefix != "" {
		input.Prompt = prefix
		input.PromptStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("4")).
			Bold(true)
	}
	_ = input.Focus()
	model := promptModel{
		ui: output, kind: promptInput, title: title, description: description,
		text: input, validate: validate, value: value, width: 80,
	}
	if maxTotal > 0 {
		model.liveValidate = func(value string) error {
			total := len(prefix) + len(value)
			if total > maxTotal {
				return fmt.Errorf("combined name exceeds %d characters (%d/%d)", maxTotal, total, maxTotal)
			}
			return nil
		}
	}
	model.resizeInput()
	model.refreshWarning()
	return model
}

func (m *promptModel) resizeInput() {
	width := m.width - lipgloss.Width(m.text.Prompt)
	if width < 1 {
		width = 1
	}
	m.text.Width = width
}

func (m *promptModel) refreshWarning() {
	m.warning = nil
	if m.liveValidate != nil {
		m.warning = m.liveValidate(m.text.Value())
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
			m.resizeInput()
		}
		return m, nil
	}
	key, ok := message.(tea.KeyMsg)
	if !ok {
		if m.kind == promptInput {
			var command tea.Cmd
			m.text, command = m.text.Update(message)
			m.refreshWarning()
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
					m.warning = nil
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
		m.refreshWarning()
		return m, command
	}

	if m.kind == promptSlider {
		switch key.String() {
		case "left", "down", "h", "j":
			m.sliderValue -= m.sliderStep
		case "right", "up", "l", "k":
			m.sliderValue += m.sliderStep
		case "home":
			m.sliderValue = m.sliderMin
		case "end":
			m.sliderValue = m.sliderMax
		case "enter", " ":
			m.value = strconv.FormatFloat(m.sliderValue, 'g', -1, 64)
			m.done = true
			return m, tea.Quit
		}
		if m.sliderValue < m.sliderMin {
			m.sliderValue = m.sliderMin
		}
		if m.sliderValue > m.sliderMax {
			m.sliderValue = m.sliderMax
		}
		return m, nil
	}

	if len(m.options) == 0 {
		return m, nil
	}
	switch key.String() {
	case "up", "left", "k", "shift+tab":
		m.moveSelection(-1)
	case "down", "right", "j", "tab":
		m.moveSelection(1)
	case "home":
		m.selectBoundary(0, 1)
	case "end":
		m.selectBoundary(len(m.options)-1, -1)
	case "enter", " ":
		if m.options[m.selected].Disabled {
			return m, nil
		}
		m.value = m.options[m.selected].Value
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func (m *promptModel) moveSelection(direction int) {
	if len(m.options) == 0 {
		return
	}
	for step := 1; step <= len(m.options); step++ {
		index := (m.selected + direction*step) % len(m.options)
		if index < 0 {
			index += len(m.options)
		}
		if !m.options[index].Disabled {
			m.selected = index
			return
		}
	}
}

func (m *promptModel) selectBoundary(index, direction int) {
	for index >= 0 && index < len(m.options) {
		if !m.options[index].Disabled {
			m.selected = index
			return
		}
		index += direction
	}
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
	case promptSlider:
		if m.sliderRender != nil {
			lines = append(lines, m.sliderRender(m.sliderValue))
		}
	default:
		for index := range m.options {
			marker := "  "
			style := lipgloss.NewStyle()
			if m.options[index].Dimmed || m.options[index].Disabled {
				style = m.ui.dim
			}
			if index == m.selected {
				marker = "> "
				style = m.ui.ok.Copy().Bold(true)
			}
			lines = append(lines, style.Render(fitPrompt(marker+m.options[index].Label, width)))
		}
	}

	if m.err != nil {
		lines = append(lines, m.ui.err.Render(fitPrompt(m.err.Error(), width)))
	} else if m.warning != nil {
		lines = append(lines, m.ui.warn.Render(fitPrompt(m.warning.Error(), width)))
	}
	if !m.done && !m.aborted {
		hint := m.hint
		if m.kind == promptInput {
			hint = "enter  Apply    esc  Cancel"
		} else if m.kind == promptSlider {
			hint = "← →  Adjust    enter  Apply    esc  Cancel"
		}
		lines = append(lines, m.ui.dim.Render(fitPrompt(hint, width)))
	}
	return strings.Join(lines, "\n")
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
	return p.SelectWithHint(title, options, value, "")
}

// SelectWithHint is Select with a custom footer hint line. An empty hint
// falls back to the default navigation hint.
func (p *Prompter) SelectWithHint(title string, options []Option, value *string, hint string) error {
	if value == nil || len(options) == 0 {
		return errors.New("invalid selection configuration")
	}
	if p.ui.TTY {
		fieldTitle, description := p.consumePending(title)
		model := newSelectPrompt(p.ui, promptSelect, fieldTitle, description, options, *value)
		if hint != "" {
			model.hint = hint
		}
		result, err := p.run(model)
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
	if options[i-1].Disabled {
		return errors.New("selection is unavailable")
	}
	*value = options[i-1].Value
	return nil
}

// Slider asks for a bounded floating-point value adjusted with the left and
// right arrow keys. render is used to draw the current position.
func (p *Prompter) Slider(title string, min, max, step float64, value *float64, render func(float64) string) error {
	if value == nil || min > max || step <= 0 {
		return errors.New("invalid slider configuration")
	}
	if p.ui.TTY {
		fieldTitle, description := p.consumePending(title)
		result, err := p.run(newSliderPrompt(p.ui, fieldTitle, description, min, max, step, *value, render))
		if err != nil {
			return err
		}
		parsed, err := strconv.ParseFloat(result.value, 64)
		if err != nil {
			return err
		}
		*value = parsed
		return nil
	}

	p.printPending()
	fmt.Fprintln(p.out, title)
	fmt.Fprintf(p.out, "  value (%.1f - %.1f, default %.1f)> ", min, max, *value)
	line, err := p.ui.ReadLine()
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	parsed, err := strconv.ParseFloat(line, 64)
	if err != nil || parsed < min || parsed > max {
		return errors.New("invalid value")
	}
	*value = parsed
	return nil
}

func (p *Prompter) Input(title string, value *string, validate func(string) error) error {
	return p.input(title, "", 0, value, false, validate)
}

// InputWithPrefix renders a fixed prefix directly before the editable input.
func (p *Prompter) InputWithPrefix(title, prefix string, value *string, validate func(string) error) error {
	return p.input(title, prefix, 0, value, false, validate)
}

// InputWithPrefixLimit renders a fixed prefix and warns when their combined
// value exceeds maxTotal. The supplied validator still controls submission.
func (p *Prompter) InputWithPrefixLimit(title, prefix string, maxTotal int, value *string, validate func(string) error) error {
	return p.input(title, prefix, maxTotal, value, false, validate)
}

func (p *Prompter) Secret(title string, value *string, validate func(string) error) error {
	return p.input(title, "", 0, value, true, validate)
}

func (p *Prompter) input(title, prefix string, maxTotal int, value *string, secret bool, validate func(string) error) error {
	if value == nil {
		return errors.New("invalid input configuration")
	}
	if p.ui.TTY {
		fieldTitle, description := p.consumePending(title)
		result, err := p.run(newInputPromptWithPrefixLimit(p.ui, fieldTitle, description, prefix, maxTotal, *value, secret, validate))
		if err != nil {
			return err
		}
		*value = result.value
		return nil
	}

	p.printPending()
	prompt := title
	if prefix != "" {
		prompt = fmt.Sprintf("%s (interface: %s<name>)", title, prefix)
	}
	if !secret && strings.TrimSpace(*value) != "" {
		prompt = fmt.Sprintf("%s [%s]", prompt, *value)
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
