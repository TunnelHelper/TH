package ui

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

type Prompter struct {
	ui  *UI
	out io.Writer
}

func NewPrompter(ui *UI) *Prompter {
	return &Prompter{ui: ui, out: ui.Out}
}

func (p *Prompter) newForm(groups ...*huh.Group) *huh.Form {
	keymap := huh.NewDefaultKeyMap()
	keymap.Quit.SetKeys("ctrl+c", "ctrl+z")
	return huh.NewForm(groups...).WithKeyMap(keymap)
}

type Option struct {
	Label  string
	Value  string
	Dimmed bool
}

func (p *Prompter) Select(title string, options []Option, value *string) error {
	if p.ui.TTY {
		huhOptions := make([]huh.Option[string], 0, len(options))
		for _, opt := range options {
			label := opt.Label
			if opt.Dimmed {
				label = p.ui.dim.Render(label)
			}
			huhOptions = append(huhOptions, huh.NewOption(label, opt.Value))
		}
		sel := huh.NewSelect[string]().Title(title).Options(huhOptions...).Value(value)
		if p.ui.PendingTitle != "" {
			sel.Title(p.ui.PendingTitle + "\n" + title)
			if p.ui.PendingDim != "" {
				sel.Description(p.ui.PendingDim)
			}
			p.ui.PendingTitle = ""
			p.ui.PendingDim = ""
		}
		return p.newForm(huh.NewGroup(sel)).Run()
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
	if p.ui.TTY {
		input := huh.NewInput().Title(title).Value(value)
		if p.ui.PendingTitle != "" {
			input.Title(p.ui.PendingTitle + "\n" + title)
			if p.ui.PendingDim != "" {
				input.Description(p.ui.PendingDim)
			}
			p.ui.PendingTitle = ""
			p.ui.PendingDim = ""
		}
		if validate != nil {
			input = input.Validate(func(s string) error { return validate(strings.TrimSpace(s)) })
		}
		return p.newForm(huh.NewGroup(input)).Run()
	}

	p.printPending()
	prompt := title
	if strings.TrimSpace(*value) != "" {
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

func (p *Prompter) Secret(title string, value *string, validate func(string) error) error {
	if p.ui.TTY {
		input := huh.NewInput().Title(title).Value(value).EchoMode(huh.EchoModePassword)
		if p.ui.PendingTitle != "" {
			input.Title(p.ui.PendingTitle + "\n" + title)
			if p.ui.PendingDim != "" {
				input.Description(p.ui.PendingDim)
			}
			p.ui.PendingTitle = ""
			p.ui.PendingDim = ""
		}
		if validate != nil {
			input = input.Validate(func(s string) error { return validate(strings.TrimSpace(s)) })
		}
		return p.newForm(huh.NewGroup(input)).Run()
	}
	p.printPending()
	fmt.Fprintf(p.out, "%s: ", title)
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

func (p *Prompter) Confirm(title string, value *bool, defaultYes bool) error {
	if p.ui.TTY {
		c := huh.NewConfirm().Title(title).Value(value)
		c = c.Affirmative("Yes").Negative("No")
		if p.ui.PendingTitle != "" {
			c.Title(p.ui.PendingTitle + "\n" + title)
			if p.ui.PendingDim != "" {
				c.Description(p.ui.PendingDim)
			}
			p.ui.PendingTitle = ""
			p.ui.PendingDim = ""
		}
		return p.newForm(huh.NewGroup(c)).Run()
	}

	p.printPending()
	def := "y/N"
	if defaultYes {
		def = "Y/n"
	}
	fmt.Fprintf(p.out, "%s (%s): ", title, def)
	line, err := p.ui.ReadLine()
	if err != nil {
		return err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		*value = defaultYes
		return nil
	}
	if line == "y" || line == "yes" {
		*value = true
		return nil
	}
	if line == "n" || line == "no" {
		*value = false
		return nil
	}
	return errors.New("invalid confirmation")
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
