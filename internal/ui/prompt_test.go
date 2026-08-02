package ui

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestDecisionUsesSecondaryDefaultAndConsumesPendingText(t *testing.T) {
	output := &bytes.Buffer{}
	userInterface := New(output, output, strings.NewReader("\n"))
	userInterface.TTY = false
	userInterface.Title("Edit tunnel")
	userInterface.Dim("Review before saving")
	prompter := NewPrompter(userInterface)
	value := "discard"

	err := prompter.Decision("Tunnel changes",
		Option{Label: "Save changes", Value: "save"},
		Option{Label: "Discard changes", Value: "discard"},
		&value,
	)
	if err != nil {
		t.Fatal(err)
	}
	if value != "discard" {
		t.Fatalf("value = %q", value)
	}
	if userInterface.PendingTitle != "" || userInterface.PendingDim != "" {
		t.Fatal("pending prompt context was not consumed")
	}
	transcript := output.String()
	for _, expected := range []string{"Edit tunnel", "Review before saving", "Save changes", "Discard changes", "> [2]"} {
		if !strings.Contains(transcript, expected) {
			t.Fatalf("transcript does not contain %q:\n%s", expected, transcript)
		}
	}
}

func TestDecisionMapsPrimaryButton(t *testing.T) {
	output := &bytes.Buffer{}
	userInterface := New(output, output, strings.NewReader("1\n"))
	userInterface.TTY = false
	prompter := NewPrompter(userInterface)
	value := "cancel"

	err := prompter.Decision("Remove peer",
		Option{Label: "Remove peer", Value: "remove"},
		Option{Label: "Cancel", Value: "cancel"},
		&value,
	)
	if err != nil {
		t.Fatal(err)
	}
	if value != "remove" {
		t.Fatalf("value = %q", value)
	}
}

func TestDecisionRendersAndSubmitsInTTYMode(t *testing.T) {
	viewInterface := New(&bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""))
	viewInterface.TTY = true
	field := newSelectPrompt(viewInterface, promptDecision, "Tunnel changes", "",
		[]Option{
			Option{Label: "Save changes", Value: "save"},
			Option{Label: "Discard changes", Value: "discard"},
		},
		"save",
	)
	view := field.View()
	if !strings.Contains(view, "Save changes") || !strings.Contains(view, "Discard changes") {
		t.Fatalf("TTY decision did not render both buttons:\n%q", view)
	}

	output := &bytes.Buffer{}
	userInterface := New(output, output, strings.NewReader("\r"))
	userInterface.TTY = true
	prompter := NewPrompter(userInterface)
	value := "save"

	err := prompter.Decision("Tunnel changes",
		Option{Label: "Save changes", Value: "save"},
		Option{Label: "Discard changes", Value: "discard"},
		&value,
	)
	if err != nil {
		t.Fatal(err)
	}
	if value != "save" {
		t.Fatalf("value = %q", value)
	}
}

func TestPromptModelKeepsValidationErrorInline(t *testing.T) {
	userInterface := New(&bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""))
	userInterface.TTY = true
	model := newInputPrompt(userInterface, "Interface", "", "", false, func(value string) error {
		if value == "" {
			return errors.New("value is required")
		}
		return nil
	})

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := updated.(promptModel)
	if command != nil || result.done || result.err == nil || !strings.Contains(result.View(), "value is required") {
		t.Fatalf("invalid input should remain active: %+v", result)
	}
}

func TestPromptModelRendersFixedPrefixBeforeInput(t *testing.T) {
	userInterface := New(&bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""))
	userInterface.TTY = true
	model := newInputPromptWithPrefix(userInterface, "Tunnel name", "", "ipsec-", "edge", false, nil)

	if model.text.Prompt != "ipsec-" {
		t.Fatalf("input prompt = %q, want fixed interface prefix", model.text.Prompt)
	}
	if !strings.Contains(model.View(), "ipsec-") || !strings.Contains(model.View(), "edge") {
		t.Fatalf("fixed prefix and editable name were not rendered together:\n%s", model.View())
	}
	if model.text.Width != 74 {
		t.Fatalf("input width = %d, want terminal width minus prefix", model.text.Width)
	}
}

func TestPromptModelWarnsWhenPrefixAndInputExceedLimit(t *testing.T) {
	userInterface := New(&bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""))
	userInterface.TTY = true
	model := newInputPromptWithPrefixLimit(userInterface, "Tunnel name", "", "ipsec-", 15, "1234567890", false, nil)

	if model.warning == nil || !strings.Contains(model.warning.Error(), "16/15") {
		t.Fatalf("missing combined length warning: %v", model.warning)
	}
	if !strings.Contains(model.View(), "combined name exceeds 15 characters") {
		t.Fatalf("combined length warning was not rendered below input:\n%s", model.View())
	}
}

func TestPromptModelEscAborts(t *testing.T) {
	userInterface := New(&bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""))
	model := newSelectPrompt(userInterface, promptSelect, "Choose", "", []Option{{Label: "One", Value: "one"}}, "one")
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	result := updated.(promptModel)
	if command == nil || !result.aborted || result.done {
		t.Fatalf("escape state = %+v, command nil=%t", result, command == nil)
	}
}

func TestPromptSelectShowsAllOptionsWithoutWindow(t *testing.T) {
	userInterface := New(&bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""))
	options := make([]Option, 20)
	for index := range options {
		options[index] = Option{Label: "Option " + string(rune('A'+index)), Value: string(rune('a' + index))}
	}
	model := newSelectPrompt(userInterface, promptSelect, "Choose", "", options, options[10].Value)
	view := model.View()
	for _, label := range []string{"Option A", "Option K", "Option T"} {
		if !strings.Contains(view, label) {
			t.Fatalf("selection hides %q; all options must be rendered:\n%s", label, view)
		}
	}
	if strings.Contains(view, "more above") || strings.Contains(view, "more below") {
		t.Fatalf("selection still windows options behind a more-marker:\n%s", view)
	}
}

func TestRenderButtonsWrapsWithoutOverflow(t *testing.T) {
	buttons := []Button{{Label: "Save a very long configuration"}, {Label: "Discard changes"}}
	rendered := RenderButtons(buttons, 0, 18)
	if !strings.Contains(rendered, "\n") {
		t.Fatalf("narrow button group did not wrap: %q", rendered)
	}
	for _, line := range strings.Split(rendered, "\n") {
		if width := lipgloss.Width(line); width > 18 {
			t.Fatalf("button line is %d cells wide: %q", width, line)
		}
	}
}

func TestSliderAdjustsWithArrowKeys(t *testing.T) {
	userInterface := New(&bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""))
	userInterface.TTY = true
	model := newSliderPrompt(userInterface, "Balance", "", -1, 1, 0.1, 0,
		func(value float64) string { return "value=" + strconv.FormatFloat(value, 'g', -1, 64) })

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyLeft})
	result := updated.(promptModel)
	if result.sliderValue != -0.1 {
		t.Fatalf("left arrow must decrease the slider, got %v", result.sliderValue)
	}
	if !strings.Contains(result.View(), "value=-0.1") {
		t.Fatalf("slider view must render the position:\n%s", result.View())
	}

	updated, _ = result.Update(tea.KeyMsg{Type: tea.KeyRight})
	result = updated.(promptModel)
	if result.sliderValue != 0 {
		t.Fatalf("right arrow must increase the slider, got %v", result.sliderValue)
	}

	updated, command := result.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result = updated.(promptModel)
	if command == nil || !result.done || result.value != "0" {
		t.Fatalf("enter must confirm the slider value, got %q", result.value)
	}
}
