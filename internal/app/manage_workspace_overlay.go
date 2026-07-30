package app

import (
	"fmt"
	"strings"

	"github.com/TunnelHelper/TH/internal/ui"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func (m *manageWorkspaceModel) beginInput(action, title, description string, steps ...workspaceInputStep) {
	values := make([]string, len(steps))
	for index := range steps {
		values[index] = steps[index].Value
	}
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayInput, Title: title, Description: description,
		Action: action, Steps: steps, Values: values,
	}
	m.configureInputStep()
}

func (m *manageWorkspaceModel) beginChoice(action, title, description string, buttons []workspaceButton, selected int) {
	if selected < 0 || selected >= len(buttons) {
		selected = 0
	}
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayChoice, Title: title, Description: description,
		Action: action, Buttons: buttons, Selected: selected,
	}
}

func (m *manageWorkspaceModel) beginConfirm(action, title, description, confirmLabel, cancelLabel string, destructive bool) {
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayConfirm, Title: title, Description: description,
		Action: action, Selected: 1,
		Buttons: []workspaceButton{
			{Label: confirmLabel, Value: "confirm", Destructive: destructive},
			{Label: cancelLabel, Value: "cancel"},
		},
	}
}

func (m *manageWorkspaceModel) configureInputStep() {
	if m.overlay == nil || m.overlay.Kind != workspaceOverlayInput || m.overlay.Step >= len(m.overlay.Steps) {
		return
	}
	step := m.overlay.Steps[m.overlay.Step]
	input := textinput.New()
	input.Prompt = "> "
	input.SetValue(m.overlay.Values[m.overlay.Step])
	input.CharLimit = 8192
	input.Width = max(12, min(76, m.width-6))
	if step.Secret {
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '*'
	}
	input.Focus()
	input.CursorEnd()
	m.input = input
}

func (m *manageWorkspaceModel) resizeInput() {
	if m.overlay != nil && m.overlay.Kind == workspaceOverlayInput {
		m.input.Width = max(12, min(76, m.width-6))
	}
}

func (m manageWorkspaceModel) updateOverlay(message tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := message.(tea.KeyMsg)
	if !isKey {
		if m.overlay.Kind == workspaceOverlayInput {
			var command tea.Cmd
			m.input, command = m.input.Update(message)
			return m, command
		}
		return m, nil
	}

	if key.String() == "esc" {
		m.overlay = nil
		return m, nil
	}
	if m.overlay.Kind == workspaceOverlayInput {
		if key.String() == "enter" {
			step := m.overlay.Steps[m.overlay.Step]
			value := m.input.Value()
			if step.Validator != nil {
				if err := step.Validator(value); err != nil {
					m.overlay.Err = err
					return m, nil
				}
			}
			m.overlay.Values[m.overlay.Step] = value
			if m.overlay.Step+1 < len(m.overlay.Steps) {
				m.overlay.Step++
				m.overlay.Err = nil
				m.configureInputStep()
				return m, nil
			}
			action, values := m.overlay.Action, append([]string(nil), m.overlay.Values...)
			m.overlay = nil
			if err := m.applyWorkspaceInput(action, values); err != nil {
				m.err = err
			}
			return m, nil
		}
		m.overlay.Err = nil
		var command tea.Cmd
		m.input, command = m.input.Update(message)
		return m, command
	}

	switch key.String() {
	case "left", "up", "shift+tab", "h", "k":
		if m.overlay.Selected > 0 {
			m.overlay.Selected--
		} else {
			m.overlay.Selected = len(m.overlay.Buttons) - 1
		}
	case "right", "down", "tab", "l", "j":
		if m.overlay.Selected+1 < len(m.overlay.Buttons) {
			m.overlay.Selected++
		} else {
			m.overlay.Selected = 0
		}
	case "enter", " ":
		action := m.overlay.Action
		value := m.overlay.Buttons[m.overlay.Selected].Value
		kind := m.overlay.Kind
		m.overlay = nil
		if kind == workspaceOverlayConfirm {
			if value == "cancel" {
				return m, nil
			}
			command, err := m.applyWorkspaceConfirm(action)
			if err != nil {
				m.err = err
			}
			return m, command
		}
		if err := m.applyWorkspaceChoice(action, value); err != nil {
			m.err = err
		}
	}
	return m, nil
}

func (m manageWorkspaceModel) overlayView(width int) string {
	if m.overlay == nil {
		return ""
	}
	lines := []string{workspaceAccentStyle.Render(fit(m.overlay.Title, width))}
	if m.overlay.Description != "" {
		lines = append(lines, workspaceDimStyle.Render(fit(m.overlay.Description, width)))
	}
	if m.overlay.Kind == workspaceOverlayInput {
		step := m.overlay.Steps[m.overlay.Step]
		label := step.Label
		if len(m.overlay.Steps) > 1 {
			label = fmt.Sprintf("%s  (%d/%d)", label, m.overlay.Step+1, len(m.overlay.Steps))
		}
		lines = append(lines, label, m.input.View())
		if m.overlay.Err != nil {
			lines = append(lines, workspaceErrorStyle.Render(fit(m.overlay.Err.Error(), width)))
		}
		lines = append(lines, workspaceHintLines(width, "enter  Apply", "esc  Cancel")...)
		return strings.Join(lines, "\n")
	}
	lines = append(lines, renderWorkspaceButtons(m.overlay.Buttons, m.overlay.Selected, width))
	if m.overlay.Err != nil {
		lines = append(lines, workspaceErrorStyle.Render(fit(m.overlay.Err.Error(), width)))
	}
	lines = append(lines, workspaceHintLines(width, "arrows/tab  Select", "enter  Apply", "esc  Cancel")...)
	return strings.Join(lines, "\n")
}

func renderWorkspaceButtons(buttons []workspaceButton, selected, width int) string {
	shared := make([]ui.Button, len(buttons))
	for index, button := range buttons {
		shared[index] = ui.Button{Label: button.Label, Destructive: button.Destructive}
	}
	return ui.RenderButtons(shared, selected, width)
}
