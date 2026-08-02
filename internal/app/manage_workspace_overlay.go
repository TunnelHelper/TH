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

func (m *manageWorkspaceModel) beginInfo(title, description string, lines ...string) {
	m.overlay = &workspaceOverlay{
		Kind: workspaceOverlayInfo, Title: title, Description: description,
		Lines: append([]string(nil), lines...),
	}
}

func (m *manageWorkspaceModel) beginList(action, title, description, itemLabel string, items []string, itemValidator func(string) error, listValidator func([]string) error) {
	m.overlay = workspaceListOverlay(action, title, description, itemLabel, items, itemValidator, listValidator)
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
	if m.overlay != nil && (m.overlay.Kind == workspaceOverlayInput || m.overlay.Kind == workspaceOverlayList && m.overlay.Editing) {
		m.input.Width = max(12, min(76, m.width-6))
	}
}

func (m manageWorkspaceModel) updateOverlay(message tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := message.(tea.KeyMsg)
	if m.overlay.Kind == workspaceOverlayList {
		var event workspaceListEvent
		var command tea.Cmd
		m.input, command, event = workspaceUpdateListOverlay(m.overlay, m.input, message, m.width)
		switch event {
		case workspaceListCancel:
			m.overlay = nil
		case workspaceListApply:
			action := m.overlay.Action
			value := strings.Join(m.overlay.Items, ",")
			m.overlay = nil
			if err := m.applyWorkspaceInput(action, []string{value}); err != nil {
				m.err = err
			}
		}
		return m, command
	}
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
	if m.overlay.Kind == workspaceOverlayInfo {
		workspaceUpdateInfoOverlay(m.overlay, key, m.width, m.height)
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
		for _, line := range wrapDisplayText(m.overlay.Description, width) {
			lines = append(lines, workspaceDimStyle.Render(line))
		}
	}
	if m.overlay.Kind == workspaceOverlayInfo {
		return workspaceRenderInfoOverlay(m.overlay, lines, width, m.height)
	}
	if m.overlay.Kind == workspaceOverlayList {
		return workspaceRenderListOverlay(m.overlay, m.input, lines, width, m.height)
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

func workspaceUpdateInfoOverlay(overlay *workspaceOverlay, key tea.KeyMsg, width, height int) {
	lines := workspaceInfoLines(overlay, width)
	pageSize := workspaceInfoPageSize(height)
	maxOffset := max(0, len(lines)-pageSize)
	switch key.String() {
	case "up", "k":
		overlay.Offset = max(0, overlay.Offset-1)
	case "down", "j":
		overlay.Offset = min(maxOffset, overlay.Offset+1)
	case "pgup":
		overlay.Offset = max(0, overlay.Offset-pageSize)
	case "pgdown":
		overlay.Offset = min(maxOffset, overlay.Offset+pageSize)
	case "home":
		overlay.Offset = 0
	case "end":
		overlay.Offset = maxOffset
	}
}

func workspaceRenderInfoOverlay(overlay *workspaceOverlay, prefix []string, width, height int) string {
	content := workspaceInfoLines(overlay, width)
	pageSize := workspaceInfoPageSize(height)
	maxOffset := max(0, len(content)-pageSize)
	offset := min(overlay.Offset, maxOffset)
	end := min(len(content), offset+pageSize)
	lines := append([]string(nil), prefix...)
	if status := workspaceWindowStatus(offset, end, len(content), width); status != "" {
		lines = append(lines, status)
	}
	lines = append(lines, content[offset:end]...)
	lines = append(lines, workspaceHintLines(width, "up/down  Scroll", "pgup/pgdown  Page", "esc  Close")...)
	return strings.Join(lines, "\n")
}

func workspaceInfoLines(overlay *workspaceOverlay, width int) []string {
	var lines []string
	for _, value := range overlay.Lines {
		lines = append(lines, wrapDisplayText(value, width)...)
	}
	return lines
}

func workspaceInfoPageSize(height int) int {
	if height <= 0 {
		return 10
	}
	return max(3, min(12, height-8))
}

type workspaceListEvent uint8

const (
	workspaceListNoop workspaceListEvent = iota
	workspaceListCancel
	workspaceListApply
)

func workspaceListOverlay(action, title, description, itemLabel string, items []string, itemValidator func(string) error, listValidator func([]string) error) *workspaceOverlay {
	return &workspaceOverlay{
		Kind: workspaceOverlayList, Action: action, Title: title, Description: description,
		Items: append([]string(nil), items...), ItemLabel: itemLabel,
		ItemValidator: itemValidator, ListValidator: listValidator, EditIndex: -1,
	}
}

func workspaceUpdateListOverlay(overlay *workspaceOverlay, input textinput.Model, message tea.Msg, width int) (textinput.Model, tea.Cmd, workspaceListEvent) {
	key, isKey := message.(tea.KeyMsg)
	if overlay.Editing {
		if !isKey {
			var command tea.Cmd
			input, command = input.Update(message)
			return input, command, workspaceListNoop
		}
		switch key.String() {
		case "esc":
			overlay.Editing = false
			overlay.Err = nil
			return input, nil, workspaceListNoop
		case "enter":
			value := strings.TrimSpace(input.Value())
			if overlay.ItemValidator != nil {
				if err := overlay.ItemValidator(value); err != nil {
					overlay.Err = err
					return input, nil, workspaceListNoop
				}
			}
			for index, existing := range overlay.Items {
				if index != overlay.EditIndex && existing == value {
					overlay.Err = fmt.Errorf("%s is already present", value)
					return input, nil, workspaceListNoop
				}
			}
			if overlay.EditIndex >= 0 && overlay.EditIndex < len(overlay.Items) {
				overlay.Items[overlay.EditIndex] = value
				overlay.Selected = overlay.EditIndex
			} else {
				overlay.Items = append(overlay.Items, value)
				overlay.Selected = len(overlay.Items) - 1
			}
			overlay.Editing = false
			overlay.EditIndex = -1
			overlay.Err = nil
			return input, nil, workspaceListNoop
		default:
			overlay.Err = nil
			var command tea.Cmd
			input, command = input.Update(message)
			return input, command, workspaceListNoop
		}
	}
	if !isKey {
		return input, nil, workspaceListNoop
	}
	maximum := len(overlay.Items)
	overlay.Selected = min(overlay.Selected, maximum)
	switch key.String() {
	case "esc":
		return input, nil, workspaceListCancel
	case "up", "k":
		overlay.Selected = max(0, overlay.Selected-1)
	case "down", "j":
		overlay.Selected = min(maximum, overlay.Selected+1)
	case "a":
		overlay.Selected = maximum
		input = workspaceListInput(overlay, width, -1)
	case "enter", " ":
		editIndex := overlay.Selected
		if editIndex == maximum {
			editIndex = -1
		}
		input = workspaceListInput(overlay, width, editIndex)
	case "d":
		if overlay.Selected < len(overlay.Items) {
			overlay.Items = append(overlay.Items[:overlay.Selected], overlay.Items[overlay.Selected+1:]...)
			overlay.Selected = min(overlay.Selected, len(overlay.Items))
			overlay.Err = nil
		}
	case "s", "ctrl+s":
		if overlay.ListValidator != nil {
			if err := overlay.ListValidator(overlay.Items); err != nil {
				overlay.Err = err
				return input, nil, workspaceListNoop
			}
		}
		return input, nil, workspaceListApply
	}
	return input, nil, workspaceListNoop
}

func workspaceListInput(overlay *workspaceOverlay, width, editIndex int) textinput.Model {
	input := textinput.New()
	input.Prompt = "> "
	input.CharLimit = 8192
	input.Width = max(12, min(76, width-6))
	if editIndex >= 0 && editIndex < len(overlay.Items) {
		input.SetValue(overlay.Items[editIndex])
	}
	input.Focus()
	input.CursorEnd()
	overlay.Editing = true
	overlay.EditIndex = editIndex
	overlay.Err = nil
	return input
}

func workspaceRenderListOverlay(overlay *workspaceOverlay, input textinput.Model, prefix []string, width, height int) string {
	lines := append([]string(nil), prefix...)
	if overlay.Editing {
		label := overlay.ItemLabel
		if overlay.EditIndex >= 0 {
			label = "Edit " + strings.ToLower(label)
		} else {
			label = "Add " + strings.ToLower(label)
		}
		lines = append(lines, label, input.View())
		if overlay.Err != nil {
			lines = append(lines, workspaceErrorStyle.Render(fit(overlay.Err.Error(), width)))
		}
		lines = append(lines, workspaceHintLines(width, "enter  Keep item", "esc  Back to list")...)
		return strings.Join(lines, "\n")
	}
	total := len(overlay.Items) + 1
	pageSize := 8
	if height > 0 {
		pageSize = max(3, min(10, height-10))
	}
	start, end := workspaceVisibleRange(total, overlay.Selected, pageSize)
	if status := workspaceWindowStatus(start, end, total, width); status != "" {
		lines = append(lines, status)
	}
	for index := start; index < end; index++ {
		label := "+ Add " + strings.ToLower(overlay.ItemLabel)
		if index < len(overlay.Items) {
			label = overlay.Items[index]
		}
		marker := "  "
		if index == overlay.Selected {
			marker = "> "
			label = workspaceFocusStyle.Render(fit(marker+label, width))
		} else {
			label = fit(marker+label, width)
		}
		lines = append(lines, label)
	}
	if overlay.Err != nil {
		lines = append(lines, workspaceErrorStyle.Render(fit(overlay.Err.Error(), width)))
	}
	lines = append(lines, workspaceHintLines(width, "enter  Edit/add", "a  Add", "d  Remove", "s  Apply list", "esc  Cancel")...)
	return strings.Join(lines, "\n")
}

func renderWorkspaceButtons(buttons []workspaceButton, selected, width int) string {
	shared := make([]ui.Button, len(buttons))
	for index, button := range buttons {
		shared[index] = ui.Button{Label: button.Label, Destructive: button.Destructive}
	}
	return ui.RenderButtons(shared, selected, width)
}
