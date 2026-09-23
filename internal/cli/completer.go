package cli

import "strings"

// completer offers tab completion for the first word of the line, limited
// to the commands valid in the current state (logged in or not).
type completer struct {
	app *App
}

// Do implements readline.AutoCompleter. It returns the missing suffixes of
// matching command names and the length of the prefix being completed.
func (c *completer) Do(line []rune, pos int) ([][]rune, int) {
	if c.app.inPrompt.Load() {
		return nil, 0 // don't complete command names into a password prompt
	}
	prefix := strings.TrimLeft(string(line[:pos]), " ")
	if strings.ContainsAny(prefix, " \t") {
		return nil, 0 // only the command itself is completed
	}
	var out [][]rune
	for _, cmd := range c.app.available() {
		if strings.HasPrefix(cmd.name, strings.ToLower(prefix)) {
			out = append(out, []rune(cmd.name[len(prefix):]+" "))
		}
	}
	return out, len([]rune(prefix))
}
