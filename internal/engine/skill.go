package engine

import (
	"os"
	"path/filepath"

	"vhlocal/internal/phases"
)

// DirSkill loads the methodology from a real directory (--skill-dir): SKILL.md
// for the preamble and phases/<file> for each phase prompt.
type DirSkill struct{ Dir string }

func (d DirSkill) Preamble() string {
	b, err := os.ReadFile(filepath.Join(d.Dir, "SKILL.md"))
	if err != nil {
		return ""
	}
	return phases.LoadPreamble(string(b))
}

func (d DirSkill) Prompt(file string) (string, error) {
	b, err := os.ReadFile(filepath.Join(d.Dir, "phases", file))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
