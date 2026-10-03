package phases

import "testing"

func TestNormalizeText(t *testing.T) {
	nbHyphen := string(rune(0x2011)) // NON-BREAKING HYPHEN (the partition bug)
	emDash := string(rune(0x2014))
	enDash := string(rune(0x2013))
	minus := string(rune(0x2212))
	nbsp := string(rune(0x00A0))
	narrowNbsp := string(rune(0x202F))
	lq := string(rune(0x2018))
	rq := string(rune(0x2019))
	ldq := string(rune(0x201C))
	rdq := string(rune(0x201D))

	cases := []struct{ in, want string }{
		{"", ""},
		{"plain ASCII - stays", "plain ASCII - stays"},
		{"SG" + nbHyphen + "1", "SG-1"},
		{"em" + emDash + "and" + enDash + "dash", "em-and-dash"},
		{"minus" + minus + "sign", "minus-sign"},
		{"nbsp" + nbsp + "here", "nbsp here"},
		{"narrow" + narrowNbsp + "space", "narrow space"},
		{lq + "q" + rq + " " + ldq + "d" + rdq, "'q' \"d\""},
	}
	for _, c := range cases {
		if got := NormalizeText(c.in); got != c.want {
			t.Errorf("NormalizeText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeTextEnablesPartitionMatch(t *testing.T) {
	raw := "| SG" + string(rune(0x2011)) + "1 | auth subsystem |"
	if got := NormalizeText(raw); got != "| SG-1 | auth subsystem |" {
		t.Fatalf("normalized = %q", got)
	}
}
