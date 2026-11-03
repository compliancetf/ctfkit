package verdict

import "testing"

func TestPlanFormatAllowed(t *testing.T) {
	for v, want := range map[string]bool{"1.2": true, "1.1": false, "1.3": false, "2.0": false, "": false, "1.2.0": false} {
		if got := PlanFormatAllowed(v); got != want {
			t.Errorf("PlanFormatAllowed(%q) = %v, want %v", v, got, want)
		}
	}
}
