package sarif_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// staleNotification is the run-level notice the scan specification gives a catalog file
// older than the release embedded in the binary.
func staleNotification() sarif.Notification {
	return sarif.Notification{
		DescriptorID: "ctf.catalog.stale",
		Level:        ctfkit.LevelNote,
		Text:         "catalog 2026.1.0 (file) is older than the embedded release 2026.9.3",
	}
}

func notificationInput() sarif.Input {
	return sarif.Input{
		Tool:          sarif.Tool{Name: toolName, Version: toolVersion},
		Notifications: []sarif.Notification{staleNotification()},
	}
}

// A notification is a run-level toolExecutionNotifications entry on the one
// invocation, which SARIF requires to state whether execution succeeded. The
// renderer only runs for a completed analysis, so that is true.
func TestRenderToolExecutionNotification(t *testing.T) {
	data, err := sarif.Render(notificationInput())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	var doc struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful *bool `json:"executionSuccessful"`
				Notifications       []struct {
					Descriptor struct {
						ID string `json:"id"`
					} `json:"descriptor"`
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("want one run with one invocation, got %s", data)
	}
	inv := doc.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful == nil || !*inv.ExecutionSuccessful {
		t.Errorf("executionSuccessful = %v, want true", inv.ExecutionSuccessful)
	}
	if len(inv.Notifications) != 1 {
		t.Fatalf("want one notification, got %d", len(inv.Notifications))
	}
	n, want := inv.Notifications[0], staleNotification()
	if n.Descriptor.ID != want.DescriptorID || n.Level != want.Level || n.Message.Text != want.Text {
		t.Errorf("notification = %+v, want %+v", n, want)
	}
}

// Every golden predates notifications, so a run without one has to render the
// same bytes as before: no invocations key at all, not an empty one.
func TestRenderOmitsInvocationsWithoutNotifications(t *testing.T) {
	in := notificationInput()
	in.Notifications = nil

	data, err := sarif.Render(in)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if bytes.Contains(data, []byte(`"invocations"`)) {
		t.Errorf("a run with no notification wrote an invocations key:\n%s", data)
	}
}

// cff-1 does not type invocations yet, and its run object allows keys it does
// not list, so a document carrying one still validates.
func TestRenderNotificationValidatesAgainstSchema(t *testing.T) {
	data, err := sarif.Render(notificationInput())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := compileSchema(t).Validate(doc); err != nil {
		t.Errorf("a document with a notification does not validate against cff-1: %v", err)
	}
}

func TestRenderRejectsBadNotification(t *testing.T) {
	cases := map[string]sarif.Notification{
		"no descriptor id": {Level: ctfkit.LevelNote, Text: "x"},
		"unknown level":    {DescriptorID: "ctf.catalog.stale", Level: "fatal", Text: "x"},
		"no text":          {DescriptorID: "ctf.catalog.stale", Level: ctfkit.LevelNote},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			in := notificationInput()
			in.Notifications = []sarif.Notification{n}
			if _, err := sarif.Render(in); err == nil {
				t.Errorf("Render accepted a notification with %s", name)
			} else if !strings.Contains(err.Error(), "notification") {
				t.Errorf("error = %q, want it to name the notification", err)
			}
		})
	}
}
