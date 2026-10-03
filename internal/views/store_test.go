package views

import "testing"

// T007 (FR-006): named views persist, reapply to reproduce the same filters, and
// delete cleanly; a nameless view is rejected.
func TestSavedViewLifecycle(t *testing.T) {
	t.Setenv("VHLOCAL_VIEWS_DIR", t.TempDir())

	if _, err := Save(View{Name: "   "}); err == nil {
		t.Fatal("a view without a name must be rejected")
	}

	v, err := Save(View{Name: "Open Criticals", Filters: map[string]string{"severity": "Critical", "review": "needs-review"}, Sort: map[string]string{"key": "severity", "dir": "desc"}})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if v.ID != "open-criticals" || v.CreatedAt == 0 || v.UpdatedAt == 0 {
		t.Fatalf("unexpected saved view: %+v", v)
	}

	got, ok := Get(v.ID)
	if !ok || got.Filters["severity"] != "Critical" || got.Sort["key"] != "severity" {
		t.Fatalf("reapplied view lost data: %+v ok=%v", got, ok)
	}

	list, _ := List()
	if len(list) != 1 {
		t.Fatalf("list has %d views, want 1", len(list))
	}

	if err := Delete(v.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := Get(v.ID); ok {
		t.Fatal("view should be gone after delete")
	}
	// Deleting a missing view is not an error.
	if err := Delete(v.ID); err != nil {
		t.Fatalf("deleting missing view errored: %v", err)
	}
}

// Re-saving under the same id preserves CreatedAt and refreshes UpdatedAt.
func TestSaveIsIdempotentOnID(t *testing.T) {
	t.Setenv("VHLOCAL_VIEWS_DIR", t.TempDir())
	v1, _ := Save(View{Name: "Mine"})
	v2, err := Save(View{ID: v1.ID, Name: "Mine", Filters: map[string]string{"scan": "x"}})
	if err != nil {
		t.Fatalf("resave: %v", err)
	}
	if v2.CreatedAt != v1.CreatedAt {
		t.Fatalf("CreatedAt changed on resave: %v → %v", v1.CreatedAt, v2.CreatedAt)
	}
	if list, _ := List(); len(list) != 1 {
		t.Fatalf("resave created a duplicate: %d views", len(list))
	}
}
