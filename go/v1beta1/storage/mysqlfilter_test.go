package storage_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/grafeas/grafeas/go/v1beta1/storage"
)

var myFilter storage.MysqlFilterSql

func TestParseFilter(t *testing.T) {
	filter := `note_name="test_note_1"`
	actual, args, err := myFilter.ParseFilter(filter, "")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expected := `(data->'$.note_name' = ?)`
	if actual != expected {
		t.Errorf("Expecting: " + expected + "\nGet: " + actual)
	}
	if !reflect.DeepEqual(args, []interface{}{"test_note_1"}) {
		t.Errorf("Expecting args [test_note_1], got: %v", args)
	}
	actual, args, err = myFilter.ParseFilter(filter, "o.")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expected = `(o.data->'$.note_name' = ?)`
	if actual != expected {
		t.Errorf("Expecting: " + expected + "\nGet: " + actual)
	}
	if !reflect.DeepEqual(args, []interface{}{"test_note_1"}) {
		t.Errorf("Expecting args [test_note_1], got: %v", args)
	}
}

func TestParseFilterKind(t *testing.T) {
	actual, args, err := myFilter.ParseFilter(`kind="VULNERABILITY"`, "")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expected := `(data->'$.kind' = 1)`
	if actual != expected {
		t.Errorf("Expecting: " + expected + "\nGet: " + actual)
	}
	if len(args) != 0 {
		t.Errorf("Expecting no args, got: %v", args)
	}
}

// TestParseFilterNoInjection makes sure that no part of a filter value ends up
// in the generated SQL text: values are only ever bound as parameters.
func TestParseFilterNoInjection(t *testing.T) {
	filters := []string{
		`note_name=="x\") OR 1=1 -- "`,
		`note_name=="x\" UNION SELECT name, name FROM projects -- "`,
		`note_name=="x'; DROP TABLE notes; -- "`,
	}
	for _, filter := range filters {
		sql, args, err := myFilter.ParseFilter(filter, "")
		if err != nil {
			// Rejecting the filter outright is also a safe outcome.
			continue
		}
		if sql != `(data->'$.note_name' = ?)` {
			t.Errorf("Filter %q produced unexpected SQL: %s", filter, sql)
		}
		for _, forbidden := range []string{"OR 1=1", "UNION", "DROP", "--", `"`} {
			if strings.Contains(sql, forbidden) {
				t.Errorf("Filter %q leaked %q into SQL: %s", filter, forbidden, sql)
			}
		}
		if len(args) != 1 {
			t.Errorf("Filter %q: expecting a single bound value, got: %v", filter, args)
		}
	}
}

// TestParseFilterRejectsFunctions makes sure unknown functions are not
// translated into raw SQL calls.
func TestParseFilterRejectsFunctions(t *testing.T) {
	for _, filter := range []string{`sleep(10)=1`, `note_name=load_file("/etc/passwd")`} {
		if sql, _, err := myFilter.ParseFilter(filter, ""); err == nil {
			t.Errorf("Expecting an error for filter %q, got SQL: %s", filter, sql)
		}
	}
}
