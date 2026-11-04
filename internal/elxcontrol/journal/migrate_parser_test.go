package journal

import (
	"strings"
	"testing"
)

func TestMigrationSplitterIgnoresCommentSemicolons(t *testing.T) {
	statements := splitSQLStatements(accountingAssignmentSchema)
	if len(statements) != 1 || !strings.Contains(statements[0], "CREATE TABLE elx_accounting_assignments") ||
		strings.Contains(statements[0], "the node must not") {
		t.Fatalf("accounting migration split incorrectly: %q", statements)
	}
}

func TestMigrationSplitterPreservesQuotedSemicolons(t *testing.T) {
	src := "-- leading; comment\nSELECT 'a; b' AS text; /* block; comment */ SELECT $$hello;world$$, \"with;semicolon\";\n-- trailing;"
	statements := splitSQLStatements(src)
	if len(statements) != 2 {
		t.Fatalf("got %d statements: %#v", len(statements), statements)
	}
	if !strings.Contains(statements[0], "'a; b'") ||
		!strings.Contains(statements[1], "$$hello;world$$") ||
		!strings.Contains(statements[1], "\"with;semicolon\"") {
		t.Fatalf("quoted SQL was split or corrupted: %#v", statements)
	}
}
