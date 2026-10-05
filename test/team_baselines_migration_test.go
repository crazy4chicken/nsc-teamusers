package test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"teamusers/migrations"
)

func TestTeamBaselineMigrationDownRequiresNoBaselineBindings(t *testing.T) {
	t.Run("empty rollback", func(t *testing.T) {
		database := newIntegrationDatabase(t)
		if err := downLatestIntegrationMigration(t, database); err != nil {
			t.Fatalf("roll back empty team-baseline migration: %v", err)
		}
		var hasTeamValue, hasBaselineIndex bool
		if err := database.pool.QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM pg_enum
				WHERE enumtypid = 'role_binding_subject_kind'::regtype AND enumlabel = 'team'
			)`).Scan(&hasTeamValue); err != nil {
			t.Fatalf("inspect subject-kind enum after empty rollback: %v", err)
		}
		if err := database.pool.QueryRow(context.Background(), `
			SELECT to_regclass('role_bindings_one_team_baseline_idx') IS NOT NULL`).Scan(&hasBaselineIndex); err != nil {
			t.Fatalf("inspect baseline index after empty rollback: %v", err)
		}
		if hasTeamValue || hasBaselineIndex {
			t.Fatalf("team baseline schema remains after empty rollback: team enum value=%t, unique index=%t", hasTeamValue, hasBaselineIndex)
		}
	})

	t.Run("refuses rollback with baseline", func(t *testing.T) {
		stack, _, adminToken := newAdminSession(t)
		team := createBaselineTestTeam(t, stack, adminToken, "baseline-down-refusal")
		role := createBaselineTestRole(t, stack, adminToken, "baseline-down-refusal", team.ID, []string{})
		status, body := stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
			"role_id": role.ID, "subject_kind": "team", "subject_id": team.ID,
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create baseline before rollback refusal = %d %s, want 201", status, body)
		}

		err := downLatestIntegrationMigration(t, stack.database)
		if err == nil || !strings.Contains(err.Error(), "cannot roll back team baseline migration while team baseline bindings remain") {
			t.Fatalf("rollback with baseline error = %v, want explicit baseline refusal", err)
		}
		var baselineCount int
		if err := stack.database.pool.QueryRow(context.Background(), `
			SELECT count(*) FROM role_bindings WHERE subject_kind = 'team' AND team_id = $1`, team.ID).Scan(&baselineCount); err != nil {
			t.Fatalf("count baseline after rollback refusal: %v", err)
		}
		if baselineCount != 1 {
			t.Fatalf("baseline count after rollback refusal = %d, want 1", baselineCount)
		}
	})
}

func downLatestIntegrationMigration(t *testing.T, database *integrationDatabase) error {
	t.Helper()
	migrationDB, err := goose.OpenDBWithDriver("pgx", database.connectionString)
	if err != nil {
		t.Fatalf("open migration database: %v", err)
		return err
	}
	defer migrationDB.Close()
	migrationDB.SetMaxOpenConns(1)
	migrationDB.SetMaxIdleConns(1)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set goose dialect: %v", err)
		return err
	}
	goose.SetBaseFS(migrations.FS)
	goose.SetVerbose(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return goose.DownContext(ctx, migrationDB, ".")
}
