package domain

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestScopeRank(t *testing.T) {
	if !(ScopeRank("own") > ScopeRank("team") && ScopeRank("team") > ScopeRank("any") && ScopeRank("any") > ScopeRank("*")) {
		t.Fatalf("scope ranks do not reflect own > team > any > *")
	}
	if got := ScopeRank("invalid"); got >= ScopeRank("*") {
		t.Fatalf("ScopeRank(invalid) = %d, want below wildcard rank", got)
	}
}

func TestResolvePrecedence(t *testing.T) {
	grants := []Permission{
		{Resource: "orders", Action: "read", Scope: "*"},
		{Resource: "orders", Action: "read", Scope: "any"},
		{Resource: "orders", Action: "read", Scope: "team"},
		{Resource: "orders", Action: "read", Scope: "own"},
		{Resource: "orders", Action: "delete", Scope: "*"},
		{Resource: "orders", Action: "*", Scope: "team"},
		{Resource: "orders", Action: "read", Scope: "team", Deny: true},
		{Resource: "orders", Action: "read", Scope: "*", Deny: true},
	}
	requests := []Permission{
		{Resource: "orders", Action: "read", Scope: "own"},
		{Resource: "orders", Action: "read", Scope: "team"},
		{Resource: "orders", Action: "read", Scope: "any"},
		{Resource: "orders", Action: "delete", Scope: "own"},
	}

	resolved := Resolve(grants, requests)
	if resolved[0].Allowed || !resolved[0].Denied || resolved[0].Grant.Scope != "*" {
		t.Fatalf("explicit deny should beat narrower allow = %#v", resolved[0])
	}
	if resolved[1].Allowed || !resolved[1].Denied || resolved[1].Grant.Scope != "team" {
		t.Fatalf("explicit team deny = %#v, want denied", resolved[1])
	}
	if resolved[2].Allowed || !resolved[2].Denied || resolved[2].Grant.Scope != "*" {
		t.Fatalf("wildcard deny should match any scope = %#v", resolved[2])
	}
	if !resolved[3].Allowed || resolved[3].Grant.Action != "delete" {
		t.Fatalf("unrelated deny should not affect delete = %#v", resolved[3])
	}
}

func TestCompileAndEvalCondition(t *testing.T) {
	condition, err := Compile(`subject.id == "u-1" && resource.team_id == "t-1" && resource.attrs["tier"] == "gold"`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	values := Context{
		Subject:  Subject{ID: "u-1", Kind: "user"},
		Resource: Resource{OwnerID: "u-2", TeamID: "t-1", Attrs: map[string]any{"tier": "gold"}},
		Request:  Request{Time: time.Now()},
	}
	got, err := condition.Eval(values)
	if err != nil {
		t.Fatalf("Eval() error = %v", err)
	}
	if !got {
		t.Fatal("Eval() = false, want true")
	}

	empty, err := Compile(" \n\t")
	if err != nil {
		t.Fatalf("Compile(empty) error = %v", err)
	}
	got, err = empty.Eval(Context{})
	if err != nil || !got {
		t.Fatalf("empty Eval() = (%v, %v), want (true, nil)", got, err)
	}

	for _, source := range []string{
		`env("HOME") == "x"`,
		`os.Getenv("HOME") == "x"`,
		`$env["subject"] != nil`,
		`timezone("UTC") != nil`,
	} {
		if _, err := Compile(source); err == nil {
			t.Fatalf("Compile(%q) error = nil, want sandbox rejection", source)
		}
	}

	if _, err := Compile(`subject.id`); err == nil {
		t.Fatal("Compile(non-bool) error = nil, want AsBool rejection")
	}
	if _, err := Compile(strings.Repeat("x", MaxConditionSourceLength+1)); !errors.Is(err, ErrConditionSourceTooLong) {
		t.Fatalf("long condition error = %v, want ErrConditionSourceTooLong", err)
	}
}

func TestConditionEvaluationDeadline(t *testing.T) {
	condition, err := Compile(`any(1..1000000, # == -1)`)
	if err != nil {
		t.Fatalf("Compile(pathological) error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, err = condition.EvalWithContext(ctx, Context{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("EvalWithContext() error = %v, want context deadline", err)
	}
}
