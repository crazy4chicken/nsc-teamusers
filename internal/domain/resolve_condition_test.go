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

	withoutDeny := Resolve(grants, requests)
	if !withoutDeny[0].Allowed || withoutDeny[0].Grant.Scope != "own" {
		t.Fatalf("own request = %#v, want own allow", withoutDeny[0])
	}
	if !withoutDeny[1].Allowed || withoutDeny[1].Grant.Scope != "team" || withoutDeny[1].Grant.Deny {
		t.Fatalf("team request without deny = %#v, want team allow", withoutDeny[1])
	}
	if !withoutDeny[2].Allowed || withoutDeny[2].Grant.Scope != "any" {
		t.Fatalf("any request = %#v, want any allow", withoutDeny[2])
	}
	if !withoutDeny[3].Allowed || withoutDeny[3].Grant.Action != "delete" {
		t.Fatalf("delete request = %#v, want exact delete allow", withoutDeny[3])
	}

	withDeny := Resolve(grants, requests, true)
	if withDeny[0].Allowed || !withDeny[0].Denied || withDeny[0].Grant.Scope != "*" {
		t.Fatalf("explicit deny should beat narrower allow = %#v", withDeny[0])
	}
	if withDeny[1].Allowed || !withDeny[1].Denied || withDeny[1].Grant.Scope != "team" {
		t.Fatalf("explicit team deny = %#v, want denied", withDeny[1])
	}
	if withDeny[2].Allowed || !withDeny[2].Denied || withDeny[2].Grant.Scope != "*" {
		t.Fatalf("wildcard deny should match any scope = %#v", withDeny[2])
	}
	if !withDeny[3].Allowed || withDeny[3].Grant.Action != "delete" {
		t.Fatalf("unrelated deny should not affect delete = %#v", withDeny[3])
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
