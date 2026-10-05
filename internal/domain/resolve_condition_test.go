package domain

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)


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
	for _, index := range []int{0, 1, 2} {
		if resolved[index].Allowed || !resolved[index].Denied {
			t.Fatalf("explicit deny should override matching allows for request %q = %#v", requests[index].String(), resolved[index])
		}
	}
	if !resolved[3].Allowed || resolved[3].Denied {
		t.Fatalf("unrelated deny should not affect delete = %#v", resolved[3])
	}

	allow := Permission{Resource: "orders", Action: "read", Scope: "team"}
	deny := Permission{Resource: "orders", Action: "read", Scope: "team", Deny: true}
	for _, ordered := range [][]Permission{{allow, deny}, {deny, allow}} {
		resolution := Resolve(ordered, []Permission{{Resource: "orders", Action: "read", Scope: "team"}})[0]
		if !resolution.Denied || resolution.Allowed {
			t.Fatalf("deny precedence depends on grant order %v: %#v", ordered, resolution)
		}
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
