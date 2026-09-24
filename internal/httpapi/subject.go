package httpapi

import "context"

// Subject identifies the authenticated principal making an admin request.
type Subject struct {
	UserID  string
	TeamID  string
	Kind    string
	PermVer int64
}

type subjectContextKey struct{}

// ContextWithSubject returns a context carrying the authenticated subject.
func ContextWithSubject(ctx context.Context, subject Subject) context.Context {
	return context.WithValue(ctx, subjectContextKey{}, subject)
}

// SubjectFrom retrieves the authenticated subject from ctx.
func SubjectFrom(ctx context.Context) (Subject, bool) {
	if ctx == nil {
		return Subject{}, false
	}
	subject, ok := ctx.Value(subjectContextKey{}).(Subject)
	return subject, ok
}
