package passwd

import (
	"unicode"
	"unicode/utf8"
)

// Policy describes the password requirements applied to a password.
type Policy struct {
	MinLength     int  `json:"min_length"`
	RequireLetter bool `json:"require_letter"`
	RequireUpper  bool `json:"require_upper"`
	RequireLower  bool `json:"require_lower"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`
	HistoryCount  int  `json:"history_count"`
	BreachCheck   bool `json:"breach_check"`
}

// DefaultPolicy returns the built-in password requirements: at least 12 runes,
// one letter, and one digit.
func DefaultPolicy() Policy {
	return Policy{
		MinLength:     12,
		RequireLetter: true,
		RequireDigit:  true,
	}
}

// PolicyRule contains optional password requirement overrides.
type PolicyRule struct {
	MinLength     *int
	RequireLetter *bool
	RequireUpper  *bool
	RequireLower  *bool
	RequireDigit  *bool
	RequireSymbol *bool
	HistoryCount  *int
	BreachCheck   *bool
}

// MergePolicy combines priority-ordered password policy rules. For each field,
// the first rule that sets the field wins; fields no rule sets use the default.
func MergePolicy(rules []PolicyRule) Policy {
	policy := DefaultPolicy()
	var (
		minLengthSet     bool
		requireLetterSet bool
		requireUpperSet  bool
		requireLowerSet  bool
		requireDigitSet  bool
		requireSymbolSet bool
		historyCountSet  bool
		breachCheckSet   bool
	)

	for _, rule := range rules {
		if !minLengthSet && rule.MinLength != nil {
			policy.MinLength = *rule.MinLength
			minLengthSet = true
		}
		if !requireLetterSet && rule.RequireLetter != nil {
			policy.RequireLetter = *rule.RequireLetter
			requireLetterSet = true
		}
		if !requireUpperSet && rule.RequireUpper != nil {
			policy.RequireUpper = *rule.RequireUpper
			requireUpperSet = true
		}
		if !requireLowerSet && rule.RequireLower != nil {
			policy.RequireLower = *rule.RequireLower
			requireLowerSet = true
		}
		if !requireDigitSet && rule.RequireDigit != nil {
			policy.RequireDigit = *rule.RequireDigit
			requireDigitSet = true
		}
		if !requireSymbolSet && rule.RequireSymbol != nil {
			policy.RequireSymbol = *rule.RequireSymbol
			requireSymbolSet = true
		}
		if !historyCountSet && rule.HistoryCount != nil {
			policy.HistoryCount = *rule.HistoryCount
			historyCountSet = true
		}
		if !breachCheckSet && rule.BreachCheck != nil {
			policy.BreachCheck = *rule.BreachCheck
			breachCheckSet = true
		}
	}

	return policy
}

// Validate reports whether password satisfies the policy requirements.
func (p Policy) Validate(password string) bool {
	if !utf8.ValidString(password) {
		return false
	}

	length := 0
	var (
		hasLetter bool
		hasUpper  bool
		hasLower  bool
		hasDigit  bool
		hasSymbol bool
	)
	for _, r := range password {
		length++
		hasLetter = hasLetter || unicode.IsLetter(r)
		hasUpper = hasUpper || unicode.IsUpper(r)
		hasLower = hasLower || unicode.IsLower(r)
		hasDigit = hasDigit || unicode.IsDigit(r)
		hasSymbol = hasSymbol || unicode.IsPunct(r) || unicode.IsSymbol(r)
	}

	if p.MinLength < 1 || length < p.MinLength {
		return false
	}

	return (!p.RequireLetter || hasLetter) &&
		(!p.RequireUpper || hasUpper) &&
		(!p.RequireLower || hasLower) &&
		(!p.RequireDigit || hasDigit) &&
		(!p.RequireSymbol || hasSymbol)
}
