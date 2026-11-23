package rbac

import (
	"testing"

	rbacv1 "github.com/kvdi/kvdi/apis/rbac/v1"
	"github.com/kvdi/kvdi/pkg/types"
)

type fakeResourceGetter struct{}

func (fakeResourceGetter) GetTemplates() ([]string, error)        { return nil, nil }
func (fakeResourceGetter) GetUsers() ([]types.VDIUser, error)     { return nil, nil }
func (fakeResourceGetter) GetRoles() ([]types.VDIUserRole, error) { return nil, nil }

func saRule(patterns ...string) rbacv1.Rule {
	return rbacv1.Rule{
		Verbs:            []rbacv1.Verb{rbacv1.VerbUse},
		Resources:        []rbacv1.Resource{rbacv1.ResourceServiceAccounts},
		ResourcePatterns: patterns,
		Namespaces:       []string{"team-a"},
	}
}

func TestRuleIncludesServiceAccountPatterns(t *testing.T) {
	getter := fakeResourceGetter{}
	cases := []struct {
		name     string
		held     rbacv1.Rule
		proposed rbacv1.Rule
		want     bool
	}{
		{"identical pattern", saRule("^builder$"), saRule("^builder$"), true},
		{"subset of held patterns", saRule("^builder$", "^viewer$"), saRule("^viewer$"), true},
		{"held match-all", saRule(".*"), saRule("^cluster-admin$"), true},
		{"widen to match-all", saRule("^builder$"), saRule(".*"), false},
		{"different service account", saRule("^builder$"), saRule("^namespace-admin$"), false},
		{"no held patterns", saRule(), saRule(".*"), false},
		{
			"widen via resource all",
			rbacv1.Rule{
				Verbs:            []rbacv1.Verb{rbacv1.VerbUse},
				Resources:        []rbacv1.Resource{rbacv1.ResourceAll},
				ResourcePatterns: []string{"^builder$"},
				Namespaces:       []string{"team-a"},
			},
			rbacv1.Rule{
				Verbs:            []rbacv1.Verb{rbacv1.VerbUse},
				Resources:        []rbacv1.Resource{rbacv1.ResourceAll},
				ResourcePatterns: []string{".*"},
				Namespaces:       []string{"team-a"},
			},
			false,
		},
		{
			"widen via proposed wildcard verb",
			rbacv1.Rule{
				Verbs:            []rbacv1.Verb{rbacv1.VerbAll},
				Resources:        []rbacv1.Resource{rbacv1.ResourceServiceAccounts},
				ResourcePatterns: []string{"^builder$"},
				Namespaces:       []string{"team-a"},
			},
			rbacv1.Rule{
				Verbs:            []rbacv1.Verb{rbacv1.VerbAll},
				Resources:        []rbacv1.Resource{rbacv1.ResourceServiceAccounts},
				ResourcePatterns: []string{".*"},
				Namespaces:       []string{"team-a"},
			},
			false,
		},
		{
			"read-only grant ignores service account patterns",
			rbacv1.Rule{
				Verbs:            []rbacv1.Verb{rbacv1.VerbAll},
				Resources:        []rbacv1.Resource{rbacv1.ResourceAll},
				ResourcePatterns: []string{"^builder$"},
				Namespaces:       []string{"team-a"},
			},
			rbacv1.Rule{
				Verbs:            []rbacv1.Verb{rbacv1.VerbRead},
				Resources:        []rbacv1.Resource{rbacv1.ResourceAll},
				ResourcePatterns: []string{"^viewer$"},
				Namespaces:       []string{"team-a"},
			},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RuleIncludes(tc.held, tc.proposed, getter); got != tc.want {
				t.Errorf("RuleIncludes() = %v, want %v", got, tc.want)
			}
		})
	}
}
