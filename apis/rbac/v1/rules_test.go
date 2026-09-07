/*
Copyright 2020,2021 Avi Zimmerman

This file is part of kvdi.

kvdi is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

kvdi is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with kvdi.  If not, see <https://www.gnu.org/licenses/>.
*/

package v1

import "testing"

func TestMatchesResourceName(t *testing.T) {
	cases := []struct {
		patterns []string
		name     string
		expected bool
	}{
		{[]string{".*"}, "anything-at-all", true},
		{[]string{"dev"}, "dev", true},
		{[]string{"dev"}, "prod-dev-admin", false},
		{[]string{"dev"}, "devops", false},
		{[]string{"reader"}, "cluster-reader-admin", false},
		{[]string{"ubuntu-.*"}, "ubuntu-xfce", true},
		{[]string{"ubuntu-.*"}, "my-ubuntu-xfce", false},
		{[]string{"alice", "bob"}, "bob", true},
		{[]string{"bob"}, "bobby", false},
		{[]string{"("}, "anything", false},
		{[]string{}, "anything", false},
	}
	for _, c := range cases {
		r := &Rule{ResourcePatterns: c.patterns}
		if got := r.MatchesResourceName(c.name); got != c.expected {
			t.Errorf("patterns %v against %q: expected %v, got %v", c.patterns, c.name, c.expected, got)
		}
	}
}
