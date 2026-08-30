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

package webmesh

import "testing"

func TestMetadataValidateURL(t *testing.T) {
	for _, tc := range []struct {
		metadataURL string
		expect      string
	}{
		{"https://metadata.example.com", "https://metadata.example.com/id-tokens/validate"},
		{"https://metadata.example.com/webmesh/", "https://metadata.example.com/webmesh/id-tokens/validate"},
		{"http://metadata.example.com", ""},
		{"metadata.example.com", ""},
		{"", ""},
	} {
		out, err := metadataValidateURL(tc.metadataURL)
		if tc.expect == "" {
			if err == nil {
				t.Errorf("Expected %q to be rejected, got %q", tc.metadataURL, out)
			}
			continue
		}
		if err != nil {
			t.Errorf("Expected %q to be accepted, got: %s", tc.metadataURL, err)
		} else if out != tc.expect {
			t.Errorf("Expected %q, got %q", tc.expect, out)
		}
	}
}
