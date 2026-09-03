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

package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetLocalPathFromRequest(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	outside := filepath.Join(base, "secret")
	if err := os.MkdirAll(filepath.Join(home, "docs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "docs", "a.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "tls.key"), []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "tls.key"), filepath.Join(home, "leak")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../secret", filepath.Join(home, "leakdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("docs/a.txt", filepath.Join(home, "inside")); err != nil {
		t.Fatal(err)
	}

	orig := homeMntPath
	homeMntPath = home
	t.Cleanup(func() { homeMntPath = orig })

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{"root", "/", home, false},
		{"regular file", "docs/a.txt", filepath.Join(home, "docs", "a.txt"), false},
		{"symlink inside home", "inside", filepath.Join(home, "docs", "a.txt"), false},
		{"dot-dot traversal", "../secret/tls.key", "", true},
		{"symlink to file outside home", "leak", "", true},
		{"symlink to dir outside home", "leakdir/tls.key", "", true},
		{"sibling prefix", "../home-other", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getLocalPathFromRequest(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got path %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
