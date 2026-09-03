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
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func setupHome(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	outside := filepath.Join(base, "secret")
	for _, d := range []string{filepath.Join(home, "docs"), outside} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "docs", "a.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "tls.key"), []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"leak":         filepath.Join(outside, "tls.key"),
		"leakdir":      "../secret",
		"docs/leaklnk": "../../secret/tls.key",
	} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Fatal(err)
		}
	}
	orig := homeMntPath
	homeMntPath = home
	t.Cleanup(func() { homeMntPath = orig })
	return home
}

func TestOpenHomePath(t *testing.T) {
	home := setupHome(t)

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{"root", "/", home, false},
		{"empty", "", home, false},
		{"regular file", "docs/a.txt", filepath.Join(home, "docs", "a.txt"), false},
		{"leading slash", "/docs/a.txt", filepath.Join(home, "docs", "a.txt"), false},
		{"dot-dot traversal", "../secret/tls.key", "", true},
		{"nested dot-dot", "docs/../../secret/tls.key", "", true},
		{"symlink to file outside home", "leak", "", true},
		{"symlink to dir outside home", "leakdir/tls.key", "", true},
		{"nested symlink", "docs/leaklnk", "", true},
		{"missing file", "docs/nope.txt", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := openHomePath(tt.path)
			if tt.wantErr {
				if err == nil {
					f.Close()
					t.Fatalf("expected error, got %q", f.Name())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer f.Close()
			want, err := os.Stat(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(want, got) {
				t.Fatalf("opened %q, want %q", f.Name(), tt.want)
			}
		})
	}
}

func TestCreateUploadFile(t *testing.T) {
	home := setupHome(t)
	uid := os.Getuid()

	f, err := createUploadFile("a.txt", uid)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := os.Stat(filepath.Join(home, "Uploads", "a.txt")); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(filepath.Dir(home), "secret", "tls.key")
	if err := os.Symlink(outside, filepath.Join(home, "Uploads", "evil")); err != nil {
		t.Fatal(err)
	}
	if f, err := createUploadFile("evil", uid); err == nil {
		f.Close()
		t.Fatal("expected error writing through symlink")
	}
	if b, _ := os.ReadFile(outside); string(b) != "key" {
		t.Fatalf("outside file was modified: %q", b)
	}

	if err := os.RemoveAll(filepath.Join(home, "Uploads")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(home), "secret"), filepath.Join(home, "Uploads")); err != nil {
		t.Fatal(err)
	}
	if f, err := createUploadFile("b.txt", uid); err == nil {
		f.Close()
		t.Fatal("expected error when Uploads is a symlink")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(home), "secret", "b.txt")); !os.IsNotExist(err) {
		t.Fatalf("file created outside home: %v", err)
	}
}

func TestTarDirToTempFileSkipsSymlinks(t *testing.T) {
	setupHome(t)

	dir, err := openHomePath("/")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	tarball, err := tarDirToTempFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(filepath.Dir(tarball))

	f, err := os.Open(tarball)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gzr)

	var names []string
	contents := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if hdr.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			contents[hdr.Name] = string(b)
		}
	}
	sort.Strings(names)

	want := []string{"home/", "home/docs/", "home/docs/a.txt"}
	if len(names) != len(want) {
		t.Fatalf("got entries %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got entries %v, want %v", names, want)
		}
	}
	if contents["home/docs/a.txt"] != "ok" {
		t.Fatalf("unexpected file contents %q", contents["home/docs/a.txt"])
	}
}
