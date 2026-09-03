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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	"github.com/kvdi/kvdi/pkg/proxyproto"
	"github.com/kvdi/kvdi/pkg/util/errors"
)

// homeMntPath redeclared locally for mocking
var homeMntPath = v1.DesktopHomeMntPath

// openHomePath opens the requested path relative to the user's home mount.
// Every path component is opened with O_NOFOLLOW relative to the previously
// opened directory descriptor, so neither ".." traversal nor symlinks planted
// in the home volume (even ones swapped in concurrently) can reach files on
// the proxy's own filesystem.
func openHomePath(path string) (*os.File, error) {
	root, err := os.Open(homeMntPath)
	if err != nil {
		return nil, errors.New("File transfer is disabled for this desktop session")
	}

	rel := filepath.Clean("/" + path)
	if rel == "/" {
		return root, nil
	}

	cur := root
	parts := strings.Split(strings.TrimPrefix(rel, "/"), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			cur.Close()
			return nil, fmt.Errorf("%s is outside the user's home directory", path)
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(cur.Fd()), part, flags, 0)
		cur.Close()
		if err != nil {
			if err == unix.ELOOP || err == unix.ENOTDIR {
				return nil, fmt.Errorf("%s is not a regular file or directory within the user's home directory", path)
			}
			return nil, &os.PathError{Op: "open", Path: filepath.Join(homeMntPath, rel), Err: err}
		}
		cur = os.NewFile(uintptr(fd), filepath.Join(homeMntPath, strings.Join(parts[:i+1], string(filepath.Separator))))
	}
	return cur, nil
}

// createUploadFile creates name inside the Uploads directory of the home mount,
// owned by uid. The directory and file are opened relative to the home mount
// descriptor with O_NOFOLLOW so a symlink planted at either location cannot
// redirect the write outside the home volume.
func createUploadFile(name string, uid int) (*os.File, error) {
	root, err := os.Open(homeMntPath)
	if err != nil {
		return nil, errors.New("File transfer is disabled for this desktop session")
	}
	defer root.Close()

	const uploads = "Uploads"
	if err := unix.Mkdirat(int(root.Fd()), uploads, 0755); err != nil && err != unix.EEXIST {
		return nil, &os.PathError{Op: "mkdir", Path: filepath.Join(homeMntPath, uploads), Err: err}
	}
	dirFd, err := unix.Openat(int(root.Fd()), uploads, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%s is not a directory within the user's home directory", uploads)
	}
	dir := os.NewFile(uintptr(dirFd), filepath.Join(homeMntPath, uploads))
	defer dir.Close()
	if err := dir.Chown(uid, uid); err != nil {
		return nil, err
	}

	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return nil, fmt.Errorf("invalid upload file name %q", name)
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0644)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("%s is not a regular file within the user's home directory", name)
		}
		return nil, &os.PathError{Op: "open", Path: filepath.Join(dir.Name(), name), Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name))
	if err := f.Chown(uid, uid); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// tarDirToTempFile writes a gzipped tarball of the already opened directory to
// a temporary file and returns its path. Entries are opened relative to their
// parent descriptor with O_NOFOLLOW; symlinks and other irregular files are
// skipped.
func tarDirToTempFile(dir *os.File) (string, error) {
	targetDir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", err
	}
	baseDir := filepath.Base(dir.Name())
	outFile := filepath.Join(targetDir, fmt.Sprintf("%s.tar.gz", baseDir))

	fwriter, err := os.Create(outFile)
	if err != nil {
		return "", err
	}
	defer fwriter.Close()

	gzw := gzip.NewWriter(fwriter)
	defer gzw.Close()

	tarball := tar.NewWriter(gzw)
	defer tarball.Close()

	if err := tarDirEntries(tarball, dir, baseDir); err != nil {
		if cleanErr := os.RemoveAll(targetDir); cleanErr != nil {
			fmt.Println("Failed to clean up failed tar directory:", cleanErr)
		}
		return "", err
	}
	return outFile, nil
}

func tarDirEntries(tw *tar.Writer, dir *os.File, prefix string) error {
	finfo, err := dir.Stat()
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(finfo, "")
	if err != nil {
		return err
	}
	hdr.Name = prefix + "/"
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		mode := entry.Type()
		if !mode.IsDir() && !mode.IsRegular() {
			continue
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if mode.IsDir() {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(dir.Fd()), entry.Name(), flags, 0)
		if err != nil {
			// entry removed or replaced while traversing
			continue
		}
		f := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), entry.Name()))
		err = tarEntry(tw, f, prefix+"/"+entry.Name())
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func tarEntry(tw *tar.Writer, f *os.File, name string) error {
	finfo, err := f.Stat()
	if err != nil {
		return err
	}
	if finfo.IsDir() {
		return tarDirEntries(tw, f, name)
	}
	if !finfo.Mode().IsRegular() {
		return nil
	}
	hdr, err := tar.FileInfoHeader(finfo, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.CopyN(tw, f, finfo.Size())
	return err
}

func (p *Server) logConnectionMetrics(proxyType string, conn *proxyproto.Conn) chan struct{} {
	st := make(chan struct{})
	logger := p.log.WithValues("Connection", proxyType)
	go func() {
		ticker := time.NewTicker(time.Second * 10)
		for {
			select {
			case <-st:
				logger.Info("Connection is closing")
				return
			case <-ticker.C:
				logger.Info("Connection is alive", "BytesSent", conn.BytesSentCount(), "BytesReceived", conn.BytesRecvdCount())
			}
		}
	}()
	return st
}
