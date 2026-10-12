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
	"net"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestHandleConnFailedHandshakeDoesNotPanic(t *testing.T) {
	srv := New(zap.New(), "127.0.0.1", 0, &ProxyOpts{})
	client, server := net.Pipe()
	client.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handleConn panicked on a connection that closed before sending a request type: %v", r)
		}
	}()
	srv.handleConn(server)
}
