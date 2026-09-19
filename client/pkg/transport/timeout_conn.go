// Copyright 2015 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"errors"
	"net"
	"sync"
	"time"
)

// timeoutConn arms a fresh deadline before every read and every write, so a
// call that blocks longer than its timeout fails.
//
// An explicit deadline a caller sets with SetReadDeadline, SetWriteDeadline or
// SetDeadline is kept beside those per-call defaults, and the earlier of the
// two applies. A rearm therefore never undoes a caller's deadline: one already
// in the past, such as the one net/http sets to abort a pending background
// read, still ends the next call at once. A zero explicit deadline clears only
// the explicit limit; the per-call defaults continue.
//
// The state lives on one value that is never copied: the constructors return a
// pointer and every method takes one.
type timeoutConn struct {
	net.Conn
	writeTimeout time.Duration
	readTimeout  time.Duration

	// mu orders a deadline change against a rearm. It is never held across a
	// blocking read or write.
	mu    sync.Mutex
	read  connDeadlines
	write connDeadlines
}

// connDeadlines is one direction's explicit deadline and the per-call
// deadline last armed.
type connDeadlines struct {
	explicit time.Time
	armed    time.Time
}

// effective is the earlier of the two deadlines that are set, or zero when
// neither is.
func (d connDeadlines) effective() time.Time {
	switch {
	case d.explicit.IsZero():
		return d.armed
	case d.armed.IsZero() || d.explicit.Before(d.armed):
		return d.explicit
	default:
		return d.armed
	}
}

func (c *timeoutConn) Write(b []byte) (n int, err error) {
	if c.writeTimeout > 0 {
		if err := c.rearm(&c.write, c.writeTimeout, c.Conn.SetWriteDeadline); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

func (c *timeoutConn) Read(b []byte) (n int, err error) {
	if c.readTimeout > 0 {
		if err := c.rearm(&c.read, c.readTimeout, c.Conn.SetReadDeadline); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// rearm arms one direction's per-call deadline from now, bounded by that
// direction's explicit deadline.
func (c *timeoutConn) rearm(d *connDeadlines, timeout time.Duration, set func(time.Time) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d.armed = time.Now().Add(timeout)
	return set(d.effective())
}

// SetReadDeadline sets the explicit read deadline. A read in progress is held
// to it at once.
func (c *timeoutConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.read.explicit = t
	return c.Conn.SetReadDeadline(c.read.effective())
}

// SetWriteDeadline sets the explicit write deadline. A write in progress is
// held to it at once.
func (c *timeoutConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.write.explicit = t
	return c.Conn.SetWriteDeadline(c.write.effective())
}

// SetDeadline sets both explicit deadlines.
func (c *timeoutConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.read.explicit, c.write.explicit = t, t
	return errors.Join(c.Conn.SetReadDeadline(c.read.effective()), c.Conn.SetWriteDeadline(c.write.effective()))
}
