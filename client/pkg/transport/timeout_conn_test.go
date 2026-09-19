// Copyright 2026 The etcd Authors
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
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

const (
	// longTimeout is a per-call default no case waits out.
	longTimeout = time.Hour
	// shortTimeout is a per-call default a case waits out.
	shortTimeout = 100 * time.Millisecond
	// blockedTimeout is a per-call default long enough for a case to change a
	// blocked call's explicit deadline well before the default ends it.
	blockedTimeout = 500 * time.Millisecond
	// promptly bounds what "at once" means in these cases, and every wait on
	// an operation they start.
	promptly = 2 * time.Second
)

func past() time.Time { return time.Now().Add(-time.Second) }

// pipeConn is one end of an in-memory connection with real deadline
// semantics, and its peer. Both are closed when the case ends.
func pipeConn(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}

// closer releases every call blocked on c by closing it.
func closer(c net.Conn) func() {
	return func() { c.Close() }
}

// call is one operation running on its own goroutine.
type call struct {
	done chan struct{}
	err  error
}

// start runs op on its own goroutine. The case joins it before it ends,
// calling release first when op has not returned by then, so no operation
// outlives the case that started it.
func start(t *testing.T, release func(), op func() error) *call {
	t.Helper()
	c := &call{done: make(chan struct{})}
	go func() {
		defer close(c.done)
		c.err = op()
	}()
	t.Cleanup(func() {
		select {
		case <-c.done:
			return
		default:
		}
		release()
		select {
		case <-c.done:
		case <-time.After(promptly):
			t.Errorf("an operation was still blocked %s after its release", promptly)
		}
	})
	return c
}

// wait returns the call's error, and fails the case when the call is still
// blocked after promptly.
func (c *call) wait(t *testing.T, what string) error {
	t.Helper()
	select {
	case <-c.done:
		return c.err
	case <-time.After(promptly):
		t.Fatalf("%s: still blocked after %s", what, promptly)
		return nil
	}
}

// requireBlocked requires the call not to have returned yet.
func (c *call) requireBlocked(t *testing.T, what string) {
	t.Helper()
	select {
	case <-c.done:
		t.Fatalf("fixture: %s returned %v before the case changed its deadline", what, c.err)
	default:
	}
}

// requireTimeout requires the call to end promptly with a timeout.
func requireTimeout(t *testing.T, what string, c *call) {
	t.Helper()
	err := c.wait(t, what)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("%s: returned %v, want a timeout", what, err)
	}
}

// exchange passes one byte from one end to the other and requires both calls
// to succeed promptly.
func exchange(t *testing.T, what string, from, to net.Conn) {
	t.Helper()
	for _, c := range []*call{start(t, closer(from), writeOne(from)), start(t, closer(to), readOne(to))} {
		if err := c.wait(t, what); err != nil {
			t.Fatalf("%s: returned %v, want the byte passed", what, err)
		}
	}
}

func readOne(c net.Conn) func() error {
	return func() error {
		n, err := c.Read(make([]byte, 1))
		if err == nil && n != 1 {
			return fmt.Errorf("read %d bytes, want 1", n)
		}
		return err
	}
}

func writeOne(c net.Conn) func() error {
	return func() error {
		_, err := c.Write([]byte{1})
		return err
	}
}

// enteringConn reports each read and write as it reaches the connection
// underneath, which is after timeoutConn has armed that call's deadline.
type enteringConn struct {
	net.Conn
	reading chan struct{}
	writing chan struct{}
}

func newEnteringConn(c net.Conn) *enteringConn {
	return &enteringConn{Conn: c, reading: make(chan struct{}, 1), writing: make(chan struct{}, 1)}
}

func (e *enteringConn) Read(p []byte) (int, error) {
	signal(e.reading)
	return e.Conn.Read(p)
}

func (e *enteringConn) Write(p []byte) (int, error) {
	signal(e.writing)
	return e.Conn.Write(p)
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// awaitEntered waits for a call to reach the connection underneath.
func awaitEntered(t *testing.T, what string, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(promptly):
		t.Fatalf("fixture: %s never reached the connection", what)
	}
}

// TestTimeoutConnReadHonorsAnExpiredExplicitDeadline forces one order of an
// explicit deadline against the per-call rearm: the deadline is set, and has
// passed, before the read starts. The read's own rearm must not replace it.
func TestTimeoutConnReadHonorsAnExpiredExplicitDeadline(t *testing.T) {
	a, _ := pipeConn(t)
	c := &timeoutConn{Conn: a, readTimeout: longTimeout, writeTimeout: longTimeout}
	if err := c.SetReadDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read started after its explicit deadline passed", start(t, closer(a), readOne(c)))
}

// TestTimeoutConnWriteHonorsAnExpiredExplicitDeadline is the write direction.
func TestTimeoutConnWriteHonorsAnExpiredExplicitDeadline(t *testing.T) {
	a, _ := pipeConn(t)
	c := &timeoutConn{Conn: a, readTimeout: longTimeout, writeTimeout: longTimeout}
	if err := c.SetWriteDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a write started after its explicit deadline passed", start(t, closer(a), writeOne(c)))
}

// TestTimeoutConnSetDeadlineCoversBothDirections sets one expired deadline for
// both directions before either call starts.
func TestTimeoutConnSetDeadlineCoversBothDirections(t *testing.T) {
	a, _ := pipeConn(t)
	c := &timeoutConn{Conn: a, readTimeout: longTimeout, writeTimeout: longTimeout}
	if err := c.SetDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read started after SetDeadline's deadline passed", start(t, closer(a), readOne(c)))
	requireTimeout(t, "a write started after SetDeadline's deadline passed", start(t, closer(a), writeOne(c)))
}

// TestTimeoutConnExplicitDeadlineEndsABlockedCall forces the other order: each
// call has armed its per-call deadline and reached the connection underneath
// before the explicit deadline is set, and must then end at once.
func TestTimeoutConnExplicitDeadlineEndsABlockedCall(t *testing.T) {
	for _, tc := range []struct {
		name        string
		set         func(*timeoutConn, time.Time) error
		read, write bool
	}{
		{"SetReadDeadline", (*timeoutConn).SetReadDeadline, true, false},
		{"SetWriteDeadline", (*timeoutConn).SetWriteDeadline, false, true},
		{"SetDeadline", (*timeoutConn).SetDeadline, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := pipeConn(t)
			e := newEnteringConn(a)
			c := &timeoutConn{Conn: e, readTimeout: longTimeout, writeTimeout: longTimeout}
			var read, write *call
			if tc.read {
				read = start(t, closer(a), readOne(c))
				awaitEntered(t, "the read", e.reading)
			}
			if tc.write {
				write = start(t, closer(a), writeOne(c))
				awaitEntered(t, "the write", e.writing)
			}
			if err := tc.set(c, past()); err != nil {
				t.Fatal(err)
			}
			if read != nil {
				requireTimeout(t, "a blocked read after "+tc.name+" set an expired deadline", read)
			}
			if write != nil {
				requireTimeout(t, "a blocked write after "+tc.name+" set an expired deadline", write)
			}
		})
	}
}

// TestTimeoutConnPerCallDefaultOutlastsExplicitChangesDuringACall moves a
// blocked call's explicit deadline past its per-call default, or clears an
// explicit deadline that was later than the default, while the call is
// blocked. Neither lifts the default the call armed.
func TestTimeoutConnPerCallDefaultOutlastsExplicitChangesDuringACall(t *testing.T) {
	later := func() time.Time { return time.Now().Add(longTimeout) }
	for _, tc := range []struct {
		name           string
		before, during func() time.Time
	}{
		{"moved later", nil, later},
		{"cleared", later, func() time.Time { return time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := pipeConn(t)
			e := newEnteringConn(a)
			c := &timeoutConn{Conn: e, readTimeout: blockedTimeout, writeTimeout: blockedTimeout}
			if tc.before != nil {
				if err := c.SetDeadline(tc.before()); err != nil {
					t.Fatal(err)
				}
			}
			read := start(t, closer(a), readOne(c))
			awaitEntered(t, "the read", e.reading)
			write := start(t, closer(a), writeOne(c))
			awaitEntered(t, "the write", e.writing)
			if err := c.SetDeadline(tc.during()); err != nil {
				t.Fatal(err)
			}
			read.requireBlocked(t, "the read")
			write.requireBlocked(t, "the write")
			requireTimeout(t, "a blocked read whose explicit deadline was "+tc.name, read)
			requireTimeout(t, "a blocked write whose explicit deadline was "+tc.name, write)
		})
	}
}

// TestTimeoutConnClearsAndRestoresExplicitDeadlines clears each direction's
// expired explicit deadline, which lets a call through, and restores it.
func TestTimeoutConnClearsAndRestoresExplicitDeadlines(t *testing.T) {
	a, b := pipeConn(t)
	c := &timeoutConn{Conn: a, readTimeout: longTimeout, writeTimeout: longTimeout}

	if err := c.SetReadDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read under an expired explicit deadline", start(t, closer(a), readOne(c)))
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	exchange(t, "a read after its explicit deadline was cleared", b, c)
	if err := c.SetReadDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read after its explicit deadline was restored", start(t, closer(a), readOne(c)))

	if err := c.SetWriteDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a write under an expired explicit deadline", start(t, closer(a), writeOne(c)))
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	exchange(t, "a write after its explicit deadline was cleared", c, b)
	if err := c.SetWriteDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a write after its explicit deadline was restored", start(t, closer(a), writeOne(c)))
}

// TestTimeoutConnSetDeadlineClearsAndRestores is the same through SetDeadline,
// both directions at once.
func TestTimeoutConnSetDeadlineClearsAndRestores(t *testing.T) {
	a, b := pipeConn(t)
	c := &timeoutConn{Conn: a, readTimeout: longTimeout, writeTimeout: longTimeout}

	if err := c.SetDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read under an expired SetDeadline", start(t, closer(a), readOne(c)))
	requireTimeout(t, "a write under an expired SetDeadline", start(t, closer(a), writeOne(c)))
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	exchange(t, "a read after SetDeadline was cleared", b, c)
	exchange(t, "a write after SetDeadline was cleared", c, b)
	if err := c.SetDeadline(past()); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read after SetDeadline was restored", start(t, closer(a), readOne(c)))
	requireTimeout(t, "a write after SetDeadline was restored", start(t, closer(a), writeOne(c)))
}

// TestTimeoutConnPerCallDefaultBoundsLaterExplicitDeadlines keeps the per-call
// defaults ending every call with no explicit deadline, with one later than the
// defaults, and once that one is cleared.
func TestTimeoutConnPerCallDefaultBoundsLaterExplicitDeadlines(t *testing.T) {
	a, _ := pipeConn(t)
	c := &timeoutConn{Conn: a, readTimeout: shortTimeout, writeTimeout: shortTimeout}
	requireTimeout(t, "a read with no explicit deadline", start(t, closer(a), readOne(c)))
	requireTimeout(t, "a write with no explicit deadline", start(t, closer(a), writeOne(c)))
	if err := c.SetDeadline(time.Now().Add(longTimeout)); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read whose explicit deadline is later than its default", start(t, closer(a), readOne(c)))
	requireTimeout(t, "a write whose explicit deadline is later than its default", start(t, closer(a), writeOne(c)))
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	requireTimeout(t, "a read after its explicit deadline was cleared", start(t, closer(a), readOne(c)))
	requireTimeout(t, "a write after its explicit deadline was cleared", start(t, closer(a), writeOne(c)))
}

// TestTimeoutConnDeadlineSetterRearmStress races an expiring setter against a
// read's rearm many times, for the race detector. It is stress evidence, not
// deterministic coverage of either order: the setter-first order is forced by
// TestTimeoutConnReadHonorsAnExpiredExplicitDeadline, and the rearm-first
// order by TestTimeoutConnExplicitDeadlineEndsABlockedCall. Whichever order a
// run lands in, once the setter has returned the read must end at once.
func TestTimeoutConnDeadlineSetterRearmStress(t *testing.T) {
	for i := range 200 {
		a, _ := pipeConn(t)
		c := &timeoutConn{Conn: a, readTimeout: longTimeout, writeTimeout: longTimeout}
		begin := make(chan struct{})
		read := start(t, closer(a), func() error {
			<-begin
			return readOne(c)()
		})
		set := start(t, func() {}, func() error {
			<-begin
			return c.SetReadDeadline(past())
		})
		close(begin)
		if err := set.wait(t, "the setter"); err != nil {
			t.Fatal(err)
		}
		requireTimeout(t, fmt.Sprintf("iteration %d: a read raced against an expiring setter", i), read)
	}
}

// TestTimeoutConnConstructorsShareDeadlineState sets an expired deadline
// through one holder of a connection the listener accepted, or the dialer
// dialed, and reads through another. Every holder shares one deadline state, so
// the read ends at once.
func TestTimeoutConnConstructorsShareDeadlineState(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	dialer := &rwTimeoutDialer{wtimeoutd: longTimeout, rdtimeoutd: longTimeout, Dialer: net.Dialer{Timeout: promptly}}
	dialed, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dialed.Close() })
	if deadlineErr := ln.(*net.TCPListener).SetDeadline(time.Now().Add(promptly)); deadlineErr != nil {
		t.Fatal(deadlineErr)
	}
	rwln := &rwTimeoutListener{Listener: ln, readTimeout: longTimeout, writeTimeout: longTimeout}
	accepted, err := rwln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accepted.Close() })

	for _, conn := range []struct {
		name string
		net.Conn
	}{{"accepted", accepted}, {"dialed", dialed}} {
		holder := struct{ net.Conn }{conn.Conn}
		if err := holder.SetReadDeadline(past()); err != nil {
			t.Fatal(err)
		}
		requireTimeout(t, "a read through one holder of the "+conn.name+" connection after another set an expired deadline",
			start(t, closer(conn.Conn), readOne(conn.Conn)))
	}
}

// request is the one request the HTTP case sends.
const request = "GET / HTTP/1.1\r\nHost: timeoutconn\r\n\r\n"

// gatedConn hands the server the whole request in its first read, however TCP
// segmented it, so request parsing needs no further read. The next read is
// net/http's background read, which reads one byte; gatedConn requires that
// shape and holds the read until the server has applied a read deadline in the
// past. That is the order in which abortPendingRead meets a background read
// that has not reached the connection yet.
type gatedConn struct {
	net.Conn
	stop <-chan struct{}

	mu        sync.Mutex
	delivered bool
	pending   []byte
	gated     bool

	// reached is closed when the background read reaches the gate, and
	// released once an expired read deadline has been applied underneath.
	reached     chan struct{}
	released    chan struct{}
	releaseOnce sync.Once
	// misread reports a read after the request that was not the background
	// read, which would leave the case proving nothing.
	misread chan string
}

func (g *gatedConn) Read(p []byte) (int, error) {
	g.mu.Lock()
	if !g.delivered {
		g.delivered = true
		g.mu.Unlock()
		whole := make([]byte, len(request))
		if _, err := io.ReadFull(g.Conn, whole); err != nil {
			return 0, err
		}
		g.mu.Lock()
		g.pending = whole
	}
	if len(g.pending) > 0 {
		n := copy(p, g.pending)
		g.pending = g.pending[n:]
		g.mu.Unlock()
		return n, nil
	}
	background := !g.gated
	g.gated = true
	g.mu.Unlock()
	if background {
		if len(p) != 1 {
			select {
			case g.misread <- fmt.Sprintf("the first read after the request asked for %d bytes, not net/http's one-byte background read", len(p)):
			default:
			}
			return g.Conn.Read(p)
		}
		close(g.reached)
		select {
		case <-g.released:
		case <-g.stop:
		}
	}
	return g.Conn.Read(p)
}

// SetReadDeadline applies the deadline underneath first, and only then
// releases a held background read, so the read cannot rearm before the
// expired deadline is in place.
func (g *gatedConn) SetReadDeadline(t time.Time) error {
	if err := g.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	if !t.IsZero() && !t.After(time.Now()) {
		g.releaseOnce.Do(func() { close(g.released) })
	}
	return nil
}

type gatedListener struct {
	net.Listener
	stop  <-chan struct{}
	conns chan *gatedConn
}

func (l *gatedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	g := &gatedConn{
		Conn:     c,
		stop:     l.stop,
		reached:  make(chan struct{}),
		released: make(chan struct{}),
		misread:  make(chan string, 1),
	}
	select {
	case l.conns <- g:
	default:
	}
	return g, nil
}

// TestTimeoutConnLetsHTTPAbortAPendingRead serves one request to a client that
// then keeps its connection open and idle, and forces net/http's background
// read to reach the connection only after abortPendingRead has applied its
// expired deadline. The server must finish that request and go idle at once,
// not after the connection's per-read timeout.
func TestTimeoutConnLetsHTTPAbortAPendingRead(t *testing.T) {
	const readTimeout = 10 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	gl := &gatedListener{
		Listener: &rwTimeoutListener{Listener: ln, readTimeout: readTimeout, writeTimeout: readTimeout},
		stop:     stop,
		conns:    make(chan *gatedConn, 1),
	}
	idle := make(chan time.Time, 1)
	closed := make(chan struct{})
	var closeOnce sync.Once
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, writeErr := w.Write([]byte("ok")); writeErr != nil {
				t.Errorf("writing the reply: %v", writeErr)
			}
		}),
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateIdle:
				select {
				case idle <- time.Now():
				default:
				}
			case http.StateClosed:
				closeOnce.Do(func() { close(closed) })
			}
		},
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(gl) }()
	accepted := false
	// The server, its one connection and any held read are stopped and joined
	// before the case ends, whatever it concluded.
	defer func() {
		close(stop)
		if closeErr := srv.Close(); closeErr != nil {
			t.Errorf("closing the server: %v", closeErr)
		}
		select {
		case serveErr := <-served:
			if !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("serving: %v", serveErr)
			}
		case <-time.After(promptly):
			t.Errorf("the server was still serving %s after it was closed", promptly)
		}
		if !accepted {
			return
		}
		select {
		case <-closed:
		case <-time.After(promptly):
			t.Errorf("the connection was still open %s after the server was closed", promptly)
		}
	}()

	client, err := net.DialTimeout("tcp", ln.Addr().String(), promptly)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if deadlineErr := client.SetDeadline(time.Now().Add(promptly)); deadlineErr != nil {
		t.Fatal(deadlineErr)
	}
	var g *gatedConn
	select {
	case g = <-gl.conns:
		accepted = true
	case <-time.After(promptly):
		t.Fatalf("fixture: the server did not accept the connection within %s", promptly)
	}
	if _, requestErr := io.WriteString(client, request); requestErr != nil {
		t.Fatal(requestErr)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		select {
		case why := <-g.misread:
			t.Fatalf("fixture: %s", why)
		default:
		}
		t.Fatalf("reading the reply: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	answered := time.Now()

	select {
	case <-g.reached:
	case why := <-g.misread:
		t.Fatalf("fixture: %s", why)
	case <-time.After(promptly):
		t.Fatalf("fixture: net/http's background read did not reach the gate within %s", promptly)
	}
	select {
	case at := <-idle:
		if waited := at.Sub(answered); waited >= promptly {
			t.Fatalf("the server went idle %s after answering: abortPendingRead waited out the per-read timeout", waited)
		}
	case <-time.After(promptly):
		t.Fatalf("the server did not go idle within %s of answering: abortPendingRead is waiting out the %s per-read timeout", promptly, readTimeout)
	}
}
