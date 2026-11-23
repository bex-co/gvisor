// Copyright 2018 The gVisor Authors.
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

package devpts

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestSimpleMasterToReplica(t *testing.T) {
	ld := newLineDiscipline(linux.DefaultReplicaTermios, nil)
	ctx := contexttest.Context(t)
	inBytes := []byte("hello, tty\n")
	src := usermem.BytesIOSequence(inBytes)
	outBytes := make([]byte, 32)
	dst := usermem.BytesIOSequence(outBytes)

	// Write to the input queue.
	nw, err := ld.inputQueueWrite(ctx, src)
	if err != nil {
		t.Fatalf("error writing to input queue: %v", err)
	}
	if nw != int64(len(inBytes)) {
		t.Fatalf("wrote wrong length: got %d, want %d", nw, len(inBytes))
	}

	// Read from the input queue.
	nr, err := ld.inputQueueRead(ctx, dst)
	if err != nil {
		t.Fatalf("error reading from input queue: %v", err)
	}
	if nr != int64(len(inBytes)) {
		t.Fatalf("read wrong length: got %d, want %d", nr, len(inBytes))
	}

	outStr := string(outBytes[:nr])
	inStr := string(inBytes)
	if outStr != inStr {
		t.Fatalf("written and read strings do not match: got %q, want %q", outStr, inStr)
	}
}

func TestEchoDeadlock(t *testing.T) {
	ctx := contexttest.Context(t)
	termios := linux.DefaultReplicaTermios
	termios.LocalFlags |= linux.ECHO
	ld := newLineDiscipline(termios, nil)
	outBytes := make([]byte, 32)
	dst := usermem.BytesIOSequence(outBytes)
	entry := waiter.NewFunctionEntry(waiter.ReadableEvents, func(waiter.EventMask) {
		ld.inputQueueRead(ctx, dst)
	})
	ld.masterWaiter.EventRegister(&entry)
	defer ld.masterWaiter.EventUnregister(&entry)
	inBytes := []byte("hello, tty\n")
	n, err := ld.inputQueueWrite(ctx, usermem.BytesIOSequence(inBytes))
	if err != nil {
		t.Fatalf("inputQueueWrite: %v", err)
	}
	if int(n) != len(inBytes) {
		t.Fatalf("read wrong length: got %d, want %d", n, len(inBytes))
	}
	outStr := string(outBytes[:n])
	inStr := string(inBytes)
	if outStr != inStr {
		t.Fatalf("written and read strings do not match: got %q, want %q", outStr, inStr)
	}
}

func TestEndOfFileHandling(t *testing.T) {
	ctx := contexttest.Context(t)
	termios := linux.DefaultReplicaTermios
	ld := newLineDiscipline(termios, nil)

	// EOF with non-empty read buffer.
	inBytes := []byte("hello, tty")
	inBytes = append(inBytes, termios.ControlCharacters[linux.VEOF])
	outBytes := make([]byte, 32)
	dst := usermem.BytesIOSequence(outBytes)
	// Write to the input queue.
	nw, err := ld.inputQueueWrite(ctx, usermem.BytesIOSequence(inBytes))
	if err != nil {
		t.Fatalf("error writing to input queue: %v", err)
	}
	if nw != int64(len(inBytes)) {
		t.Fatalf("wrote wrong length: got %d, want %d", nw, len(inBytes))
	}

	// Read from the input queue.
	nr, err := ld.inputQueueRead(ctx, dst)
	if err != nil {
		t.Fatalf("error reading from input queue: %v", err)
	}
	if nr != int64(len(inBytes)-1) {
		t.Fatalf("read wrong length: got %d, want %d", nr, len(inBytes)-1)
	}

	// EOF with empty read buffer.
	inBytes = []byte{termios.ControlCharacters[linux.VEOF]}
	outBytes = make([]byte, 32)
	dst = usermem.BytesIOSequence(outBytes)
	// Write to the input queue.
	nw, err = ld.inputQueueWrite(ctx, usermem.BytesIOSequence(inBytes))
	if err != nil {
		t.Fatalf("error writing to input queue: %v", err)
	}
	if nw != int64(len(inBytes)) {
		t.Fatalf("wrote wrong length: got %d, want %d", nw, len(inBytes))
	}

	// Read from the input queue.
	nr, err = ld.inputQueueRead(ctx, dst)
	if err != nil {
		t.Fatalf("error reading from input queue: %v", err)
	}
	if nr != 0 {
		t.Fatalf("read length should be zero: got %d", nr)
	}
}

// newTestLineDiscipline returns a line discipline with termios and one open
// replica, whose terminal has no controlling process to signal.
func newTestLineDiscipline(termios linux.KernelTermios) *lineDiscipline {
	term := &Terminal{replicaKTTY: kernel.NewTTY(0, nil)}
	term.ld = newLineDiscipline(termios, term)
	term.ld.replicaOpen()
	return term.ld
}

// readAvailable returns what one call to read returns, or "" if read would
// block.
func readAvailable(t *testing.T, read func(context.Context, usermem.IOSequence) (int64, error)) string {
	t.Helper()
	buf := make([]byte, 64)
	n, err := read(contexttest.Context(t), usermem.BytesIOSequence(buf))
	if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

// TestSignalFlushesOutputMasterHasNoRoomFor checks that a signal character
// discards the output the master has no room for, as
// drivers/tty/pty.c:pty_flush_buffer() does on Linux, and keeps what the
// master can already read. (On Linux, how much the master can already read
// depends on how far a worker thread got, so this is checked here rather than
// in a syscall test.)
func TestSignalFlushesOutputMasterHasNoRoomFor(t *testing.T) {
	ctx := contexttest.Context(t)
	termios := linux.DefaultReplicaTermios
	termios.LocalFlags &^= linux.ECHO
	ld := newTestLineDiscipline(termios)

	output := bytes.Repeat([]byte{'x'}, 3*canonMaxBytes)
	if n, err := ld.outputQueueWrite(ctx, usermem.BytesIOSequence(output)); err != nil || n != int64(len(output)) {
		t.Fatalf("outputQueueWrite = %d, %v, want %d, nil", n, err, len(output))
	}
	if _, err := ld.inputQueueWrite(ctx, usermem.BytesIOSequence([]byte("\x03"))); err != nil {
		t.Fatalf("inputQueueWrite: %v", err)
	}
	read := 0
	for s := readAvailable(t, ld.outputQueueRead); s != ""; s = readAvailable(t, ld.outputQueueRead) {
		read += len(s)
	}
	if read != nonCanonMaxBytes {
		t.Errorf("master read %d bytes after the signal, want %d", read, nonCanonMaxBytes)
	}
}

// TestEcho checks what the line discipline echoes back to the master and
// passes to the replica, against what drivers/tty/n_tty.c does on Linux.
func TestEcho(t *testing.T) {
	for _, test := range []struct {
		name string
		// lflagsOn and lflagsOff are the local flags set in and cleared from
		// the default termios.
		lflagsOn  uint32
		lflagsOff uint32
		input     string
		// echo is what the master reads back.
		echo string
		// read is what the replica reads.
		read string
	}{
		{name: "interrupt", input: "\x03", echo: "^C"},
		{name: "quit", input: "\x1c", echo: "^\\"},
		{name: "suspend", input: "\x1a", echo: "^Z"},
		{name: "interrupt without ECHOCTL", lflagsOff: linux.ECHOCTL, input: "\x03", echo: "\x03"},
		{name: "interrupt without ECHO", lflagsOff: linux.ECHO, input: "\x03"},
		{name: "interrupt without ISIG", lflagsOff: linux.ISIG | linux.ICANON, input: "\x03", echo: "^C", read: "\x03"},
		{name: "interrupt then a line", input: "\x03ab\n", echo: "^Cab\r\n", read: "ab\n"},
		{name: "interrupt flushes the line before it", input: "abc\x03\n", echo: "^C\r\n", read: "\n"},
		{name: "suspend flushes the echo of an earlier quit", input: "ab\x1cc\x1ad\n", echo: "^Zd\r\n", read: "d\n"},
		{name: "interrupt with NOFLSH", lflagsOn: linux.NOFLSH, input: "abc\x03\n", echo: "abc^C\r\n", read: "abc\n"},
		{name: "kill erases the line", input: "abc\x15def\n", echo: "abc\b \b\b \b\b \bdef\r\n", read: "def\n"},
		{name: "kill without ECHOKE", lflagsOff: linux.ECHOKE, input: "abc\x15def\n", echo: "abc^U\r\ndef\r\n", read: "def\n"},
		{name: "kill without ECHOK and ECHOKE", lflagsOff: linux.ECHOK | linux.ECHOKE, input: "abc\x15def\n", echo: "abc^Udef\r\n", read: "def\n"},
		{name: "kill without ECHO", lflagsOff: linux.ECHO, input: "abc\x15def\n", read: "def\n"},
		{name: "kill on an empty line", lflagsOff: linux.ECHOKE, input: "\x15", echo: ""},
		{name: "noncanonical kill", lflagsOff: linux.ICANON, input: "a\x15", echo: "a^U", read: "a\x15"},
		{name: "erase without ECHOE", lflagsOff: linux.ECHOE, input: "ab\x7f\n", echo: "ab^?\r\n", read: "a\n"},
		{name: "literal next interrupt", input: "\x16\x03\n", echo: "^\b^C\r\n", read: "\x03\n"},
		{name: "literal next newline", input: "a\x16\nb\n", echo: "a^\b^Jb\r\n", read: "a\nb\n"},
		{name: "literal next without ECHOCTL", lflagsOff: linux.ECHOCTL, input: "\x16\x03\n", echo: "\x03\r\n", read: "\x03\n"},
		{name: "reprint", input: "a\x01\x12", echo: "a^A^R\r\na^A"},
		{name: "ECHONL without ECHO", lflagsOn: linux.ECHONL, lflagsOff: linux.ECHO, input: "ab\r", echo: "\r\n", read: "ab\n"},
		{name: "noncanonical literal next and reprint", lflagsOff: linux.ICANON, input: "\x16\x12", echo: "^V^R", read: "\x16\x12"},
		{name: "stop and start", input: "\x13\x11a\n", echo: "a\r\n", read: "a\n"},
		{name: "stop holds echoes", lflagsOff: linux.ICANON, input: "\x13ab", read: "ab"},
		{name: "control characters", input: "a\x01\x1b\tb\n", echo: "a^A^[\tb\r\n", read: "a\x01\x1b\tb\n"},
		{name: "control characters without ECHOCTL", lflagsOff: linux.ECHOCTL, input: "a\x01b\n", echo: "a\x01b\r\n", read: "a\x01b\n"},
		{name: "carriage return", input: "\r", echo: "\r\n", read: "\n"},
		{name: "noncanonical newline", lflagsOff: linux.ICANON, input: "\n", echo: "^J", read: "\n"},
		{name: "noncanonical carriage return", lflagsOff: linux.ICANON, input: "\r", echo: "\r\n", read: "\n"},
		{name: "noncanonical delete", lflagsOff: linux.ICANON, input: "\x7f", echo: "^?", read: "\x7f"},
	} {
		t.Run(test.name, func(t *testing.T) {
			termios := linux.DefaultReplicaTermios
			termios.LocalFlags |= test.lflagsOn
			termios.LocalFlags &^= test.lflagsOff
			ld := newTestLineDiscipline(termios)

			n, err := ld.inputQueueWrite(contexttest.Context(t), usermem.BytesIOSequence([]byte(test.input)))
			if err != nil || n != int64(len(test.input)) {
				t.Fatalf("inputQueueWrite(%q) = %d, %v, want %d, nil", test.input, n, err, len(test.input))
			}
			if got := readAvailable(t, ld.outputQueueRead); got != test.echo {
				t.Errorf("echo of %q: got %q, want %q", test.input, got, test.echo)
			}
			if got := readAvailable(t, ld.inputQueueRead); got != test.read {
				t.Errorf("read of %q: got %q, want %q", test.input, got, test.read)
			}
		})
	}
}

// TestFlowControl checks that VSTOP and VSTART stop and start output under
// IXON, as drivers/tty/n_tty.c and drivers/tty/pty.c do on Linux.
func TestFlowControl(t *testing.T) {
	ctx := contexttest.Context(t)
	ld := newTestLineDiscipline(linux.DefaultReplicaTermios)
	ld.setPacketMode(1)
	typeInput := func(input string) {
		t.Helper()
		if _, err := ld.inputQueueWrite(ctx, usermem.BytesIOSequence([]byte(input))); err != nil {
			t.Fatalf("inputQueueWrite(%q): %v", input, err)
		}
	}
	expectRead := func(want string) {
		t.Helper()
		if got := readAvailable(t, ld.outputQueueRead); got != want {
			t.Errorf("master read: got %q, want %q", got, want)
		}
	}
	writeOutput := func() error {
		_, err := ld.outputQueueWrite(ctx, usermem.BytesIOSequence([]byte("out")))
		return err
	}

	typeInput("\x13")
	expectRead(string([]byte{linux.TIOCPKT_STOP}))
	if ld.replicaReadiness()&waiter.WritableEvents != 0 {
		t.Errorf("replica is writable while output is stopped")
	}
	if err := writeOutput(); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		t.Errorf("outputQueueWrite while output is stopped: got %v, want %v", err, linuxerr.ErrWouldBlock)
	}
	// The echo waits for output to start.
	typeInput("a")
	expectRead("")

	typeInput("\x11")
	expectRead(string([]byte{linux.TIOCPKT_START}))
	expectRead("\x00a")
	if ld.replicaReadiness()&waiter.WritableEvents == 0 {
		t.Errorf("replica is not writable once output starts")
	}
	if err := writeOutput(); err != nil {
		t.Errorf("outputQueueWrite: %v", err)
	}
	expectRead("\x00out")
}
