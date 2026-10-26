package githttp

import (
	"fmt"
	"io"
)

// Git's pkt-line framing: a 4-byte hex length prefix covering the prefix
// itself, then the payload. "0000" is a flush packet.
//
// The gateway only needs to emit the service advertisement header; the rest
// of the protocol is handled by git-receive-pack itself.

// writePktLine writes one pkt-line containing s.
func writePktLine(w io.Writer, s string) error {
	if len(s)+4 > 65520 {
		return fmt.Errorf("pkt-line payload too long: %d bytes", len(s))
	}
	if _, err := fmt.Fprintf(w, "%04x%s", len(s)+4, s); err != nil {
		return fmt.Errorf("write pkt-line: %w", err)
	}
	return nil
}

// writeFlush writes the flush packet that ends a pkt-line section.
func writeFlush(w io.Writer) error {
	if _, err := io.WriteString(w, "0000"); err != nil {
		return fmt.Errorf("write flush packet: %w", err)
	}
	return nil
}
