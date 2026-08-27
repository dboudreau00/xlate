package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// AuditRecord is one line of the append-only JSONL audit trail. Records
// are hash-chained: Hash = SHA-256 over the record serialized with Hash
// empty, and Prev carries the previous record's Hash (genesis: 64 zeros).
// Any insertion, deletion, edit, or reorder breaks the chain from that
// point forward, detectable with -verify-audit.
//
// The trail never contains payload bodies or token values — translated
// traffic routinely carries payment identifiers and PII, and credentials
// do not belong in logs under any circumstances.
type AuditRecord struct {
	Seq    uint64         `json:"seq"`
	Time   string         `json:"time"` // RFC3339Nano UTC
	Actor  string         `json:"actor"`
	Event  string         `json:"event"`
	Detail map[string]any `json:"detail,omitempty"`
	Prev   string         `json:"prev"`
	Hash   string         `json:"hash"`
}

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event classes considered security-relevant get an fsync per record;
// routine traffic records are flushed but rely on the OS for durability.
func criticalEvent(event string) bool {
	switch {
	case strings.HasPrefix(event, "tripwire."),
		strings.HasPrefix(event, "account."),
		strings.HasPrefix(event, "alert."),
		strings.HasPrefix(event, "server."),
		event == "ingest.denied",
		event == "ingest.blocked",
		event == "admin.denied":
		return true
	}
	return false
}

type AuditLog struct {
	mu   sync.Mutex
	f    *os.File
	end  int64 // byte offset of the end of the last durable record
	seq  uint64
	prev string
}

// OpenAudit opens (or creates, 0600) the trail and resumes the chain from
// the last valid record so restarts extend rather than restart the chain.
//
// A crash can tear the final line: routine records are not fsynced, so
// power loss legitimately leaves a partial record at the tail. That torn
// line was never durably part of the chain, and left in place it would
// merge with the next appended record and poison verification forever.
// Standard WAL recovery applies: truncate an unterminated tail back to
// the last complete record. Only a newline-less final fragment is
// removed — complete lines that fail to parse are left for -verify-audit
// to flag, because those are evidence of tampering, not of a crash.
func OpenAudit(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	a := &AuditLog{f: f, prev: genesisHash}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lineEnd int64 // offset just past the newline of the last scanned line
	for sc.Scan() {
		// +1 for the newline Scan strips. A final line without a newline
		// deliberately overcounts here; the torn-tail check below compares
		// against the real size, and a.end only advances for lines that
		// parsed, so the fragment is never counted as durable.
		lineEnd += int64(len(sc.Bytes())) + 1
		var r AuditRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Hash != "" {
			a.seq, a.prev, a.end = r.Seq, r.Hash, lineEnd
		} else if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			a.end = lineEnd // blank lines are tolerated by verification
		}
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if tail := st.Size() - a.end; tail > 0 {
		raw := make([]byte, int(min(tail, 4096)))
		if _, err := f.ReadAt(raw, a.end); err == nil && !bytes.Contains(raw, []byte{'\n'}) {
			if err := f.Truncate(a.end); err != nil {
				f.Close()
				return nil, fmt.Errorf("audit: cannot repair torn tail (%d bytes): %w", tail, err)
			}
			log.Printf("audit: repaired torn tail — truncated %d bytes of a partial record left by a crash", tail)
		} else {
			// Complete-but-invalid trailing lines: keep the bytes as
			// evidence and append after them; verification will flag them.
			a.end = st.Size()
		}
	}
	if _, err := f.Seek(a.end, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return a, nil
}

// Emit appends one record. Failures are reported to the caller but must
// not take the data plane down; the server logs them loudly instead.
//
// Records go to the file directly — with a flush per record a buffer adds
// nothing, and bufio's sticky error state would turn one transient write
// failure into a permanently dead trail. A failed append instead truncates
// back to the last good record, so the file stays parseable and the next
// Emit gets a clean retry.
func (a *AuditLog) Emit(actor, event string, detail map[string]any) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := AuditRecord{
		Seq:    a.seq + 1,
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Actor:  actor,
		Event:  event,
		Detail: detail,
		Prev:   a.prev,
	}
	rec.Hash = hashRecord(&rec)
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		// Undo any partial bytes; if even that fails, the next Emit will
		// land after a torn fragment, which reopen-recovery repairs.
		_ = a.f.Truncate(a.end)
		_, _ = a.f.Seek(a.end, io.SeekStart)
		return err
	}
	a.seq, a.prev = rec.Seq, rec.Hash
	a.end += int64(len(line)) + 1
	if criticalEvent(event) {
		return a.f.Sync()
	}
	return nil
}

func (a *AuditLog) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.f.Sync()
	return a.f.Close()
}

// hashRecord computes the chained hash over a canonical serialization:
// the record (Hash empty) is marshaled, round-tripped through generic
// values, and re-marshaled. The round trip matters — the writer holds Go
// structs in Detail (fields emit in declaration order) while the verifier
// re-reads them as maps (keys emit sorted); without canonicalization the
// two sides hash different bytes for identical content. UseNumber keeps
// numerics verbatim through the trip.
func hashRecord(r *AuditRecord) string {
	c := *r
	c.Hash = ""
	raw, _ := json.Marshal(c)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err == nil {
		if b, err := json.Marshal(v); err == nil {
			raw = b
		}
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// lastLineIsTorn reports which line number a newline-less final fragment
// occupies, or 0 when the file ends cleanly. It reads the file
// independently of the caller's scanner position.
func lastLineIsTorn(f *os.File) (int, error) {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return 0, err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, st.Size()-1); err != nil {
		return 0, err
	}
	if last[0] == '\n' {
		return 0, nil
	}
	// Count lines to identify the fragment's line number.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
	}
	return n, sc.Err()
}

// VerifyAudit walks a trail file and reports the first chain break.
func VerifyAudit(path string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	prev, n, line := genesisHash, 0, 0
	for sc.Scan() {
		line++
		txt := strings.TrimSpace(sc.Text())
		if txt == "" {
			continue
		}
		var r AuditRecord
		rdec := json.NewDecoder(strings.NewReader(txt))
		rdec.UseNumber()
		if err := rdec.Decode(&r); err != nil {
			// A newline-less final fragment is crash damage, not
			// tampering — say so, or an operator reads a power cut as a
			// breach. The server repairs it on its next start.
			if last, lerr := lastLineIsTorn(f); lerr == nil && last == line {
				return fmt.Errorf("line %d: final record is torn (no trailing newline — crash damage, repaired automatically on the next server start): %w", line, err)
			}
			return fmt.Errorf("line %d: unparseable record: %w", line, err)
		}
		if r.Prev != prev {
			return fmt.Errorf("line %d (seq %d): chain break — prev is %.12s…, expected %.12s…", line, r.Seq, r.Prev, prev)
		}
		if got := hashRecord(&r); got != r.Hash {
			return fmt.Errorf("line %d (seq %d): record tampered — hash mismatch", line, r.Seq)
		}
		prev = r.Hash
		n++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	fmt.Fprintf(out, "audit chain OK: %d records, tail %.12s…\n", n, prev)
	return nil
}
