package memberlist

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	mkm := make([]byte, 256)
	_, err := io.ReadFull(rand.Reader, mkm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	kr, err := NewKeyring(mkm, 0)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	plaintext := []byte("this is a plain text message")
	extra := []byte("random data")

	var buf bytes.Buffer
	err = encryptPayload(2, kr, plaintext, extra, &buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expLen := encryptedLength(2, len(plaintext))
	if buf.Len() != expLen {
		t.Fatalf("output length is unexpected %d %d %d", len(plaintext), buf.Len(), expLen)
	}

	msg, err := decryptPayload(kr, buf.Bytes(), extra)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	cmp := bytes.Compare(msg, plaintext)
	if cmp != 0 {
		t.Errorf("len %d %v", len(msg), msg)
		t.Errorf("len %d %v", len(plaintext), plaintext)
		t.Fatalf("encrypt/decrypt failed! %d '%s' '%s'", cmp, msg, plaintext)
	}
}
