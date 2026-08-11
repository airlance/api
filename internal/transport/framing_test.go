package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestWriteFrameThenReadFrame_Roundtrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello, protocol")

	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, payload)
	}
}

func TestWriteFrame_EmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte{}); err != nil {
		t.Fatalf("WriteFrame failed on empty payload: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got))
	}
}

func TestWriteFrame_RejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	oversized := make([]byte, MaxFrameSize+1)

	err := WriteFrame(&buf, oversized)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected nothing written to buf on rejection, got %d bytes", buf.Len())
	}
}

func TestReadFrame_RejectsOversizedLengthPrefix_WithoutAllocating(t *testing.T) {
	var lenBuf [4]byte

	claimedLength := uint32(MaxFrameSize) * 2
	binary.BigEndian.PutUint32(lenBuf[:], claimedLength)

	r := io.MultiReader(bytes.NewReader(lenBuf[:]), bytes.NewReader(nil))

	_, err := ReadFrame(r)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge (checked before body read), got %v", err)
	}
}

func TestReadFrame_EOFOnConnectionBoundary(t *testing.T) {
	var buf bytes.Buffer

	_, err := ReadFrame(&buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on empty read, got %v", err)
	}
}

func TestReadFrame_UnexpectedEOFMidFrame(t *testing.T) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 100) // заявляем 100 байт тела
	r := io.MultiReader(bytes.NewReader(lenBuf[:]), bytes.NewReader([]byte{1, 2, 3, 4, 5}))

	_, err := ReadFrame(r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF for truncated frame, got %v", err)
	}
}

func TestWriteFrame_LengthPrefixIsBigEndian(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte{0xAA, 0xBB, 0xCC}

	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	header := buf.Bytes()[:4]
	got := binary.BigEndian.Uint32(header)
	if got != uint32(len(payload)) {
		t.Fatalf("length prefix mismatch: got %d, want %d", got, len(payload))
	}
}

func TestReadFrame_MultipleFramesSequentially(t *testing.T) {
	var buf bytes.Buffer
	frames := [][]byte{
		[]byte("first"),
		[]byte("second, a bit longer"),
		{},
		[]byte("fourth"),
	}

	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame failed: %v", err)
		}
	}

	for i, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame #%d failed: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame #%d mismatch: got %q, want %q", i, got, want)
		}
	}

	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after all frames consumed, got %v", err)
	}
}
