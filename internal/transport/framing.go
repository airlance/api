package transport

import (
	"encoding/binary"
	"fmt"
	"io"
)

const MaxFrameSize = 1 << 20
const lengthPrefixSize = 4

var ErrFrameTooLarge = fmt.Errorf("transport: frame exceeds max size (%d bytes)", MaxFrameSize)

func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [lengthPrefixSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}

	var lenBuf [lengthPrefixSize]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}

	return nil
}
