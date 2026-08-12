package noiseik

import (
	"time"

	"github.com/airlance/api/internal/transport"
)

type Conn struct {
	raw     *transport.Connection
	session *session
}

func (c *Conn) ReadFrame() ([]byte, error) {
	ciphertext, err := c.raw.ReadFrame()
	if err != nil {
		return nil, err
	}
	return c.session.decrypt(ciphertext)
}

func (c *Conn) WriteFrame(plaintext []byte) error {
	ciphertext, err := c.session.encrypt(plaintext)
	if err != nil {
		return err
	}
	return c.raw.WriteFrame(ciphertext)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *Conn) Close() error {
	return c.raw.Close()
}

func (c *Conn) RemoteStaticKey() []byte {
	return c.session.remoteStatic
}
