package transport

import (
	"net"

	"github.com/airlance/api/internal/infrastructure/logger"
)

type Handler func(conn *Connection)

type Listener struct {
	addr    string
	handler Handler
}

func NewListener(addr string, handler Handler) *Listener {
	return &Listener{addr: addr, handler: handler}
}

func (l *Listener) ListenAndServe() error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	logger.Log.WithField("addr", l.addr).Info("transport: listening on address")

	for {
		rawConn, err := ln.Accept()
		if err != nil {
			// net.Listener.Accept возвращает ошибку и при штатном закрытии
			// самого listener'а (ln.Close() вызван снаружи) — в этом случае
			// продолжать accept loop бессмысленно и вредно (будет крутиться
			// в busy-loop на постоянно возвращающемся Accept). На этом этапе
			// у нас нет отдельного канала для отличения "listener закрыт
			// намеренно" от "временный сбой accept" — просто выходим и
			// пробрасываем ошибку. Если понадобится graceful shutdown без
			// трактовки закрытия как ошибки — это явное расширение API
			// (например, context.Context + errors.Is(err, net.ErrClosed)),
			// откладываю до момента, когда появится реальный caller для
			// graceful shutdown, а не гадаю про форму API заранее.
			return err
		}

		conn := NewConnection(rawConn)
		go l.handler(conn)
	}
}
