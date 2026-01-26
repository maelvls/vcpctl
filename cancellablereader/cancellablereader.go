package cancellablereader

import (
	"context"
	"io"
)

func ReadAllWithContext(ctx context.Context, r io.Reader) ([]byte, error) {
	return io.ReadAll(New(ctx, r))
}

type CancelableReader struct {
	ctx  context.Context
	data chan []byte
	err  error
	r    io.Reader
	pend []byte
}

func (c *CancelableReader) begin() {
	buf := make([]byte, 1024)
	for {
		n, err := c.r.Read(buf)
		if n > 0 {
			tmp := make([]byte, n)
			copy(tmp, buf[:n])
			c.data <- tmp
		}
		if err != nil {
			c.err = err
			close(c.data)
			return
		}
	}
}

func (c *CancelableReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pend) == 0 {
		select {
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		case d, ok := <-c.data:
			if !ok {
				return 0, c.err
			}
			c.pend = d
		}
	}
	n := copy(p, c.pend)
	c.pend = c.pend[n:]
	return n, nil
}

func New(ctx context.Context, r io.Reader) *CancelableReader {
	c := &CancelableReader{
		r:    r,
		ctx:  ctx,
		data: make(chan []byte),
	}
	go c.begin()
	return c
}
