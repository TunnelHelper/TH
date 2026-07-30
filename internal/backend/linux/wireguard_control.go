//go:build linux

package linux

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mdlayher/genetlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type wireGuardControl struct {
	timeout time.Duration
	mu      sync.Mutex
	client  *wgctrl.Client
}

func newWireGuardControl(timeout time.Duration) *wireGuardControl {
	control := &wireGuardControl{timeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, _ = control.kernelClient(ctx)
	return control
}

func (c *wireGuardControl) health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("open WireGuard kernel generic netlink: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set WireGuard kernel generic-netlink deadline: %w", err)
	}
	if _, err := conn.GetFamily(unix.WG_GENL_NAME); err != nil {
		return fmt.Errorf("resolve WireGuard kernel generic-netlink family %q: %w", unix.WG_GENL_NAME, err)
	}
	return nil
}

func (c *wireGuardControl) kernelClient(ctx context.Context) (*wgctrl.Client, error) {
	if err := c.health(ctx); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open WireGuard kernel control client: %w", err)
	}
	c.client = client
	return c.client, nil
}

func (c *wireGuardControl) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return nil
	}
	err := c.client.Close()
	c.client = nil
	return err
}
