//go:build linux

package linux

import (
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func (b *Backend) startEventWatchers() {
	b.watchLinkEvents()
	b.watchAddressEvents()
	b.watchRouteEvents()
	b.watchXFRMEvents()
	b.eventWG.Add(1)
	go func() {
		defer b.eventWG.Done()
		b.watchVICIEvents()
	}()
}

func (b *Backend) signalEvent() {
	select {
	case b.events <- struct{}{}:
	default:
	}
}

func (b *Backend) watchLinkEvents() {
	updates := make(chan netlink.LinkUpdate, 16)
	if err := netlink.LinkSubscribe(updates, b.eventCtx.Done()); err != nil {
		return
	}
	b.eventWG.Add(1)
	go func() {
		defer b.eventWG.Done()
		for update := range updates {
			managedDown := update.Link != nil && strings.HasPrefix(update.Link.Attrs().Alias, "tunnel-helper:") &&
				update.Link.Attrs().Flags&net.FlagUp == 0
			if update.Header.Type == unix.RTM_DELLINK || managedDown {
				b.signalEvent()
			}
		}
	}()
}

func (b *Backend) watchAddressEvents() {
	updates := make(chan netlink.AddrUpdate, 16)
	if err := netlink.AddrSubscribe(updates, b.eventCtx.Done()); err != nil {
		return
	}
	b.eventWG.Add(1)
	go func() {
		defer b.eventWG.Done()
		for update := range updates {
			if !update.NewAddr {
				b.signalEvent()
			}
		}
	}()
}

func (b *Backend) watchRouteEvents() {
	updates := make(chan netlink.RouteUpdate, 16)
	if err := netlink.RouteSubscribe(updates, b.eventCtx.Done()); err != nil {
		return
	}
	b.eventWG.Add(1)
	go func() {
		defer b.eventWG.Done()
		for update := range updates {
			if update.Type == unix.RTM_DELROUTE && update.Protocol == managedRouteProtocol {
				b.signalEvent()
			}
		}
	}()
}

func (b *Backend) watchXFRMEvents() {
	updates := make(chan netlink.XfrmMsg, 8)
	errors := make(chan error, 1)
	if err := netlink.XfrmMonitor(updates, b.eventCtx.Done(), errors, nl.XFRM_MSG_EXPIRE); err != nil {
		return
	}
	b.eventWG.Add(1)
	go func() {
		defer b.eventWG.Done()
		for updates != nil || errors != nil {
			select {
			case _, ok := <-updates:
				if !ok {
					updates = nil
					continue
				}
				b.signalEvent()
			case _, ok := <-errors:
				if !ok {
					errors = nil
				}
			case <-b.eventCtx.Done():
				return
			}
		}
	}()
}

func (b *Backend) watchVICIEvents() {
	for {
		err := b.vici.watchEvents(b.eventCtx, b.signalEvent)
		if b.eventCtx.Err() != nil {
			return
		}
		if err == nil {
			return
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-b.eventCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}
