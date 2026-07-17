//go:build linux

package linux

import (
	"net"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/core"
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

func (b *Backend) signalEvent(event core.BackendEvent) {
	select {
	case b.events <- event:
	default:
	}
}

func eventForLink(eventType core.BackendEventType, link netlink.Link) (core.BackendEvent, bool) {
	if link == nil || link.Attrs() == nil {
		return core.BackendEvent{}, false
	}
	alias := link.Attrs().Alias
	id, managed := strings.CutPrefix(alias, "th:")
	if !managed || id == "" {
		return core.BackendEvent{}, false
	}
	return core.BackendEvent{Type: eventType, RecordID: id, Interface: link.Attrs().Name}, true
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
			managedDown := update.Link != nil && strings.HasPrefix(update.Link.Attrs().Alias, "th:") &&
				update.Link.Attrs().Flags&net.FlagUp == 0
			if update.Header.Type == unix.RTM_DELLINK || managedDown {
				if event, ok := eventForLink(core.BackendEventLink, update.Link); ok {
					b.signalEvent(event)
				}
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
				link, err := b.netlink.LinkByIndex(update.LinkIndex)
				if err != nil {
					continue
				}
				if event, ok := eventForLink(core.BackendEventAddress, link); ok {
					b.signalEvent(event)
				}
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
				event := core.BackendEvent{Type: core.BackendEventRoute, RouteTable: update.Table}
				if update.LinkIndex != 0 {
					if link, err := b.netlink.LinkByIndex(update.LinkIndex); err == nil {
						if linkEvent, ok := eventForLink(core.BackendEventRoute, link); ok {
							event.RecordID = linkEvent.RecordID
							event.Interface = linkEvent.Interface
						}
					}
				}
				if event.RecordID == "" && event.RouteTable == 0 {
					event = core.BackendEvent{}
				}
				b.signalEvent(event)
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
			case update, ok := <-updates:
				if !ok {
					updates = nil
					continue
				}
				event := core.BackendEvent{Type: core.BackendEventXFRM}
				if expired, ok := update.(*netlink.XfrmMsgExpire); ok && expired.XfrmState != nil {
					event.XFRMIfID = uint32(expired.XfrmState.Ifid)
				}
				b.signalEvent(event)
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
		err := b.vici.watchEvents(b.eventCtx, func() {
			b.signalEvent(core.BackendEvent{Type: core.BackendEventVICI})
		})
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
