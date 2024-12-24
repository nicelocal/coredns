package cache

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/request"
	"github.com/infobloxopen/go-trees/iptree"

	"github.com/miekg/dns"
)

// Use ::/0 as wildcard key for queries without ECS (both v4 and v6)
var zeroSubnet = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

// Use 0.0.0.0/0 as wildcard key for private ECS queries (both v4 and v6)
// (i.e. those were the client explicitly asked via ECS to not pass our IP to upstreams)
var privateZeroSubnet = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

// ServeDNS implements the plugin.Handler interface.
func (c *Cache) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	rc := r.Copy() // We potentially modify r, to prevent other plugins from seeing this (r is a pointer), copy r into rc.
	state := request.Request{W: w, Req: rc}
	do := state.Do()
	cd := r.CheckingDisabled
	ad := r.AuthenticatedData

	zone := plugin.Zones(c.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(c.Name(), c.Next, ctx, w, rc)
	}

	now := c.now().UTC()
	server := metrics.WithServer(ctx)

	// On cache refresh, we will just use the DO bit from the incoming query for the refresh since we key our cache
	// with the query DO bit. That means two separate cache items for the query DO bit true or false. In the situation
	// in which upstream doesn't support DNSSEC, the two cache items will effectively be the same. Regardless, any
	// DNSSEC RRs in the response are written to cache with the response.

	subnet := &zeroSubnet
	o := r.IsEdns0()
	var ecs *dns.EDNS0_SUBNET
	var ok bool
	if o != nil {
		for _, s := range o.Option {
			if ecs, ok = s.(*dns.EDNS0_SUBNET); ok {
				// Section 7.1.1, "Recursive Resolvers".
				// If the triggering query included an ECS option itself, it MUST be
				// examined for its SOURCE PREFIX-LENGTH.  The Recursive Resolver's
				// outgoing query MUST then set SOURCE PREFIX-LENGTH to the shorter of
				// the incoming query's SOURCE PREFIX-LENGTH or the server's maximum
				// cacheable prefix length.

				// Section 7.1.3, "Forwarding Resolvers".
				// Forwarding Resolvers essentially appear to be Stub Resolvers to
				// whatever Recursive Resolver is ultimately handling the query, but
				// they look like a Recursive Resolver to their client.  A Forwarding
				// Resolver using this option MUST prepare it as described in
				// Section 7.1.1, "Recursive Resolvers".

				var mask net.IPMask
				if ecs.Family == 1 {
					ecs.SourceNetmask = min(ecs.SourceNetmask, c.mask_v4)
					mask = net.CIDRMask(int(ecs.SourceNetmask), 32)
				} else {
					ecs.SourceNetmask = min(ecs.SourceNetmask, c.mask_v6)
					mask = net.CIDRMask(int(ecs.SourceNetmask), 128)
				}
				ecs.Address = ecs.Address.Mask(mask)
				if ecs.SourceNetmask == 0 {
					subnet = &privateZeroSubnet
				} else {
					subnet = &net.IPNet{IP: ecs.Address, Mask: mask}
				}
				break
			}
		}
	}

	// TODO: Retry resolving without ECS data if REFUSED is returned (https://www.rfc-editor.org/rfc/rfc7871#section-7.1.3)

	ttl := 0
	i := c.getIgnoreTTL(now, state, subnet, server)
	if i == nil {
		crr := &ResponseWriter{ResponseWriter: w, Cache: c, state: state, server: server, do: do, ad: ad, cd: cd,
			subnet:  subnet,
			ecs:     ecs,
			nexcept: c.nexcept, pexcept: c.pexcept, wildcardFunc: wildcardFunc(ctx)}
		return c.doRefresh(ctx, state, crr)
	}
	ttl = i.ttl(now)
	if ttl < 0 {
		// serve stale behavior
		if c.verifyStale {
			crr := &ResponseWriter{ResponseWriter: w, Cache: c, state: state, server: server, do: do, cd: cd,
				subnet: subnet,
				ecs:    ecs}
			cw := newVerifyStaleResponseWriter(crr)
			ret, err := c.doRefresh(ctx, state, cw)
			if cw.refreshed {
				return ret, err
			}
		}

		// Adjust the time to get a 0 TTL in the reply built from a stale item.
		now = now.Add(time.Duration(ttl) * time.Second)
		if !c.verifyStale {
			cw := newPrefetchResponseWriter(server, state, subnet, ecs, c)
			go c.doPrefetch(ctx, state, cw, i, subnet, now)
		}
		servedStale.WithLabelValues(server, c.zonesMetricLabel, c.viewMetricLabel).Inc()
	} else if c.shouldPrefetch(i, now) {
		cw := newPrefetchResponseWriter(server, state, subnet, ecs, c)
		go c.doPrefetch(ctx, state, cw, i, subnet, now)
	}

	if i.wildcard != "" {
		// Set wildcard source record name to metadata
		metadata.SetValueFunc(ctx, "zone/wildcard", func() string {
			return i.wildcard
		})
	}

	if c.keepttl {
		// If keepttl is enabled we fake the current time to the stored
		// one so that we always get the original TTL
		now = i.stored
	}
	resp := i.toMsg(r, now, do, ad)
	w.WriteMsg(resp)
	return dns.RcodeSuccess, nil
}

func wildcardFunc(ctx context.Context) func() string {
	return func() string {
		// Get wildcard source record name from metadata
		if f := metadata.ValueFunc(ctx, "zone/wildcard"); f != nil {
			return f()
		}
		return ""
	}
}

func (c *Cache) doPrefetch(ctx context.Context, state request.Request, cw *ResponseWriter, i *item, subnet *net.IPNet, now time.Time) {
	cachePrefetches.WithLabelValues(cw.server, c.zonesMetricLabel, c.viewMetricLabel).Inc()
	c.doRefresh(ctx, state, cw)

	// When prefetching we loose the item i, and with it the frequency
	// that we've gathered sofar. See we copy the frequencies info back
	// into the new item that was stored in the cache.
	if i1 := c.exists(state, subnet); i1 != nil {
		i1.Freq.Reset(now, i.Freq.Hits())
	}
}

func (c *Cache) doRefresh(ctx context.Context, state request.Request, cw dns.ResponseWriter) (int, error) {
	return plugin.NextOrFailure(c.Name(), c.Next, ctx, cw, state.Req)
}

func (c *Cache) shouldPrefetch(i *item, now time.Time) bool {
	if c.prefetch <= 0 {
		return false
	}
	i.Freq.Update(c.duration, now)
	threshold := int(math.Ceil(float64(c.percentage) / 100 * float64(i.origTTL)))
	return i.Freq.Hits() >= c.prefetch && i.ttl(now) <= threshold
}

// Name implements the Handler interface.
func (c *Cache) Name() string { return "cache" }

// getIgnoreTTL unconditionally returns an item if it exists in the cache.
func (c *Cache) getIgnoreTTL(now time.Time, state request.Request, subnet *net.IPNet, server string) *item {
	fmt.Println("Fetching for ", subnet.String())

	k := hash(state.Name(), state.QType(), state.Do(), state.Req.CheckingDisabled)
	cacheRequests.WithLabelValues(server, c.zonesMetricLabel, c.viewMetricLabel).Inc()

	if i, ok := c.ncache.Get(k); ok {
		tree := i.(*iptree.Tree)
		if ii, ok := tree.GetByNet(subnet); ok {
			itm := ii.(*item)
			ttl := itm.ttl(now)
			if itm.matches(state) && (ttl > 0 || (c.staleUpTo > 0 && -ttl < int(c.staleUpTo.Seconds()))) {
				cacheHits.WithLabelValues(server, Denial, c.zonesMetricLabel, c.viewMetricLabel).Inc()
				return itm
			}
		}
	}
	if i, ok := c.pcache.Get(k); ok {
		tree := i.(*iptree.Tree)
		if ii, ok := tree.GetByNet(subnet); ok {
			itm := ii.(*item)
			ttl := itm.ttl(now)
			if itm.matches(state) && (ttl > 0 || (c.staleUpTo > 0 && -ttl < int(c.staleUpTo.Seconds()))) {
				cacheHits.WithLabelValues(server, Success, c.zonesMetricLabel, c.viewMetricLabel).Inc()
				return itm
			}
		}
	}
	if subnet != &zeroSubnet {
		return c.getIgnoreTTL(now, state, &zeroSubnet, server)
	}

	cacheMisses.WithLabelValues(server, c.zonesMetricLabel, c.viewMetricLabel).Inc()
	return nil
}

func (c *Cache) exists(state request.Request, subnet *net.IPNet) *item {
	k := hash(state.Name(), state.QType(), state.Do(), state.Req.CheckingDisabled)
	if i, ok := c.ncache.Get(k); ok {
		tree := i.(*iptree.Tree)
		if ii, ok := tree.GetByNet(subnet); ok {
			return ii.(*item)
		}
	}
	if i, ok := c.pcache.Get(k); ok {
		tree := i.(*iptree.Tree)
		if ii, ok := tree.GetByNet(subnet); ok {
			return ii.(*item)
		}
	}
	if subnet != &zeroSubnet {
		return c.exists(state, &zeroSubnet)
	}
	return nil
}
