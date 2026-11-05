package state

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/views"
)

// SetFunnelNode binds authority to a verified node ID, never to a claimable tag.
func (s *State) SetFunnelNode(id types.NodeID) { s.funnelNodeID.Store(id.Uint64()) }

// SetFunnelAvailable gates publication on startup success. Keep the identity
// binding on failure so user ACLs cannot grant the internal peer normal access.
func (s *State) SetFunnelAvailable(available bool) { s.funnelAvailable.Store(available) }

func (s *State) IsFunnelNode(id types.NodeID) bool {
	return s.cfg.DNSConfig.Funnel.Enabled && id != 0 && s.funnelNodeID.Load() == id.Uint64()
}

func (s *State) FunnelPort() string {
	_, port, _ := net.SplitHostPort(s.cfg.Addr)
	return port
}

// FunnelAuthorized is independent of the client's publication hint. The local
// AllowFunnel map is authoritative for each host:port at connection admission.
func (s *State) FunnelAuthorized(n types.NodeView) bool {
	if !s.cfg.DNSConfig.Funnel.Enabled || !n.Valid() || n.IsExpired() || s.IsFunnelNode(n.ID()) {
		return false
	}
	if _, ok := n.CertDomain(s.cfg); !ok {
		return false
	}
	_, ok := s.polMan.NodeCapMap(n.ID())[nodecap.Funnel]
	return ok
}

func (s *State) FunnelTarget(host string) (types.NodeView, bool) {
	if !s.funnelAvailable.Load() {
		return types.NodeView{}, false
	}
	entry, ok := s.GetNodeByID(types.NodeID(s.funnelNodeID.Load()))
	if !ok || entry.IsExpired() || !entry.IsTagged() {
		return types.NodeView{}, false
	}
	for _, n := range s.ListNodes().All() {
		if !s.FunnelAuthorized(n) || !n.Hostinfo().Valid() || !n.Hostinfo().IngressEnabled() {
			continue
		}
		name, _ := n.CertDomain(s.cfg)
		if name == strings.ToLower(host) {
			return n, true
		}
	}
	return types.NodeView{}, false
}

func (s *State) funnelNodeCaps(id types.NodeID, raw tailcfg.NodeCapMap) tailcfg.NodeCapMap {
	if _, present := raw[nodecap.Funnel]; !present {
		return raw
	}
	out := maps.Clone(raw)
	delete(out, nodecap.Funnel)
	for k := range out {
		if strings.HasPrefix(string(k), string(nodecap.FunnelPorts)) {
			delete(out, k)
		}
	}
	if n, ok := s.GetNodeByID(id); ok && s.funnelAvailable.Load() && s.FunnelAuthorized(n) {
		out[nodecap.Funnel] = nil
		out[nodecap.Cap(string(nodecap.FunnelPorts)+"?ports="+s.FunnelPort())] = nil
	}
	return out
}

func (s *State) funnelPeers(id types.NodeID) views.Slice[types.NodeView] {
	if !s.cfg.DNSConfig.Funnel.Enabled || s.funnelNodeID.Load() == 0 {
		return s.nodeStore.ListPeers(id)
	}
	self, ok := s.GetNodeByID(id)
	if !ok {
		return views.SliceOf([]types.NodeView{})
	}
	peers := make(map[types.NodeID]types.NodeView)
	if !s.IsFunnelNode(id) {
		for _, p := range s.nodeStore.ListPeers(id).All() {
			if !s.IsFunnelNode(p.ID()) {
				peers[p.ID()] = p
			}
		}
	}
	if s.IsFunnelNode(id) {
		for _, n := range s.ListNodes().All() {
			if s.funnelAvailable.Load() && s.FunnelAuthorized(n) {
				peers[n.ID()] = n
			}
		}
	} else if s.funnelAvailable.Load() && s.FunnelAuthorized(self) {
		if p, ok := s.GetNodeByID(types.NodeID(s.funnelNodeID.Load())); ok {
			peers[p.ID()] = p
		}
	}
	out := slices.Collect(maps.Values(peers))
	slices.SortFunc(out, func(a, b types.NodeView) int {
		if a.ID() < b.ID() {
			return -1
		}
		if a.ID() > b.ID() {
			return 1
		}
		return 0
	})
	return views.SliceOf(out)
}

func (s *State) funnelFilters(node types.NodeView, rules []tailcfg.FilterRule) ([]tailcfg.FilterRule, error) {
	if !s.cfg.DNSConfig.Funnel.Enabled || s.funnelNodeID.Load() == 0 {
		return rules, nil
	}
	entry, ok := s.GetNodeByID(types.NodeID(s.funnelNodeID.Load()))
	if !ok {
		return rules, nil
	}
	if s.IsFunnelNode(node.ID()) {
		return []tailcfg.FilterRule{}, nil
	}
	out := make([]tailcfg.FilterRule, 0, len(rules)+1)
	for _, rule := range rules {
		// Remove the internal peer from ALL user-defined traffic and app grants.
		var sources netipx.IPSetBuilder
		for _, src := range rule.SrcIPs {
			ips, err := util.ParseIPSet(src, nil)
			if err != nil {
				return nil, fmt.Errorf("funnel filter source %q: %w", src, err)
			}
			sources.AddSet(ips)
		}
		for _, ip := range entry.IPs() {
			sources.Remove(ip)
		}
		ips, err := sources.IPSet()
		if err != nil {
			return nil, err
		}
		if len(ips.Prefixes()) == 0 {
			continue
		}
		copyRule := rule
		copyRule.SrcIPs = nil
		for _, p := range ips.Prefixes() {
			copyRule.SrcIPs = append(copyRule.SrcIPs, p.String())
		}
		out = append(out, copyRule)
	}
	if s.funnelAvailable.Load() && s.FunnelAuthorized(node) {
		var src []string
		for _, ip := range entry.IPs() {
			src = append(src, ip.String())
		}
		var dst []netip.Prefix
		for _, ip := range node.IPs() {
			dst = append(dst, netip.PrefixFrom(ip, ip.BitLen()))
		}
		out = append(out, tailcfg.FilterRule{SrcIPs: src, CapGrant: []tailcfg.CapGrant{{Dsts: dst, CapMap: tailcfg.PeerCapMap{peercap.Ingress: nil}}}})
	}
	return out, nil
}
