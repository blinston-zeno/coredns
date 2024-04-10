package zenet

import (
    "context"
    "fmt"
    "net"

    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/request"
    "github.com/coredns/coredns/core/dnsserver"

    "github.com/coredns/caddy"
    "github.com/miekg/dns"
    "go.nanomsg.org/mangos/v3"
    "go.nanomsg.org/mangos/v3/protocol/req"
    _ "go.nanomsg.org/mangos/v3/transport/tcp"
)

type ZenetPlugin struct {
    Next plugin.Handler
    Addr string      // Address of the Mangos service
    Sock mangos.Socket
}

func (zp *ZenetPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    state := request.Request{W: w, Req: r}

    if err := zp.Sock.Send([]byte(state.Name())); err != nil {
        return dns.RcodeServerFailure, fmt.Errorf("failed to send query to mangos service: %v", err)
    }

    msg, err := zp.Sock.Recv()
    if err != nil {
        return dns.RcodeServerFailure, fmt.Errorf("failed to receive reply from mangos service: %v", err)
    }

    ip := net.ParseIP(string(msg))
    msgResp := new(dns.Msg)
    msgResp.SetReply(r)
    msgResp.Authoritative = true

    if ip.To4() != nil {
        aRecord := &dns.A{
            Hdr: dns.RR_Header{Name: state.Name(), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
            A:   ip,
        }
        msgResp.Answer = append(msgResp.Answer, aRecord)
    } else if ip.To16() != nil {
        aaaaRecord := &dns.AAAA{
            Hdr:  dns.RR_Header{Name: state.Name(), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
            AAAA: ip,
        }
        msgResp.Answer = append(msgResp.Answer, aaaaRecord)
    } else {
        // If the IP is neither IPv4 nor IPv6, return an error or handle appropriately.
        return dns.RcodeServerFailure, fmt.Errorf("invalid IP address format: %s", string(msg))
    }

    w.WriteMsg(msgResp)

    return dns.RcodeSuccess, nil
}

func (zp *ZenetPlugin) Name() string { return "zenet" }

func setup(c *caddy.Controller) error {
    addr := "tcp://localhost:40899"

    sock, err := req.NewSocket()
    if err != nil {
        return fmt.Errorf("failed to create mangos socket: %v", err)
    }
    if err := sock.Dial(addr); err != nil {
        return fmt.Errorf("failed to dial mangos service: %v", err)
    }

    c.Next()
    if c.NextArg() {
        return plugin.Error("zenet", c.ArgErr())
    }

    dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
        return &ZenetPlugin{Next: next, Addr: addr, Sock: sock}
    })

    return nil
}

func init() {
    plugin.Register("zenet", setup)
}
