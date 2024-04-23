package zenet

import (
    "context"
    "encoding/json"
    "fmt"
    "net"
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/request"
    "github.com/coredns/caddy"
    "github.com/miekg/dns"
    "go.nanomsg.org/mangos/v3"
    "go.nanomsg.org/mangos/v3/protocol/req"
    _ "go.nanomsg.org/mangos/v3/transport/tcp"
)

type ZenetPlugin struct {
    Next plugin.Handler
    Addr string
    Sock mangos.Socket
}

type ResolverQuery struct {
    Query struct {
        Name  string `json:"name"`
        QType string `json:"type"`
    } `json:"query"`
}

type Message struct {
    Query []string `json:"query"`
}

func typeToString(qtype uint16) string {
    switch qtype {
    case dns.TypeA:
        return "A"
    case dns.TypeAAAA:
        return "AAAA"
    case dns.TypeTXT:
        return "TXT"
    default:
        return "UNSUPPORTED"
    }
}

func (zp *ZenetPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    state := request.Request{W: w, Req: r}

    queryData := ResolverQuery{}
    queryData.Query.Name = state.Name()
    queryData.Query.QType = typeToString(state.QType())

    jsonData, err := json.Marshal(queryData)
    if err != nil {
        return dns.RcodeServerFailure, fmt.Errorf("failed to encode query as JSON: %v", err)
    }

    if err := zp.Sock.Send(jsonData); err != nil {
        return dns.RcodeServerFailure, fmt.Errorf("failed to send query to mangos service: %v", err)
    }

    msg, err := zp.Sock.Recv()
    if err != nil {
        return dns.RcodeServerFailure, fmt.Errorf("failed to receive reply from mangos service: %v", err)
    }

    var msgData Message
    if err = json.Unmarshal(msg, &msgData); err != nil {
        return dns.RcodeServerFailure, fmt.Errorf("failed to decode JSON message: %v", err)
    }

    msgResp := new(dns.Msg)
    msgResp.SetReply(r)
    msgResp.Authoritative = true

    switch state.QType() {
    case dns.TypeA, dns.TypeAAAA:
        ip := net.ParseIP(msgData.Query[0])
        if ip == nil {
            return dns.RcodeServerFailure, fmt.Errorf("invalid IP address format: %s", msgData.Query[0])
        }
        appendIPResponse(ip, state.Name(), msgResp)
    case dns.TypeTXT:
        appendTXTResponse(msgData.Query, state.Name(), msgResp)
    default:
        return dns.RcodeNotImplemented, fmt.Errorf("unsupported query type")
    }

    w.WriteMsg(msgResp)
    return dns.RcodeSuccess, nil
}

func appendIPResponse(ip net.IP, name string, response *dns.Msg) {
    if ip.To4() != nil {
        response.Answer = append(response.Answer, &dns.A{
            Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
            A:    ip,
        })
    } else {
        response.Answer = append(response.Answer, &dns.AAAA{
            Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
            AAAA: ip,
        })
    }
}

func appendTXTResponse(txtRecords []string, name string, response *dns.Msg) {
    for _, txt := range txtRecords {
        txtRecord := &dns.TXT{
            Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
            Txt: []string{txt},
        }
        response.Answer = append(response.Answer, txtRecord)
    }
}

func (zp *ZenetPlugin) Name() string {
    return "zenet"
}

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
