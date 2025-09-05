package snmpscan

import (
    "fmt"
    "sort"
    "strings"
    "time"

    gosnmp "github.com/gosnmp/gosnmp"
)

type Result struct {
    Target      string
    Port        uint16
    Version     string
    Communities []Community
    System      SystemInfo
    Walk        []KV
    Errors      []string
}

type Community struct {
    Name      string
    ReadOnly  bool
    ReadWrite bool
}

type SystemInfo struct {
    SysDescr    string
    SysObjectID string
    SysUpTime   string
    SysContact  string
    SysName     string
    SysLocation string
}

type KV struct {
    OID   string
    Type  string
    Value string
}

var defaultCommunities = []string{
    "public", "private", "community", "admin", "cisco", "hp", "3com",
    "read", "write", "manager", "monitor", "guest", "test", "demo",
    "default", "system", "network", "security", "snmp", "trap",
    "ro", "rw", "readonly", "readwrite",
}

func Scan(target string, port int, timeout time.Duration) (*Result, error) {
    res := &Result{Target: target, Port: uint16(port)}

    // Detect version by trying v2c then v1
    version, community := detectVersionAndCommunity(target, uint16(port), timeout)
    res.Version = version
    if community != "" {
        res.Communities = append(res.Communities, Community{Name: community, ReadOnly: true})
    }

    if community == "" {
        // Brute force a few common communities for read access
        for _, c := range defaultCommunities {
            if tryGet(target, uint16(port), c, timeout, ".1.3.6.1.2.1.1.1.0") == nil {
                res.Communities = append(res.Communities, Community{Name: c, ReadOnly: true})
                community = c
                break
            }
        }
    }

    if community == "" {
        res.Errors = append(res.Errors, "no working community found")
        return res, nil
    }

    // System info
    sysOids := []string{
        ".1.3.6.1.2.1.1.1.0", // descr
        ".1.3.6.1.2.1.1.2.0", // object id
        ".1.3.6.1.2.1.1.3.0", // uptime
        ".1.3.6.1.2.1.1.4.0", // contact
        ".1.3.6.1.2.1.1.5.0", // name
        ".1.3.6.1.2.1.1.6.0", // location
    }
    vals, _ := bulkGet(target, uint16(port), community, timeout, sysOids)
    for _, kv := range vals {
        switch kv.OID {
        case ".1.3.6.1.2.1.1.1.0":
            res.System.SysDescr = kv.Value
        case ".1.3.6.1.2.1.1.2.0":
            res.System.SysObjectID = kv.Value
        case ".1.3.6.1.2.1.1.3.0":
            res.System.SysUpTime = kv.Value
        case ".1.3.6.1.2.1.1.4.0":
            res.System.SysContact = kv.Value
        case ".1.3.6.1.2.1.1.5.0":
            res.System.SysName = kv.Value
        case ".1.3.6.1.2.1.1.6.0":
            res.System.SysLocation = kv.Value
        }
    }

    // Walk a few trees
    trees := []string{".1.3.6.1.2.1.1", ".1.3.6.1.2.1.2", ".1.3.6.1.2.1.4"}
    for _, base := range trees {
        items, _ := walk(target, uint16(port), community, timeout, base)
        res.Walk = append(res.Walk, items...)
        if len(res.Walk) > 256 {
            break
        }
    }

    sort.Slice(res.Walk, func(i, j int) bool { return res.Walk[i].OID < res.Walk[j].OID })
    return res, nil
}

func detectVersionAndCommunity(target string, port uint16, timeout time.Duration) (string, string) {
    // Prefer v2c with public
    if tryGet(target, port, "public", timeout, ".1.3.6.1.2.1.1.1.0") == nil {
        return "SNMPv2c", "public"
    }
    // Try v1 with public
    if tryGetWithVersion(target, port, "public", timeout, ".1.3.6.1.2.1.1.1.0", gosnmp.Version1) == nil {
        return "SNMPv1", "public"
    }
    return "Unknown", ""
}

func client(target string, port uint16, community string, timeout time.Duration, version gosnmp.SnmpVersion) (*gosnmp.GoSNMP, error) {
    g := &gosnmp.GoSNMP{
        Target:    target,
        Port:      port,
        Community: community,
        Version:   version,
        Timeout:   timeout,
        Retries:   1,
    }
    if err := g.Connect(); err != nil {
        return nil, err
    }
    return g, nil
}

func tryGet(target string, port uint16, community string, timeout time.Duration, oid string) error {
    return tryGetWithVersion(target, port, community, timeout, oid, gosnmp.Version2c)
}

func tryGetWithVersion(target string, port uint16, community string, timeout time.Duration, oid string, version gosnmp.SnmpVersion) error {
    g, err := client(target, port, community, timeout, version)
    if err != nil {
        return err
    }
    defer g.Conn.Close()
    _, err = g.Get([]string{oid})
    return err
}

func bulkGet(target string, port uint16, community string, timeout time.Duration, oids []string) ([]KV, error) {
    g, err := client(target, port, community, timeout, gosnmp.Version2c)
    if err != nil {
        return nil, err
    }
    defer g.Conn.Close()
    pkt, err := g.Get(oids)
    if err != nil {
        return nil, err
    }
    var res []KV
    for _, v := range pkt.Variables {
        res = append(res, KV{OID: v.Name, Type: v.Type.String(), Value: pretty(v)})
    }
    return res, nil
}

func walk(target string, port uint16, community string, timeout time.Duration, base string) ([]KV, error) {
    g, err := client(target, port, community, timeout, gosnmp.Version2c)
    if err != nil {
        return nil, err
    }
    defer g.Conn.Close()
    res := make([]KV, 0, 64)
    err = g.Walk(base, func(pdu gosnmp.SnmpPDU) error {
        res = append(res, KV{OID: pdu.Name, Type: pdu.Type.String(), Value: pretty(pdu)})
        if len(res) > 512 {
            return fmt.Errorf("limit")
        }
        return nil
    })
    if err != nil && !strings.Contains(err.Error(), "limit") {
        return res, err
    }
    return res, nil
}

func pretty(pdu gosnmp.SnmpPDU) string {
    switch pdu.Type {
    case gosnmp.OctetString:
        if b, ok := pdu.Value.([]byte); ok {
            return string(b)
        }
    case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Counter64, gosnmp.Integer:
        return fmt.Sprintf("%v", pdu.Value)
    }
    return fmt.Sprintf("%v", pdu.Value)
}

func (r *Result) Render() string {
    var b strings.Builder
    b.WriteString("SNMP Scan Result\n")
    b.WriteString(fmt.Sprintf("Target: %s:%d\n", r.Target, r.Port))
    b.WriteString(fmt.Sprintf("Version: %s\n", r.Version))
    if len(r.Communities) > 0 {
        names := make([]string, 0, len(r.Communities))
        for _, c := range r.Communities {
            names = append(names, c.Name)
        }
        b.WriteString("Communities: " + strings.Join(names, ", ") + "\n")
    }
    if r.System.SysName != "" || r.System.SysDescr != "" {
        b.WriteString("System Info:\n")
        if r.System.SysName != "" {
            b.WriteString("  Name: " + r.System.SysName + "\n")
        }
        if r.System.SysDescr != "" {
            b.WriteString("  Description: " + r.System.SysDescr + "\n")
        }
        if r.System.SysLocation != "" {
            b.WriteString("  Location: " + r.System.SysLocation + "\n")
        }
        if r.System.SysContact != "" {
            b.WriteString("  Contact: " + r.System.SysContact + "\n")
        }
    }
    if len(r.Walk) > 0 {
        b.WriteString("Walk (sample):\n")
        limit := len(r.Walk)
        if limit > 20 {
            limit = 20
        }
        for i := 0; i < limit; i++ {
            kv := r.Walk[i]
            b.WriteString(fmt.Sprintf("  %s = %s\n", kv.OID, kv.Value))
        }
    }
    if len(r.Errors) > 0 {
        b.WriteString("Errors:\n")
        for _, e := range r.Errors {
            b.WriteString("  - " + e + "\n")
        }
    }
    return b.String()
}

