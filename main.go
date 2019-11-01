package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"
	"gopkg.in/yaml.v2"
)

type configRoot struct {
	AllowGlobalUnicastOnly bool          `yaml:"allowGlobalUnicastOnly"`
	BlockPrivateAddressV4  bool          `yaml:"blockPrivateAddressV4"`
	Blacklist              []interface{} `yaml:"blacklist"`
}

type blacklistEntry struct {
	CIDR        *net.IPNet
	IsBlacklist bool
	PortRanges  []portRange
}

func newBlacklistEntryFromCIDR(cidr string) blacklistEntry {
	_, parsedNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return blacklistEntry{parsedNet, false, []portRange{neverMatchPortRange}}
}

type portRange struct {
	StartInclusive, EndInclusive int
}

var neverMatchPortRange = portRange{-1, -1}

func (p *portRange) Contains(port int) bool {
	return port >= p.StartInclusive && port <= p.EndInclusive
}

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	configFile := flag.String("config", "", "config file")
	flag.Parse()

	var config configRoot
	if len(*configFile) > 0 {
		// Load config file
		configFileBytes, err := ioutil.ReadFile(*configFile)
		if err != nil {
			log.Fatalln(err)
		}
		yaml.Unmarshal(configFileBytes, &config)
	} else {
		// Default settings
		config.AllowGlobalUnicastOnly = true
		config.BlockPrivateAddressV4 = true
	}

	// Create blacklist
	blacklist := parseBlacklist(config.Blacklist)
	if config.BlockPrivateAddressV4 {
		blacklist = append(blacklist,
			newBlacklistEntryFromCIDR("10.0.0.0/8"),
			newBlacklistEntryFromCIDR("172.16.0.0/12"),
			newBlacklistEntryFromCIDR("192.168.0.0/16"))
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	condFunc := createReqConditionFunc(&config, blacklist)

	// HTTP
	proxy.OnRequest(goproxy.ReqConditionFunc(condFunc)).
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return nil, createResponse(req)
		})

	// HTTPS
	proxy.OnRequest(goproxy.ReqConditionFunc(condFunc)).
		HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			ctx.Resp = createResponse(ctx.Req)
			return goproxy.RejectConnect, host
		})

	err := http.ListenAndServe(*addr, proxy)

	if err != nil {
		log.Fatalln(err)
	}
}

func parseBlacklist(list []interface{}) []blacklistEntry {
	var entries []blacklistEntry

	for _, item := range list {
		if mapObj, ok := item.(map[interface{}]interface{}); ok {
			// item is a map
			addr := "0.0.0.0/0"
			if x, ok := getValueFromMapSlice(mapObj, "addr"); ok {
				addr = fmt.Sprintf("%v", x)
			}

			cidr := addrStrToCIDR(addr)

			portWhitelist, portWhitelistOk := getValueFromMapSlice(mapObj, "portWhitelist")
			portBlacklist, portBlacklistOk := getValueFromMapSlice(mapObj, "portBlacklist")

			if portWhitelistOk && portBlacklistOk {
				log.Fatalln("Cannot specify portWhitelist and portBlacklist simultaneously")
			}

			portList := portWhitelist
			if portBlacklistOk {
				portList = portBlacklist
			}

			var portRanges []portRange
			if portSlice, ok := portList.([]interface{}); ok {
				for _, x := range portSlice {
					portRanges = append(portRanges, parsePortRange(x))
				}
			} else {
				// Read as a string if portRanges is not a slice
				portRanges = append(portRanges, parsePortRange((portList)))
			}

			entries = append(entries, blacklistEntry{cidr, portBlacklistOk, portRanges})
		} else {
			// item is a scalar
			cidr := addrStrToCIDR(fmt.Sprintf("%v", item))
			entries = append(entries, blacklistEntry{cidr, false, []portRange{neverMatchPortRange}})
		}
	}

	return entries
}

func addrStrToCIDR(addr string) *net.IPNet {
	if strings.Contains(addr, "/") {
		_, parsedNet, err := net.ParseCIDR(addr)
		if err != nil {
			log.Fatalln(err)
		}
		return parsedNet
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		log.Fatalf("Failed to parse '%v'\n", addr)
	}

	// Convert to v4 if possible
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	bits := len(ip) * 8
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

func getValueFromMapSlice(m map[interface{}]interface{}, key string) (interface{}, bool) {
	for k, v := range m {
		if fmt.Sprintf("%v", k) == key {
			return v, true
		}
	}
	return nil, false
}

var portRangePattern = regexp.MustCompile(`^\s*([0-9]+)\s*(?:\-\s*([0-9]+)\s*)?$`)

func parsePortRange(obj interface{}) portRange {
	if obj == nil || obj == "" {
		return neverMatchPortRange
	}
	if portInt, ok := obj.(int); ok {
		return portRange{portInt, portInt}
	}

	s := fmt.Sprintf("%v", obj)
	matches := portRangePattern.FindStringSubmatch(s)

	if len(matches) != 3 {
		log.Fatalf("Failed to parse range '%s'\n", s)
	}

	rangeStart, _ := strconv.Atoi(matches[1])

	if matches[2] == "" {
		return portRange{rangeStart, rangeStart}
	}

	rangeEnd, _ := strconv.Atoi(matches[2])
	return portRange{rangeStart, rangeEnd}
}

func createReqConditionFunc(config *configRoot, blacklist []blacklistEntry) goproxy.ReqConditionFunc {
	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		host := req.Host
		portStr := "http"

		if strings.Contains(host, ":") {
			var err error
			host, portStr, err = net.SplitHostPort(host)
			if err != nil {
				log.Printf("Failed to parse '%s': %v\n", host, err)
				return true
			}
		}

		port, err := net.LookupPort("tcp", portStr)
		if err != nil {
			log.Printf("Invalid port number '%s': %v\n", portStr, err)
			return true
		}

		addrs, err := net.LookupIP(host)
		if err != nil {
			log.Printf("Failed to lookup '%s': %v\n", host, err)
			return true
		}

		for _, addr := range addrs {
			if config.AllowGlobalUnicastOnly && !addr.IsGlobalUnicast() {
				return true
			}

			if ip4 := addr.To4(); ip4 != nil {
				addr = ip4
			}

			for _, entry := range blacklist {
				if !entry.CIDR.Contains(addr) {
					continue
				}

				if entry.IsBlacklist {
					for _, portRange := range entry.PortRanges {
						if portRange.Contains(port) {
							return true
						}
					}
				} else { // whitelist
					block := true
					for _, portRange := range entry.PortRanges {
						if portRange.Contains(port) {
							block = false
							break
						}
					}
					if block {
						return true
					}
				}
			}
		}

		return false
	}
}

func createResponse(req *http.Request) *http.Response {
	return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "The request has been rejected by coroxy\n")
}
