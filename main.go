package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	// HTTP
	proxy.OnRequest(goproxy.ReqConditionFunc(isLocalRequest)).
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return nil, createResponse(req)
		})

	// HTTPS
	proxy.OnRequest(goproxy.ReqConditionFunc(isLocalRequest)).
		HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			ctx.Resp = createResponse(ctx.Req)
			return goproxy.RejectConnect, host
		})

	err := http.ListenAndServe(*addr, proxy)

	if err != nil {
		log.Fatalln(err)
	}
}

func isLocalRequest(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	host, _, err := net.SplitHostPort(req.Host)

	if err != nil {
		log.Printf("Failed to parse '%s': %v\n", host, err)
		return true
	}

	addrs, err := net.LookupIP(host)

	if err != nil {
		log.Printf("Failed to lookup '%s': %v\n", host, err)
		return true // Reject
	}

	for _, addr := range addrs {
		if !addr.IsGlobalUnicast() {
			// IPv6 -> not a global unicast address
			// IPv4 -> a mulicast address or loopback
			return true
		}

		if ip4 := addr.To4(); ip4 != nil {
			// 10.0.0.0/8
			// 192.168.0.0/16
			if ip4[0] == 10 || (ip4[0] == 192 && ip4[1] == 168) {
				return true
			}

			// 172.16.0.0/12
			masked12 := ip4.Mask(net.CIDRMask(12, 32))
			if masked12[0] == 172 && masked12[1] == 16 {
				return true
			}
		}
	}

	return false
}

func createResponse(req *http.Request) *http.Response {
	return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "The request has been rejected by coroxy\n")
}
