package goproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	hproxy "github.com/mmczoo/gotools/proxy"
	"github.com/xlvector/dlog"
)

type ProxyPx struct {
	PxMgr *hproxy.ProxyMgr
}

// The basic proxy type. Implements http.Handler.
type ProxyHttpServer struct {
	// session variable must be aligned in i386
	// see http://golang.org/src/pkg/sync/atomic/doc.go#L41
	sess int64
	// setting Verbose to true will log information on each request sent to the proxy
	Verbose         bool
	Logger          *log.Logger
	NonproxyHandler http.Handler
	reqHandlers     []ReqHandler
	respHandlers    []RespHandler
	httpsHandlers   []HttpsHandler
	Tr              *http.Transport
	// ConnectDial will be used to create TCP connections for CONNECT requests
	// if nil Tr.Dial will be used
	ConnectDial func(network string, addr string) (net.Conn, error)

	px *ProxyPx
}

var hasPort = regexp.MustCompile(`:\d+$`)

func copyHeaders(dst, src http.Header) {
	for k, _ := range dst {
		dst.Del(k)
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func isEof(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	if err == io.EOF {
		return true
	}
	return false
}

func (proxy *ProxyHttpServer) filterRequest(r *http.Request, ctx *ProxyCtx) (req *http.Request, resp *http.Response) {
	req = r
	for _, h := range proxy.reqHandlers {
		req, resp = h.Handle(r, ctx)
		// non-nil resp means the handler decided to skip sending the request
		// and return canned response instead.
		if resp != nil {
			break
		}
	}
	return
}
func (proxy *ProxyHttpServer) filterResponse(respOrig *http.Response, ctx *ProxyCtx) (resp *http.Response) {
	resp = respOrig
	for _, h := range proxy.respHandlers {
		ctx.Resp = resp
		resp = h.Handle(resp, ctx)
	}
	return
}

func removeProxyHeaders(ctx *ProxyCtx, r *http.Request) {
	r.RequestURI = "" // this must be reset when serving a request with the client
	ctx.Logf("Sending request %v %v", r.Method, r.URL.String())
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	r.Header.Del("Accept-Encoding")
	// curl can add that, see
	// https://jdebp.eu./FGA/web-proxy-connection-header.html
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	// Connection, Authenticate and Authorization are single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	r.Header.Del("Connection")
}

// Standard net/http function. Shouldn't be used directly, http.Serve will use it.
func (proxy *ProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//r.Header["X-Forwarded-For"] = w.RemoteAddr()
	if r.Method == "CONNECT" {
		proxy.handleHttps(w, r)
	} else {
		ctx := &ProxyCtx{Req: r, Session: atomic.AddInt64(&proxy.sess, 1), proxy: proxy}

		var err error
		ctx.Logf("Got request %v %v %v %v", r.URL.Path, r.Host, r.Method, r.URL.String())
		if !r.URL.IsAbs() {
			if proxy.px != nil {
				ret := proxy.px.PxMgr.GetIpst()
				b, _ := json.Marshal(ret)
				w.Write(b)
				return
			}
			proxy.NonproxyHandler.ServeHTTP(w, r)
			return
		}
		r, resp := proxy.filterRequest(r, ctx)

		if resp == nil {
			removeProxyHeaders(ctx, r)

			var rpx *hproxy.Proxy
			if proxy.px != nil {
				rpx = proxy.setRoundTrip(ctx)
			}

			resp, err = ctx.RoundTrip(r)
			if err != nil {
				ctx.Error = err
				resp = proxy.filterResponse(nil, ctx)
				if resp == nil {
					ctx.Logf("error read response %v %v:", r.URL.Host, err.Error())
					http.Error(w, err.Error(), 500)
					return
				}
			}
			if rpx != nil {
				proxy.px.PxMgr.FeedBack(rpx)
			}
			ctx.Logf("Received response %v", resp.Status)
		}
		origBody := resp.Body
		resp = proxy.filterResponse(resp, ctx)
		defer origBody.Close()
		ctx.Logf("Copying response to client %v [%d]", resp.Status, resp.StatusCode)
		// http.ResponseWriter will take care of filling the correct response length
		// Setting it now, might impose wrong value, contradicting the actual new
		// body the user returned.
		// We keep the original body to remove the header only if things changed.
		// This will prevent problems with HEAD requests where there's no body, yet,
		// the Content-Length header should be set.
		if origBody != resp.Body {
			resp.Header.Del("Content-Length")
		}
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		nr, err := io.Copy(w, resp.Body)
		if err := resp.Body.Close(); err != nil {
			ctx.Warnf("Can't close response body %v", err)
		}
		ctx.Logf("Copied %v bytes to client error=%v", nr, err)
	}
}

// New proxy server, logs to StdErr by default
func NewProxyHttpServer() *ProxyHttpServer {
	proxy := ProxyHttpServer{
		Logger:        log.New(os.Stderr, "", log.LstdFlags),
		reqHandlers:   []ReqHandler{},
		respHandlers:  []RespHandler{},
		httpsHandlers: []HttpsHandler{},
		NonproxyHandler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 500)
		}),
		Tr: &http.Transport{TLSClientConfig: tlsClientSkipVerify,
			Proxy: http.ProxyFromEnvironment},
	}
	proxy.ConnectDial = dialerFromEnv(&proxy)
	return &proxy
}

func (p *ProxyHttpServer) setRoundTrip(ctx *ProxyCtx) *hproxy.Proxy {
	px := p.px.PxMgr.Get()
	if px == nil {
		return nil
	}
	ctx.RoundTripper = RoundTripperFunc(func(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
		transport := &http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: time.Second * 20,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MaxVersion:         tls.VersionTLS12,
				MinVersion:         tls.VersionTLS10,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_RC4_128_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			},
		}

		if px.Type == "socks5" {
			var auth *proxy.Auth
			if len(px.Username) > 0 && len(px.Password) > 0 {
				auth = &proxy.Auth{
					User:     px.Username,
					Password: px.Password,
				}
			} else {
				auth = &proxy.Auth{}
			}
			forward := proxy.FromEnvironment()
			dialSocks5Proxy, err := proxy.SOCKS5("tcp", px.IP, auth, forward)
			if err != nil {
				dlog.Warn("SetSocks5 Error:%s", err.Error())
				return p.Tr.RoundTrip(req)
			}
			transport.Dial = dialSocks5Proxy.Dial
		} else if px.Type == "http" || px.Type == "https" {
			transport.Dial = func(netw, addr string) (net.Conn, error) {
				timeout := time.Second * 5
				deadline := time.Now().Add(timeout)
				c, err := net.DialTimeout(netw, addr, timeout)
				if err != nil {
					return nil, err
				}
				c.SetDeadline(deadline)
				return c, nil
			}
			proxyUrl, err := url.Parse(px.String())
			if err == nil {
				transport.Proxy = http.ProxyURL(proxyUrl)
			}
		} else if px.Type == "socks4" {
			surl := "socks4://" + px.IP
			rsurl, err := url.Parse(surl)
			if err != nil {
				dlog.Warn("socks4 url parse: %v", err)
				return p.Tr.RoundTrip(req)
			}
			forward := proxy.FromEnvironment()
			dialersocks4, err := proxy.FromURL(rsurl, forward)
			if err != nil {
				dlog.Warn("SetSocks4 Error:%s", err.Error())
				return p.Tr.RoundTrip(req)
			}
			transport.Dial = dialersocks4.Dial
		}

		return transport.RoundTrip(req)
	})

	return px
}

type Config struct {
	Ssdb  *hproxy.Ssdb  `json:"ssdb"`
	Redis *hproxy.Redis `json:"redis"`
}

func NewConfig(fname string) *Config {
	f, err := os.Open(fname)
	if err != nil {
		dlog.Error("fail to open confile file! %s", fname, err)
		return nil
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		dlog.Error("fail to read confile file! %s", fname, err)
		return nil
	}

	p := &Config{}
	err = json.Unmarshal(data, p)
	if err != nil {
		dlog.Error("fail to unmarshal! %s", fname, err)
		return nil
	}

	return p
}

func NewProxyHttpServerWithPx(fn string) *ProxyHttpServer {
	if len(fn) == 0 {
		log.Fatalf("config file fail!")
	}

	cfg := NewConfig(fn)
	if cfg == nil {
		log.Fatalf("config file fail!!")
	}

	phs := NewProxyHttpServer()
	if cfg.Ssdb != nil {
		phs.px = &ProxyPx{
			PxMgr: hproxy.NewProxyMgrWithSsdb(cfg.Ssdb),
		}
	} else if cfg.Redis != nil {
		phs.px = &ProxyPx{
			PxMgr: hproxy.NewProxyMgr(cfg.Redis),
		}
	} else {
		log.Fatalf("config file fail!!!")
	}

	return phs
}
