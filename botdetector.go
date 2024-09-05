package botdetector

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
    "fmt"
    "encoding/json"
    "sync"
    "time"
)

// DNSResolver is an interface for DNS lookups
type DNSResolver interface {
	LookupAddr(ip string) ([]string, error)
	LookupIP(host string) ([]net.IP, error)
}

// DefaultDNSResolver uses the net package for DNS lookups
type DefaultDNSResolver struct{}

func (r *DefaultDNSResolver) LookupAddr(ip string) ([]string, error) {
	return net.LookupAddr(ip)
}

func (r *DefaultDNSResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

type Config struct {
	BotsTo              string          `json:"botsTo,omitempty"`
	OthersTo            string          `json:"othersTo,omitempty"`
	BotsList            []string        `json:"botsList,omitempty"`
	Permanent           bool            `json:"permanent,omitempty"`
	BotTag              string          `json:"botTag,omitempty"`
	ExcludeStatic       bool            `json:"excludeStatic,omitempty"`
	StaticExtensions    []string        `json:"staticExtensions,omitempty"`
	GoogleByIP          bool            `json:"googleByIP,omitempty"`
    IncludeGoogleIPs    []string        `json:"includeGoogleIPs,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
	    BotTag: "true",
	    StaticExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico"},
	}
}

type BotMiddleware struct {
	next                http.Handler
	botsTo              string
	othersTo            string
	botsList            []string
	permanent           bool
	botTag              string
	excludeStatic       bool
    staticExtensions    []string
    googleByIP          bool
    googleCIDR          []*net.IPNet
    includeGoogleIPs    []*net.IPNet
	dnsResolver         DNSResolver
    mu                  sync.RWMutex
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	middleware := &BotMiddleware{
		next:               next,
		botsTo:             config.BotsTo,
		othersTo:           config.OthersTo,
		botsList:           config.BotsList,
		permanent:          config.Permanent,
		botTag:             config.BotTag,
		excludeStatic:      config.ExcludeStatic,
        staticExtensions:   config.StaticExtensions,
        googleByIP:         config.GoogleByIP,
		dnsResolver:        &DefaultDNSResolver{},
	}

	if middleware.googleByIP {
		err := middleware.loadGoogleCIDR()
		if err != nil {
			return nil, fmt.Errorf("failed to load Google CIDR list: %v", err)
		}

        for _, includeIP := range config.IncludeGoogleIPs {
            _, cidr, err := net.ParseCIDR(includeIP)
            if err != nil {
                continue
            }
            middleware.includeGoogleIPs = append(middleware.includeGoogleIPs, cidr)
        }

        // start periodic loading of CIDR from URL
        go middleware.periodicLoad(1 * time.Hour)
	}

    return middleware, nil
}

func (m *BotMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

    // if the files are static and need to be excluded, check
    if m.excludeStatic && m.isStaticFile(req.URL.Path) && m.isRefererSameHost(req) {
		if m.next != nil {
            m.next.ServeHTTP(rw, req)
        }
        return
	}

    if req.Header.Get("X-SearchBot-Detected") == m.botTag {
        m.redirect(rw, req, m.botsTo)
        return
    }

    // checking against the Google IP list (always enabled if googleByIP is available)
    ip := getIP(req)
    if m.googleByIP && m.isGoogleBotByIP(ip) {
        m.redirect(rw, req, m.botsTo)
        return
    }

	userAgent := req.Header.Get("User-Agent")

	if m.isSearchBot(userAgent) && m.verifyBot(ip, userAgent) {
        req.Header.Set("X-SearchBot-Detected", m.botTag)
        m.redirect(rw, req, m.botsTo)
        return
	}

	m.redirect(rw, req, m.othersTo)
}

func (m *BotMiddleware) isStaticFile(urlPath string) bool {
	ext := strings.ToLower(path.Ext(urlPath))
	for _, staticExt := range m.staticExtensions {
		if ext == staticExt {
			return true
		}
	}
	return false
}

func (m *BotMiddleware) isRefererSameHost(req *http.Request) bool {
	referer := req.Header.Get("Referer")
	if referer == "" {
		return false
	}

	refererHost := getHostFromURL(referer)
	requestHost := req.Host

	return refererHost == requestHost
}

func (m *BotMiddleware) loadGoogleCIDR() error {
	resp, err := http.Get("https://www.gstatic.com/ipranges/goog.json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var data struct {
		Prefixes []struct {
			IPPrefix string `json:"ipv4Prefix"`
			IP6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	var parsedCIDR []*net.IPNet
	for _, prefix := range data.Prefixes {
		if prefix.IPPrefix != "" {
			_, cidr, err := net.ParseCIDR(prefix.IPPrefix)
			if err != nil {
				continue
			}
			parsedCIDR = append(parsedCIDR, cidr)
		}
		if prefix.IP6Prefix != "" {
			_, cidr, err := net.ParseCIDR(prefix.IP6Prefix)
			if err != nil {
				continue
			}
			parsedCIDR = append(parsedCIDR, cidr)
		}
	}

	// Обновляем список CIDR безопасным образом
	m.mu.Lock()
	m.googleCIDR = parsedCIDR
	m.mu.Unlock()

	return nil
}

func (m *BotMiddleware) periodicLoad(interval time.Duration) {
	for {
        m.loadGoogleCIDR()
		time.Sleep(interval)
	}
}

func (m *BotMiddleware) isGoogleBotByIP(ip string) bool {
    m.mu.RLock()
    defer m.mu.RUnlock()

    ipNet := net.ParseIP(ip)
	for _, cidr := range m.googleCIDR {
		if cidr.Contains(ipNet) {
			return true
		}
	}

    for _, cidr := range m.includeGoogleIPs {
        if cidr.Contains(ipNet) {
            return true
        }
    }

	return false
}

func (m *BotMiddleware) isSearchBot(userAgent string) bool {
	botPatterns := map[string]string{
		"Google": `(Google-?(bot|Other|InspectionTool|Safety|Producer|Read-Aloud|Site-Verification)?|(Storebot|APIs|AdsBot|Mediapartners|FeedFetcher)-Google)`,
		"Yandex": `(Yandex|Ya)([a-zA-Z]*)(\/\d\.\d{1,2})?; (.*;\s)?\+http:\/\/yandex\.com\/bots`,
		"Bing": `bingbot`,
	}

	for bot, pattern := range botPatterns {
		if len(m.botsList) > 0 && !contains(m.botsList, bot) {
			continue
		}
		match, _ := regexp.MatchString(pattern, userAgent)
		if match {
			return true
		}
	}

	return false
}

func (m *BotMiddleware) verifyBot(ip string, userAgent string) bool {
	hostnames, err := m.dnsResolver.LookupAddr(ip)
	if err != nil {
		return false
	}

	botDomainPattern, _ := regexp.Compile(`(\.|^)(yandex\.(ru|net|com)|(google(usercontent|bot)?|search\.msn)\.com)\.$`)

	for _, hostname := range hostnames {
		match := botDomainPattern.MatchString(hostname)
		if match {
			ips, err := m.dnsResolver.LookupIP(hostname)
			if err != nil {
				continue
			}
			for _, resolvedIP := range ips {
				if resolvedIP.String() == ip {
					return true
				}
			}
		}
	}

	return false
}

func (m *BotMiddleware) redirect(rw http.ResponseWriter, req *http.Request, target string) {
	if target == "" || target == req.Host {
		if m.next != nil {
			m.next.ServeHTTP(rw, req)
		}
		return
	}

    // Extract the scheme and path from the original URL
	scheme := "https"
	if req.TLS == nil {
        scheme = "http"
    }

    originalURL := req.URL
    newURL := scheme + "://" + target + originalURL.Path

    if originalURL.RawQuery != "" {
        newURL += "?" + originalURL.RawQuery
    }

    if originalURL.Fragment != "" {
        newURL += "#" + originalURL.Fragment
    }

	statusCode := http.StatusFound
	if m.permanent {
		statusCode = http.StatusMovedPermanently
	}

    // redirect action
	rw.Header().Set("Location", newURL)
    rw.WriteHeader(statusCode)
    _, err := rw.Write([]byte(http.StatusText(statusCode)))
    if err != nil {
        http.Error(rw, err.Error(), http.StatusInternalServerError)
    }
}

func getIP(req *http.Request) string {
	ip := req.Header.Get("X-Real-IP")
	if ip == "" {
		ip = req.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = req.RemoteAddr
	}
	return strings.Split(ip, ":")[0]
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getHostFromURL(URL string) string {
	parsedURL, err := url.Parse(URL)
	if err != nil {
		return ""
	}
	return parsedURL.Host
}
