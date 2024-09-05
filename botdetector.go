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
    "os"
    "encoding/json"
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
    GoogleCIDRFile      string          `json:"googleCIDRFile,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
	    BotTag: "true",
	    StaticExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico"},
	    GoogleCIDRFile: "google_cidr.json",
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
	dnsResolver         DNSResolver
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
		err := middleware.loadGoogleCIDR(config.GoogleCIDRFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load Google CIDR list: %v", err)
		}
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

func (m *BotMiddleware) loadGoogleCIDR(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var cidrList []string
	if err := json.NewDecoder(file).Decode(&cidrList); err != nil {
		return err
	}

	for _, cidrStr := range cidrList {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		m.googleCIDR = append(m.googleCIDR, cidr)
	}

	return nil
}

func (m *BotMiddleware) isGoogleBotByIP(ip string) bool {
    ipNet := net.ParseIP(ip)
	for _, cidr := range m.googleCIDR {
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
