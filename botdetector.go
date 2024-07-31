package botdetector

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"
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
	BotsTo    string   `json:"botsTo,omitempty"`
	OthersTo  string   `json:"othersTo,omitempty"`
	BotsList  []string `json:"botsList,omitempty"`
	Permanent bool     `json:"permanent,omitempty"`
	BotTag    string   `json:"botTag,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
	    BotTag: "true",
	}
}

type BotMiddleware struct {
	next        http.Handler
	botsTo      string
	othersTo    string
	botsList    []string
	permanent   bool
	botTag      string
	dnsResolver DNSResolver
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &BotMiddleware{
		next:        next,
		botsTo:      config.BotsTo,
		othersTo:    config.OthersTo,
		botsList:    config.BotsList,
		permanent:   config.Permanent,
		botTag:      config.BotTag,
		dnsResolver: &DefaultDNSResolver{},
	}, nil
}

func (m *BotMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

    if req.Header.Get("X-SearchBot-Detected") == m.botTag {
        m.redirect(rw, req, m.botsTo)
        return
    }

	userAgent := req.Header.Get("User-Agent")

	if m.isSearchBot(userAgent) {
		ip := getIP(req)
		if m.verifyBot(ip, userAgent) {
		    req.Header.Set("X-SearchBot-Detected", m.botTag)
			m.redirect(rw, req, m.botsTo)
			return
		}
	}

	m.redirect(rw, req, m.othersTo)
}

func (m *BotMiddleware) isSearchBot(userAgent string) bool {
	botPatterns := map[string]string{
		"Google": `(Google-?(bot|Other|InspectionTool|Safety|Producer|Read-Aloud|Site-Verification)|(Storebot|APIs|AdsBot|Mediapartners|FeedFetcher)-Google)`,
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
