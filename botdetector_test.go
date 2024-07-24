package botdetector

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type MockDNSResolver struct{}

func (r *MockDNSResolver) LookupAddr(ip string) ([]string, error) {
	if ip == "66.249.66.1" {
		return []string{"crawl-66-249-66-1.googlebot.com."}, nil
	}
	if ip == "77.88.55.66" {
		return []string{"spider-77-88-55-66.yandex.com."}, nil
	}
    if ip == "5.255.253.36" {
        return []string{"5-255-253-36.spider.yandex.com."}, nil
    }
	return nil, errors.New("unknown host")
}

func (r *MockDNSResolver) LookupIP(hostname string) ([]net.IP, error) {
	if hostname == "crawl-66-249-66-1.googlebot.com." {
		return []net.IP{net.ParseIP("66.249.66.1")}, nil
	}
	if hostname == "spider-77-88-55-66.yandex.com." {
		return []net.IP{net.ParseIP("77.88.55.66")}, nil
	}
    if hostname == "5-255-253-36.spider.yandex.com." {
		return []net.IP{net.ParseIP("5.255.253.36")}, nil
	}
	return nil, errors.New("unknown host")
}

func TestIsSearchBot(t *testing.T) {
	tests := []struct {
		userAgent string
		expected  bool
	}{
		{"Googlebot", true},
		{"Mozilla/5.0", false},
		{"YandexBot/3.0; +http://yandex.com/bots", true},
		{"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0", true},
	}

	middleware := &BotMiddleware{}

	for _, test := range tests {
		result := middleware.isSearchBot(test.userAgent)
		if result != test.expected {
			t.Errorf("isSearchBot(%s) = %v; want %v", test.userAgent, result, test.expected)
		}
	}
}

func TestVerifyBot(t *testing.T) {
	tests := []struct {
		ip        string
		userAgent string
		expected  bool
	}{
		{"66.249.66.1", "Googlebot", true},
		{"77.88.55.66", "YandexBot", true},
		{"77.88.55.67", "YandexBot", false},
		{"192.168.1.1", "Mozilla/5.0", false},
		{"5.255.253.36", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0", true},
	}

	middleware := &BotMiddleware{
		dnsResolver: &MockDNSResolver{},
	}

	for _, test := range tests {
		result := middleware.verifyBot(test.ip, test.userAgent)
		if result != test.expected {
			t.Errorf("verifyBot(%s, %s) = %v; want %v", test.ip, test.userAgent, result, test.expected)
		}
	}
}

func TestRedirect(t *testing.T) {
	tests := []struct {
	    source     string
	    target     string
		redirectTo string
		permanent  bool
		expected   int
	}{
		{"http://localhost", "http://example.com", "example.com", false, http.StatusFound},
		{"https://localhost", "https://example.com", "example.com", true, http.StatusMovedPermanently},
		{"http://localhost", "", "localhost", false, 0}, // no redirect
		{"http://localhost/some/path", "http://example.com/some/path", "example.com", false, http.StatusFound},
		{"http://localhost/some/path?some-query=foo#hashtag", "http://example.com/some/path?some-query=foo#hashtag", "example.com", false, http.StatusFound},
	}

	for _, test := range tests {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", test.source, nil)
		middleware := &BotMiddleware{permanent: test.permanent}

		middleware.redirect(recorder, req, test.redirectTo)

		if test.expected != 0 {
			if status := recorder.Result().StatusCode; status != test.expected {
				t.Errorf("redirect(%s, %v) = %v; want %v", test.target, test.permanent, status, test.expected)
			}
			if location := recorder.Header().Get("Location"); location != test.target {
				t.Errorf("redirect(%s, %v) = %v; want %v", test.target, test.permanent, location, test.target)
			}
		} else {
			if recorder.Result().StatusCode != 200 {
				t.Errorf("redirect(%s, %v) = %v; want %v", test.target, test.permanent, recorder.Result().StatusCode, 200)
			}
		}
	}
}

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		ip        string
		userAgent string
		expected  string
	}{
		{"66.249.66.1", "Googlebot", "http://bots.com"},
		{"77.88.55.66", "YandexBot/3.0; +http://yandex.com/bots", "http://bots.com"},
		{"77.88.55.67", "YandexBot/3.1; +http://yandex.com/bots", "http://others.com"},
		{"192.168.1.1", "Mozilla/5.0", "http://others.com"},
	}

	for _, test := range tests {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://localhost", nil)
		req.Header.Set("User-Agent", test.userAgent)
		req.RemoteAddr = test.ip + ":12345"

		middleware := &BotMiddleware{
			botsTo:      "bots.com",
			othersTo:    "others.com",
			dnsResolver: &MockDNSResolver{},
		}

		middleware.ServeHTTP(recorder, req)

		if location := recorder.Header().Get("Location"); location != test.expected {
			t.Errorf("ServeHTTP() redirect = %v; want %v", location, test.expected)
		}
	}
}
