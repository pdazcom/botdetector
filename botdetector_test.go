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
		return []string{"crawl-66-249-66-1.googlebot.com"}, nil
	}
	if ip == "77.88.55.66" {
		return []string{"yandex.com"}, nil
	}
	return nil, errors.New("unknown host")
}

func (r *MockDNSResolver) LookupIP(hostname string) ([]net.IP, error) {
	if hostname == "crawl-66-249-66-1.googlebot.com" {
		return []net.IP{net.ParseIP("66.249.66.1")}, nil
	}
	if hostname == "yandex.com" {
		return []net.IP{net.ParseIP("77.88.55.66")}, nil
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
	}

	middleware := &botDetector{}

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
		{"2.3.4.67", "YandexBot", false},
		{"192.168.1.1", "Mozilla/5.0", false},
	}

	middleware := &botDetector{
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
		target    string
		permanent bool
		expected  int
	}{
		{"http://example.com", false, http.StatusFound},
		{"http://example.com", true, http.StatusMovedPermanently},
		{"", false, 0}, // no redirect
	}

	for _, test := range tests {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://localhost", nil)
		middleware := &botDetector{permanent: test.permanent}

		middleware.redirect(recorder, req, test.target)

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
		{"77.88.55.22", "YandexBot/3.1; +http://yandex.com/bots", "http://others.com"},
		{"192.168.1.1", "Mozilla/5.0", "http://others.com"},
	}

	for _, test := range tests {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://localhost", nil)
		req.Header.Set("User-Agent", test.userAgent)
		req.Header.Set("X-Real-IP", test.ip)

		middleware := &botDetector{
			botsTo:     "http://bots.com",
			othersTo:   "http://others.com",
			dnsResolver: &MockDNSResolver{},
			next:       http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		}

		middleware.ServeHTTP(recorder, req)

		if status := recorder.Result().StatusCode; status != http.StatusFound {
			t.Errorf("ServeHTTP() status = %v; want %v", status, http.StatusFound)
		}
		if location := recorder.Header().Get("Location"); location != test.expected {
			t.Errorf("ServeHTTP() redirect to = %v; want %v", location, test.expected)
		}
	}
}
