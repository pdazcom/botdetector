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
    if ip == "157.55.33.18" {
        return []string{"msnbot-157-55-33-18.search.msn.com."}, nil
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
    if hostname == "msnbot-157-55-33-18.search.msn.com." {
		return []net.IP{net.ParseIP("157.55.33.18")}, nil
	}

	return nil, errors.New("unknown host")
}

func TestIsSearchBot(t *testing.T) {
	tests := []struct {
		userAgent string
		expected  bool
	}{
	    {"", false},
		{"Googlebot", true},
		{"Google", true},
		{"Mozilla/5.0", false},
		{"YandexBot/3.0; +http://yandex.com/bots", true},
		{"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0", true},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/100.0.4896.127 Safari/537.36", true},
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
		{"157.55.33.18", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/100.0.4896.127 Safari/537.36", true},
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
		{"http://localhost", "", "", false, 0}, // no redirect
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
		ip         string
		userAgent  string
		botTag     string
		headerSet  bool
		expected   string
		statusCode int
	}{
		{"66.249.66.1", "Googlebot", "true", false, "http://bots.com", http.StatusFound},
		{"77.88.55.66", "YandexBot/3.0; +http://yandex.com/bots", "true", false, "http://bots.com", http.StatusFound},
		{"192.168.1.1", "Mozilla/5.0", "true", false, "http://others.com", http.StatusFound},
		{"66.249.66.1", "Googlebot", "true", true, "http://bots.com", http.StatusFound},
		{"66.249.66.2", "Gozilla/5.0", "true", true, "http://bots.com", http.StatusFound},
		{"66.249.66.3", "Gozilla/5.1", "fdsdfsfd", true, "http://others.com", http.StatusFound},

	}

	for _, test := range tests {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://localhost", nil)
		req.Header.Set("X-Real-IP", test.ip)
		req.Header.Set("User-Agent", test.userAgent)
		if test.headerSet {
			req.Header.Set("X-SearchBot-Detected", test.botTag)
		}

		middleware := &BotMiddleware{
            botsTo:     "bots.com",
            othersTo:   "others.com",
            botTag:     "true",
            dnsResolver: &MockDNSResolver{},
            next:       http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
        }

		middleware.ServeHTTP(recorder, req)

		if location := recorder.Header().Get("Location"); location != test.expected {
			t.Errorf("ServeHTTP() location = %v; want %v", location, test.expected)
		}
		if status := recorder.Result().StatusCode; status != test.statusCode {
			t.Errorf("ServeHTTP() status = %v; want %v", status, test.statusCode)
		}
		if test.headerSet {
			if header := req.Header.Get("X-SearchBot-Detected"); header != test.botTag {
				t.Errorf("ServeHTTP() header = %v; want %v", header, test.botTag)
			}
		}
	}
}

func TestServeHTTP_WithStaticFileAndRefererSameHost(t *testing.T) {
	middleware := &BotMiddleware{
		botsTo:          "bots.com",
		othersTo:        "others.com",
		botTag:          "true",
		excludeStatic:   true,
		staticExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf"},
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}

	// Static file with referrer matching host
	req := httptest.NewRequest("GET", "http://localhost/style.css", nil)
	req.Header.Set("Referer", "http://localhost/")
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	// Checking that the static file is not redirected
	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("Expected status 200 OK for static file, got %v", status)
	}
}

func TestServeHTTP_WithStaticFileAndRefererDifferentHost(t *testing.T) {
	middleware := &BotMiddleware{
		botsTo:          "bots.com",
		othersTo:        "others.com",
		excludeStatic:   true,
		botTag:          "true",
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		staticExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf"},
	}

	// Static file with referrer from another host
	req := httptest.NewRequest("GET", "http://localhost/style.css", nil)
	req.Header.Set("Referer", "http://otherhost.com/")
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	// Checking that the request is redirected to othersTo
	if location := recorder.Header().Get("Location"); location != "http://others.com/style.css" {
		t.Errorf("Expected redirect to http://others.com/style.css, got %v", location)
	}
	if status := recorder.Code; status != http.StatusFound {
		t.Errorf("Expected status 302 Found, got %v", status)
	}
}

func TestServeHTTP_WithNonStaticFile(t *testing.T) {
	middleware := &BotMiddleware{
		botsTo:          "bots.com",
		othersTo:        "others.com",
		excludeStatic:   true,
		staticExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf"},
		botTag:          "true",
        next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}

	// Regular file (not static)
	req := httptest.NewRequest("GET", "http://localhost/index.html", nil)
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	// We check that the request is redirected to othersTo (since the bot is not defined)
	if location := recorder.Header().Get("Location"); location != "http://others.com/index.html" {
		t.Errorf("Expected redirect to http://others.com/index.html, got %v", location)
	}
	if status := recorder.Code; status != http.StatusFound {
		t.Errorf("Expected status 302 Found, got %v", status)
	}
}

func TestServeHTTP_StaticFileWithoutReferer(t *testing.T) {
	middleware := &BotMiddleware{
		botsTo:          "bots.com",
		othersTo:        "others.com",
		excludeStatic:   true,
		staticExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf"},
		botTag:          "true",
        next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}

	// Static file without referrer
	req := httptest.NewRequest("GET", "http://localhost/style.css", nil)
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	// Checking that the request is redirected to othersTo
	if location := recorder.Header().Get("Location"); location != "http://others.com/style.css" {
		t.Errorf("Expected redirect to http://others.com/style.css, got %v", location)
	}
	if status := recorder.Code; status != http.StatusFound {
		t.Errorf("Expected status 302 Found, got %v", status)
	}
}

func TestServeHTTP_WithStaticFileAndExcludeStaticDisabled(t *testing.T) {
	middleware := &BotMiddleware{
		botsTo:          "bots.com",
		othersTo:        "others.com",
		excludeStatic:   false, // Отключено исключение статики
		staticExtensions: []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf"},
		botTag:          "true",
        next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}

	// Static file with referrer matching host
	req := httptest.NewRequest("GET", "http://localhost/style.css", nil)
	req.Header.Set("Referer", "http://localhost/")
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	// Checking that the request is redirected to othersTo since excludeStatic is disabled
	if location := recorder.Header().Get("Location"); location != "http://others.com/style.css" {
		t.Errorf("Expected redirect to http://others.com/style.css, got %v", location)
	}
	if status := recorder.Code; status != http.StatusFound {
		t.Errorf("Expected status 302 Found, got %v", status)
	}
}

func TestGoogleBotByIP(t *testing.T) {
	middleware := &BotMiddleware{
		botsTo:    "bots.com",
		othersTo:  "others.com",
		googleByIP: true,
		botTag: "true",
	}

	// load CIDR ranges from JSON
	err := middleware.loadGoogleCIDR("test_cidr.json")
	if err != nil {
		t.Fatalf("Failed to load Google CIDR list: %v", err)
	}

	// create a request with an IP from the Google range
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	req.RemoteAddr = "64.233.160.1:12345" // IP в диапазоне Google

	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)

	// check that the request was redirected to botsTo
	if location := recorder.Header().Get("Location"); location != "http://bots.com/" {
		t.Errorf("Expected redirect to http://bots.com/, got %v", location)
	}
	if status := recorder.Code; status != http.StatusFound {
		t.Errorf("Expected status 302 Found, got %v", status)
	}

    req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.RemoteAddr = "1.1.1.1:12345" // IP not in Google range

	recorder2 := httptest.NewRecorder()
	middleware.ServeHTTP(recorder2, req2)

	if location := recorder2.Header().Get("Location"); location != "http://others.com" {
		t.Errorf("Expected redirect to http://others.com, got %v", location)
	}
	if status := recorder2.Code; status != http.StatusFound {
		t.Errorf("Expected status 302 Found, got %v", status)
	}
}
