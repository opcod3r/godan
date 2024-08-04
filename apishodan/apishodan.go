package apishodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	URL       = "https://api.shodan.io"
	URLDOMAIN = "https://api.shodan.io/dns/domain/"
)

type API struct {
	apiKey string
}

type UsageLimits struct {
	ScanCredits  int  `json:"scan_credits"`
	QueryCredits int  `json:"query_credits"`
	MonitoredIPs *int `json:"monitored_ips"`
}

type JsonData struct {
	ScanCredits  int         `json:"scan_credits"`
	UsageLimits  UsageLimits `json:"usage_limits"`
	Plan         string      `json:"plan"`
	HTTPS        bool        `json:"https"`
	Unlocked     bool        `json:"unlocked"`
	QueryCredits int         `json:"query_credits"`
	MonitoredIPs *int        `json:"monitored_ips"`
	UnlockedLeft int         `json:"unlocked_left"`
	Telnet       bool        `json:"telnet"`
}

type JsonSubDomain struct {
	Domain     string      `json:"domain,omitempty"`
	Tags       []string    `json:"tags,omitempty"`
	Data       []SubDomain `json:"data,omitempty"`
	SubDomains []string    `json:"subdomains,omitempty"`
}

type SubDomain struct {
	SubD     string `json:"subdomain,omitempty"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

func New(key string) *API {
	return &API{apiKey: key}
}

func (s *API) InfoAccount(ctx context.Context, verbose bool) (*JsonData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api-info?key=%s", URL, s.apiKey), nil)
	if err != nil {
		return nil, err
	}

	if verbose {
		log.Println("Sending request to Shodan API")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized {
		bodyBytes, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("unauthorized access: %s", string(bodyBytes))
	}

	// Read the response body into a byte slice for debugging
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if verbose {
		// Print the raw JSON for debugging
		fmt.Printf("Raw JSON: %s\n", string(bodyBytes))
	}

	var ret JsonData
	if err := json.Unmarshal(bodyBytes, &ret); err != nil {
		if verbose {
			// Log the error and the raw JSON for debugging
			log.Printf("Error unmarshalling JSON: %v\nRaw JSON: %s\n", err, string(bodyBytes))
		}
		return nil, err
	}
	return &ret, nil
}

func (s *API) GetSubdomain(ctx context.Context, domain string, verbose bool) (*JsonSubDomain, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s?key=%s", URLDOMAIN, domain, s.apiKey), nil)
	if err != nil {
		return nil, err
	}

	if verbose {
		log.Println("Sending request to Shodan API for subdomains")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var sub JsonSubDomain
	if err := json.NewDecoder(res.Body).Decode(&sub); err != nil {
		return nil, err
	}
	return &sub, nil
}

func GetValidKey(ctx context.Context, keys []string, maxGoroutines int, verbose bool) (string, error) {
	if verbose {
		log.Println("Validating keys...")
	}
	var mu sync.Mutex
	validKeyChan := make(chan string, 1)
	errChan := make(chan error, len(keys))
	sem := make(chan struct{}, maxGoroutines)

	var wg sync.WaitGroup

	// Test the first key
	wg.Add(1)
	go func(k string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		api := New(k)
		info, err := api.InfoAccount(ctx, verbose)
		if err != nil {
			if verbose {
				log.Printf("Key %s is invalid: %v\n", k, err)
			}
			errChan <- err
			return
		}
		if verbose {
			log.Printf("Key %s is valid with %d query credits\n", k, info.QueryCredits)
		}
		if info.QueryCredits > 0 {
			mu.Lock()
			select {
			case validKeyChan <- k:
			default:
			}
			mu.Unlock()
		} else {
			if verbose {
				log.Printf("Key %s has no query credits\n", k)
			}
			errChan <- fmt.Errorf("no query credits")
		}
	}(keys[0])

	for i := 1; i < len(keys); i++ {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			time.Sleep(1 * time.Second)
			api := New(k)
			info, err := api.InfoAccount(ctx, verbose)
			if err != nil {
				if verbose {
					log.Printf("Key %s is invalid: %v\n", k, err)
				}
				errChan <- err
				return
			}
			if verbose {
				log.Printf("Key %s is valid with %d query credits\n", k, info.QueryCredits)
			}
			if info.QueryCredits > 0 {
				mu.Lock()
				select {
				case validKeyChan <- k:
				default:
				}
				mu.Unlock()
			} else {
				if verbose {
					log.Printf("Key %s has no query credits\n", k)
				}
				errChan <- fmt.Errorf("no query credits")
			}
		}(keys[i])
	}

	go func() {
		wg.Wait()
		close(validKeyChan)
		close(errChan)
	}()

	select {
	case key := <-validKeyChan:
		return key, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-errChan:
		// If all keys are invalid
		return "", fmt.Errorf("no valid keys available... erro:\n", err)
	}
}
