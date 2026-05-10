package gitlab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client communicates with the GitLab API.
// Every API call goes through this client.
type Client struct {
	baseURL    string       // "https://gitlab.com" or self-hosted URL
	token      string       // Private token or project access token
	httpClient *http.Client // Customized for timeout configuration
}

// NewClient creates a new GitLab API client.
//
// baseURL: address of the GitLab instance.
//
//	For GitLab.com: "https://gitlab.com"
//	For self-hosted: "https://gitlab.example.com"
//
// token: GitLab Personal Access Token or Project Access Token.
//
//	Required scopes: read_api
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// get sends a GET request to the specified endpoint and
// unmarshals the response body into the given struct.
//
// endpoint example: "/api/v4/projects/123/variables"
// target: pointer to the struct to unmarshal into
func (c *Client) get(endpoint string, target interface{}) error {
	url := c.baseURL + endpoint

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// GitLab API uses PRIVATE-TOKEN header for authentication.
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Non-2xx status code → error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("JSON parse error: %w", err)
	}

	return nil
}

// getWithPagination is used for endpoints that return paginated results.
// GitLab API returns 20 results by default for list endpoints.
// We must fetch page by page to get all results.
//
// GitLab pagination:
//
//	GET /api/v4/projects/:id/variables?page=1&per_page=100
//	Response headers: X-Next-Page, X-Total-Pages
//
// This function automatically fetches and merges all pages.
func (c *Client) getWithPagination(endpoint string) ([]json.RawMessage, error) {
	var allItems []json.RawMessage
	page := 1

	for {
		// Fetch each page with up to 100 items
		url := fmt.Sprintf("%s%s?page=%d&per_page=100", c.baseURL, endpoint, page)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("PRIVATE-TOKEN", c.token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %w", err)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return nil, fmt.Errorf("API error: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		// Parse items on this page
		var items []json.RawMessage
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("page %d parse error: %w", page, err)
		}

		allItems = append(allItems, items...)

		// Check if there is a next page.
		// If X-Next-Page is empty, we are on the last page.
		nextPage := resp.Header.Get("X-Next-Page")
		if nextPage == "" || len(items) == 0 {
			break
		}
		page++
	}

	return allItems, nil
}
