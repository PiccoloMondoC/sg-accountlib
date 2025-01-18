// sg-account/pkg/clientlib/accountlib/activation.go
package accountlib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// ActivationToken represents an activation token record in the database
type ActivationToken struct {
	Token  string    `json:"token"`
	UserID uuid.UUID `json:"user_id"`
	Expiry string    `json:"expiry"`
}

// CreateActivationTokenInput represents the input required to create an activation token
type CreateActivationTokenInput struct {
	UserID uuid.UUID `json:"user_id"`
}

func (c *Client) CreateActivationToken(ctx context.Context, input CreateActivationTokenInput) (*ActivationToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/activationtokens", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var createdActivationToken ActivationToken
	if err := json.NewDecoder(resp.Body).Decode(&createdActivationToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &createdActivationToken, nil
}

// ActivateUserInput represents the input required to activate a user
type ActivateUserInput struct {
	Token string `json:"token"`
}

// ActivateUser sends a request to activate a user with the given token
func (c *Client) ActivateUser(ctx context.Context, input ActivateUserInput) error {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/activate", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// GetActivationTokensByUserIDInput represents the input required to get activation tokens by user ID
type GetActivationTokensByUserIDInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// GetActivationTokensByUserID fetches all activation tokens for a given user ID
func (c *Client) GetActivationTokensByUserID(ctx context.Context, input GetActivationTokensByUserIDInput) ([]ActivationToken, error) {
	// Prepare the URL
	url, err := url.Parse(fmt.Sprintf("%s/activationtokens", c.BaseURL))
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %w", err)
	}

	// Set query parameters
	query := url.Query()
	query.Set("user_id", input.UserID.String())
	url.RawQuery = query.Encode()

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var tokens []ActivationToken
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return tokens, nil
}

// GetActivationTokenByPlaintextInput represents the input required to get an activation token by plaintext
type GetActivationTokenByPlaintextInput struct {
	Plaintext string `json:"plaintext"`
}

// GetActivationTokenByPlaintext retrieves an activation token by its plaintext value
func (c *Client) GetActivationTokenByPlaintext(ctx context.Context, input GetActivationTokenByPlaintextInput) (*ActivationToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/activationtokens/retrieve", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var retrievedActivationToken ActivationToken
	if err := json.NewDecoder(resp.Body).Decode(&retrievedActivationToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &retrievedActivationToken, nil
}

// DeleteActivationTokenInput represents the input required to delete an activation token
type DeleteActivationTokenInput struct {
	TokenID uuid.UUID `json:"token_id"`
}

func (c *Client) DeleteActivationToken(ctx context.Context, input DeleteActivationTokenInput) error {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/activationtokens/"+input.TokenID.String(), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// DeleteActivationTokenByUserIDInput represents the input required to delete activation tokens by user ID
type DeleteActivationTokenByUserIDInput struct {
	UserID uuid.UUID `json:"user_id"`
}

func (c *Client) DeleteActivationTokenByUserID(ctx context.Context, input DeleteActivationTokenByUserIDInput) error {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/activationtokens/user/"+input.UserID.String(), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// DeleteExpiredActivationTokens deletes expired activation tokens
func (c *Client) DeleteExpiredActivationTokens(ctx context.Context) error {
	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/activationtokens/expired", nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// VerifyActivationToken verifies the provided activation token
func (c *Client) VerifyActivationToken(ctx context.Context, token string) (*ActivationToken, error) {
	// Prepare the payload
	payload := map[string]string{"token": token}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/activationtokens/verify", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var verifiedActivationToken ActivationToken
	if err := json.NewDecoder(resp.Body).Decode(&verifiedActivationToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &verifiedActivationToken, nil
}
