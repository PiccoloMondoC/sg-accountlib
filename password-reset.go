// sg-account/pkg/clientlib/accountlib/password-reset.go
package accountlib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// PasswordResetToken represents a password reset token record in the database
type PasswordResetToken struct {
	Token     string    `json:"token"`
	UserID    uuid.UUID `json:"user_id"`
	CreatedAt string    `json:"created_at"`
	Expiry    string    `json:"expiry"`
}

// CreatePasswordResetTokenInput represents the input required to create a password reset token.
type CreatePasswordResetTokenInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// CreatePasswordResetToken creates a password reset token for the user.
func (c *Client) CreatePasswordResetToken(ctx context.Context, input CreatePasswordResetTokenInput) (*PasswordResetToken, error) {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/passwordresettokens", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var createdPasswordResetToken PasswordResetToken
	if err := json.NewDecoder(resp.Body).Decode(&createdPasswordResetToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &createdPasswordResetToken, nil
}

// ProcessPasswordResetInput represents the input required to process a password reset.
type ProcessPasswordResetInput struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// PasswordResetResponse represents the response from the password reset processing endpoint.
type PasswordResetResponse struct {
	Message string    `json:"message"`
	UserID  uuid.UUID `json:"user_id"`
}

// ProcessPasswordReset processes a password reset using the provided token and new password.
func (c *Client) ProcessPasswordReset(ctx context.Context, input ProcessPasswordResetInput) (*PasswordResetResponse, error) {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/processpasswordreset", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var passwordResetResponse PasswordResetResponse
	if err := json.NewDecoder(resp.Body).Decode(&passwordResetResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &passwordResetResponse, nil
}

// GetPasswordResetTokensByUserIDInput represents the input required to get password reset tokens by user ID
type GetPasswordResetTokensByUserIDInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// GetPasswordResetTokensByUserID retrieves password reset tokens for the user by their user ID.
func (c *Client) GetPasswordResetTokensByUserID(ctx context.Context, input GetPasswordResetTokensByUserIDInput) ([]PasswordResetToken, error) {
	// Prepare the URL with the user ID.
	url := fmt.Sprintf("%s/passwordresettokens?user_id=%s", c.BaseURL, input.UserID.String())

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var tokens []PasswordResetToken
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return tokens, nil
}

// GetPasswordResetTokenByPlaintextInput represents the input required to get a password reset token by plaintext
type GetPasswordResetTokenByPlaintextInput struct {
	Plaintext string `json:"plaintext"`
}

// GetPasswordResetTokenByPlaintext retrieves a password reset token by its plaintext.
func (c *Client) GetPasswordResetTokenByPlaintext(ctx context.Context, input GetPasswordResetTokenByPlaintextInput) (*PasswordResetToken, error) {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/passwordresettoken", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var token PasswordResetToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &token, nil
}

// DeletePasswordResetTokenInput represents the input required to delete a password reset token
type DeletePasswordResetTokenInput struct {
	TokenID uuid.UUID `json:"token_id"`
}

// DeletePasswordResetToken deletes a password reset token
func (c *Client) DeletePasswordResetToken(ctx context.Context, input DeletePasswordResetTokenInput) error {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/passwordresettokens/"+input.TokenID.String(), bytes.NewBuffer(payloadBytes))
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

// DeletePasswordResetTokenByUserIDInput represents the input required to delete password reset tokens by user ID
type DeletePasswordResetTokenByUserIDInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// DeletePasswordResetTokenByUserID deletes password reset tokens for a specific user ID
func (c *Client) DeletePasswordResetTokenByUserID(ctx context.Context, input DeletePasswordResetTokenByUserIDInput) error {
	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/passwordresettokens/user/"+input.UserID.String(), nil)
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

// DeleteExpiredPasswordResetTokensInput represents the input required to delete expired password reset tokens
type DeleteExpiredPasswordResetTokensInput struct{}

// DeleteExpiredPasswordResetTokens deletes expired password reset tokens
func (c *Client) DeleteExpiredPasswordResetTokens(ctx context.Context, input DeleteExpiredPasswordResetTokensInput) error {
	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/passwordresettokens/expired", nil)
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

// VerifyPasswordResetTokenInput represents the input required to verify a password reset token
type VerifyPasswordResetTokenInput struct {
	Token string `json:"token"`
}

// VerifyPasswordResetToken verifies a password reset token
func (c *Client) VerifyPasswordResetToken(ctx context.Context, input VerifyPasswordResetTokenInput) (*PasswordResetToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}
	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/passwordresettokens/verify", bytes.NewBuffer(payloadBytes))
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
	var verifiedPasswordResetToken PasswordResetToken
	if err := json.NewDecoder(resp.Body).Decode(&verifiedPasswordResetToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &verifiedPasswordResetToken, nil
}

// ValidatePasswordResetTokenInput represents the input required to validate a password reset token
type ValidatePasswordResetTokenInput struct {
	Token string `json:"token"`
}

// ValidatePasswordResetToken validates a password reset token
func (c *Client) ValidatePasswordResetToken(ctx context.Context, input ValidatePasswordResetTokenInput) (*PasswordResetToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}
	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/passwordresettokens/validate", bytes.NewBuffer(payloadBytes))
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
	var validatedPasswordResetToken PasswordResetToken
	if err := json.NewDecoder(resp.Body).Decode(&validatedPasswordResetToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &validatedPasswordResetToken, nil
}
