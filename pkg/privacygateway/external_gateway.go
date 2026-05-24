package privacygateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ExternalChatRequest is accepted only by the public-zone gateway. Prompt must
// already be produced by the private-zone privacy compiler.
type ExternalChatRequest struct {
	Prompt string `json:"prompt"`
	Model  string `json:"model,omitempty"`
}

type ExternalChatResponse struct {
	Content string                 `json:"content"`
	Model   string                 `json:"model"`
	Usage   map[string]interface{} `json:"usage,omitempty"`
}

type OpenAICompatibleClient struct {
	Endpoint   string
	APIKey     string
	Model      string
	HTTPClient *http.Client
}

func NewOpenAICompatibleClient(endpoint, apiKey, model string) *OpenAICompatibleClient {
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/chat/completions"
	}
	return &OpenAICompatibleClient{
		Endpoint: endpoint,
		APIKey:   apiKey,
		Model:    model,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (c *OpenAICompatibleClient) Chat(ctx context.Context, req ExternalChatRequest) (ExternalChatResponse, error) {
	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" {
		return ExternalChatResponse{}, errors.New("prompt is required")
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = c.Model
	}
	if model == "" {
		return ExternalChatResponse{}, errors.New("model is required")
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return ExternalChatResponse{}, errors.New("external gateway API key is not configured")
	}

	payload := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a public-zone assistant. Do not request private data, raw logs, credentials, internal URLs, or personal identifiers.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.2,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ExternalChatResponse{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return ExternalChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return ExternalChatResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ExternalChatResponse{}, fmt.Errorf("external llm returned status %d", resp.StatusCode)
	}

	var decoded struct {
		Model   string                 `json:"model"`
		Usage   map[string]interface{} `json:"usage"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return ExternalChatResponse{}, err
	}
	if len(decoded.Choices) == 0 {
		return ExternalChatResponse{}, errors.New("external llm returned no choices")
	}
	return ExternalChatResponse{
		Content: decoded.Choices[0].Message.Content,
		Model:   decoded.Model,
		Usage:   decoded.Usage,
	}, nil
}
