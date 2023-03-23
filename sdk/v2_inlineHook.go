package sdk

import (
	"context"
	"fmt"
	"time"

	"github.com/okta/terraform-provider-okta/sdk/query"
)

type InlineHookResource resource

type InlineHook struct {
	Links       interface{}        `json:"_links,omitempty"`
	Channel     *InlineHookChannel `json:"channel,omitempty"`
	Created     *time.Time         `json:"created,omitempty"`
	Id          string             `json:"id,omitempty"`
	LastUpdated *time.Time         `json:"lastUpdated,omitempty"`
	Name        string             `json:"name,omitempty"`
	Status      string             `json:"status,omitempty"`
	Type        string             `json:"type,omitempty"`
	Version     string             `json:"version,omitempty"`
}

func (m *InlineHookResource) CreateInlineHook(ctx context.Context, body InlineHook) (*InlineHook, *Response, error) {
	url := "/api/v1/inlineHooks"

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("POST", url, body)
	if err != nil {
		return nil, nil, err
	}

	var inlineHook *InlineHook

	resp, err := rq.Do(ctx, req, &inlineHook)
	if err != nil {
		return nil, resp, err
	}

	return inlineHook, resp, nil
}

// Gets an inline hook by ID
func (m *InlineHookResource) GetInlineHook(ctx context.Context, inlineHookId string) (*InlineHook, *Response, error) {
	url := fmt.Sprintf("/api/v1/inlineHooks/%v", inlineHookId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	var inlineHook *InlineHook

	resp, err := rq.Do(ctx, req, &inlineHook)
	if err != nil {
		return nil, resp, err
	}

	return inlineHook, resp, nil
}

// Updates an inline hook by ID
func (m *InlineHookResource) UpdateInlineHook(ctx context.Context, inlineHookId string, body InlineHook) (*InlineHook, *Response, error) {
	url := fmt.Sprintf("/api/v1/inlineHooks/%v", inlineHookId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("PUT", url, body)
	if err != nil {
		return nil, nil, err
	}

	var inlineHook *InlineHook

	resp, err := rq.Do(ctx, req, &inlineHook)
	if err != nil {
		return nil, resp, err
	}

	return inlineHook, resp, nil
}

// Deletes the Inline Hook matching the provided id. Once deleted, the Inline Hook is unrecoverable. As a safety precaution, only Inline Hooks with a status of INACTIVE are eligible for deletion.
func (m *InlineHookResource) DeleteInlineHook(ctx context.Context, inlineHookId string) (*Response, error) {
	url := fmt.Sprintf("/api/v1/inlineHooks/%v", inlineHookId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.requestExecutor.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (m *InlineHookResource) ListInlineHooks(ctx context.Context, qp *query.Params) ([]*InlineHook, *Response, error) {
	url := "/api/v1/inlineHooks"
	if qp != nil {
		url = url + qp.String()
	}

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	var inlineHook []*InlineHook

	resp, err := rq.Do(ctx, req, &inlineHook)
	if err != nil {
		return nil, resp, err
	}

	return inlineHook, resp, nil
}

// Executes the Inline Hook matching the provided inlineHookId using the request body as the input. This will send the provided data through the Channel and return a response if it matches the correct data contract. This execution endpoint should only be used for testing purposes.
func (m *InlineHookResource) ExecuteInlineHook(ctx context.Context, inlineHookId string, body InlineHookPayload) (*InlineHookResponse, *Response, error) {
	url := fmt.Sprintf("/api/v1/inlineHooks/%v/execute", inlineHookId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("POST", url, body)
	if err != nil {
		return nil, nil, err
	}

	var inlineHookResponse *InlineHookResponse

	resp, err := rq.Do(ctx, req, &inlineHookResponse)
	if err != nil {
		return nil, resp, err
	}

	return inlineHookResponse, resp, nil
}

// Activates the Inline Hook matching the provided id
func (m *InlineHookResource) ActivateInlineHook(ctx context.Context, inlineHookId string) (*InlineHook, *Response, error) {
	url := fmt.Sprintf("/api/v1/inlineHooks/%v/lifecycle/activate", inlineHookId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("POST", url, nil)
	if err != nil {
		return nil, nil, err
	}

	var inlineHook *InlineHook

	resp, err := rq.Do(ctx, req, &inlineHook)
	if err != nil {
		return nil, resp, err
	}

	return inlineHook, resp, nil
}

// Deactivates the Inline Hook matching the provided id
func (m *InlineHookResource) DeactivateInlineHook(ctx context.Context, inlineHookId string) (*InlineHook, *Response, error) {
	url := fmt.Sprintf("/api/v1/inlineHooks/%v/lifecycle/deactivate", inlineHookId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("POST", url, nil)
	if err != nil {
		return nil, nil, err
	}

	var inlineHook *InlineHook

	resp, err := rq.Do(ctx, req, &inlineHook)
	if err != nil {
		return nil, resp, err
	}

	return inlineHook, resp, nil
}
