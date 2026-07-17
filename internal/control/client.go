package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/sudogeeker/tunnel-helper/internal/core"
	"github.com/sudogeeker/tunnel-helper/internal/model"
)

type Client struct {
	http *http.Client
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("daemon API %s: %s", e.Code, e.Message)
}

func NewClient(socketPath string, timeout time.Duration) *Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: timeout}}
}

func (c *Client) CloseIdleConnections() {
	c.http.CloseIdleConnections()
}

func (c *Client) Health(ctx context.Context) (map[model.Kind]core.BackendHealth, error) {
	var response struct {
		Backends map[model.Kind]core.BackendHealth `json:"backends"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/health", nil, 0, &response); err != nil {
		return nil, err
	}
	return response.Backends, nil
}

func (c *Client) List(ctx context.Context) ([]model.TunnelView, error) {
	var response struct {
		Tunnels []model.TunnelView `json:"tunnels"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/tunnels", nil, 0, &response); err != nil {
		return nil, err
	}
	return response.Tunnels, nil
}

func (c *Client) Get(ctx context.Context, id string) (model.TunnelView, error) {
	var response model.TunnelView
	if err := c.do(ctx, http.MethodGet, "/v1/tunnels/"+id, nil, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func (c *Client) Create(ctx context.Context, record model.Tunnel) (model.TunnelView, error) {
	var response model.TunnelView
	if err := c.do(ctx, http.MethodPost, "/v1/tunnels", record, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func (c *Client) Update(ctx context.Context, view model.TunnelView) (model.TunnelView, error) {
	request := updateRequest{Generation: view.Tunnel.Generation, Tunnel: view.Tunnel}
	var response model.TunnelView
	if err := c.do(ctx, http.MethodPut, "/v1/tunnels/"+view.Tunnel.ID, request, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func (c *Client) SetEnabled(ctx context.Context, view model.TunnelView, enabled bool) (model.TunnelView, error) {
	action := "disable"
	if enabled {
		action = "enable"
	}
	var response model.TunnelView
	request := actionRequest{Generation: view.Tunnel.Generation}
	if err := c.do(ctx, http.MethodPost, "/v1/tunnels/"+view.Tunnel.ID+"/"+action, request, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func (c *Client) Delete(ctx context.Context, view model.TunnelView) error {
	return c.do(ctx, http.MethodDelete, "/v1/tunnels/"+view.Tunnel.ID, nil, view.Tunnel.Generation, nil)
}

func (c *Client) Reconcile(ctx context.Context, id string) (model.TunnelView, error) {
	var response model.TunnelView
	if err := c.do(ctx, http.MethodPost, "/v1/tunnels/"+id+"/reconcile", struct{}{}, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func (c *Client) ReconcileAll(ctx context.Context) ([]model.TunnelView, error) {
	var response struct {
		Tunnels []model.TunnelView `json:"tunnels"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/reconcile", struct{}{}, 0, &response); err != nil {
		return nil, err
	}
	return response.Tunnels, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any, generation uint64, target any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if generation != 0 {
		request.Header.Set("If-Match", strconv.FormatUint(generation, 10))
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("contact tunnel-helperd: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope errorEnvelope
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil {
			return fmt.Errorf("daemon returned HTTP %d", response.StatusCode)
		}
		return &APIError{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	if target == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	if err := decoder.Decode(target); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode daemon response: %w", err)
	}
	return nil
}
