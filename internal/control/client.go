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

	"github.com/TunnelHelper/TH/internal/backup"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
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

func (c *Client) WatchEvents(ctx context.Context, after uint64) (<-chan core.Event, <-chan error, error) {
	path := "/v1/events?after=" + strconv.FormatUint(after, 10)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return nil, nil, err
	}
	streamClient := &http.Client{Transport: c.http.Transport}
	response, err := streamClient.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("contact thd: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		var envelope errorEnvelope
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil {
			return nil, nil, fmt.Errorf("daemon returned HTTP %d", response.StatusCode)
		}
		return nil, nil, &APIError{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	events := make(chan core.Event, 64)
	errors := make(chan error, 1)
	go func() {
		defer response.Body.Close()
		defer close(events)
		defer close(errors)
		decoder := json.NewDecoder(response.Body)
		for {
			var event core.Event
			if err := decoder.Decode(&event); err != nil {
				if ctx.Err() == nil {
					errors <- fmt.Errorf("read daemon event stream: %w", err)
				}
				return
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, errors, nil
}

func (c *Client) Health(ctx context.Context) (HealthResponse, error) {
	var response HealthResponse
	if err := c.do(ctx, http.MethodGet, "/v1/health", nil, 0, &response); err != nil {
		return HealthResponse{}, err
	}
	return response, nil
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
	return c.CreateWithWait(ctx, record, false)
}

func (c *Client) CreateWithWait(ctx context.Context, record model.Tunnel, wait bool) (model.TunnelView, error) {
	var response model.TunnelView
	if err := c.do(ctx, http.MethodPost, waitPath("/v1/tunnels", wait), record, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func (c *Client) Update(ctx context.Context, view model.TunnelView) (model.TunnelView, error) {
	return c.UpdateWithWait(ctx, view, false)
}

func (c *Client) UpdateWithWait(ctx context.Context, view model.TunnelView, wait bool) (model.TunnelView, error) {
	request := updateRequest{Generation: view.Tunnel.Generation, Tunnel: view.Tunnel}
	var response model.TunnelView
	if err := c.do(ctx, http.MethodPut, waitPath("/v1/tunnels/"+view.Tunnel.ID, wait), request, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func (c *Client) SetEnabled(ctx context.Context, view model.TunnelView, enabled bool) (model.TunnelView, error) {
	return c.SetEnabledWithWait(ctx, view, enabled, false)
}

func (c *Client) SetEnabledWithWait(ctx context.Context, view model.TunnelView, enabled, wait bool) (model.TunnelView, error) {
	action := "disable"
	if enabled {
		action = "enable"
	}
	var response model.TunnelView
	request := actionRequest{Generation: view.Tunnel.Generation}
	path := "/v1/tunnels/" + view.Tunnel.ID + "/" + action
	if err := c.do(ctx, http.MethodPost, waitPath(path, wait), request, 0, &response); err != nil {
		return model.TunnelView{}, err
	}
	return response, nil
}

func waitPath(path string, wait bool) string {
	if wait {
		return path + "?wait=true"
	}
	return path
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

func (c *Client) PlanBundle(ctx context.Context, bundle model.Bundle, prune bool) (core.BundlePlan, error) {
	var response core.BundlePlan
	request := bundleRequest{Bundle: bundle, Prune: prune}
	if err := c.do(ctx, http.MethodPost, "/v1/plan", request, 0, &response); err != nil {
		return core.BundlePlan{}, err
	}
	return response, nil
}

func (c *Client) ApplyBundle(ctx context.Context, bundle model.Bundle, prune, wait bool) (core.BundleApplyResult, error) {
	var response core.BundleApplyResult
	request := bundleRequest{Bundle: bundle, Prune: prune}
	if err := c.do(ctx, http.MethodPost, waitPath("/v1/apply", wait), request, 0, &response); err != nil {
		return core.BundleApplyResult{}, err
	}
	return response, nil
}

func (c *Client) Backup(ctx context.Context, passphrase string, writer io.Writer) error {
	data, err := json.Marshal(backupRequest{Passphrase: passphrase})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/admin/backup", bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("contact thd: %w", err)
	}
	defer response.Body.Close()
	if err := decodeAPIResponseError(response); err != nil {
		return err
	}
	written, err := io.Copy(writer, io.LimitReader(response.Body, backup.MaxEncryptedBytes+1))
	if err != nil {
		return fmt.Errorf("download encrypted backup: %w", err)
	}
	if written > backup.MaxEncryptedBytes {
		return errors.New("encrypted backup exceeds size limit")
	}
	if trailerError := response.Trailer.Get("X-TH-Backup-Error"); trailerError != "" {
		return fmt.Errorf("daemon failed to encrypt backup: %s", trailerError)
	}
	return nil
}

func (c *Client) RestoreBackup(ctx context.Context, passphrase string, reader io.Reader, check, wait bool) (core.RestoreResult, error) {
	path := "/v1/admin/restore?check=" + strconv.FormatBool(check) + "&wait=" + strconv.FormatBool(wait)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, io.LimitReader(reader, backup.MaxEncryptedBytes+1))
	if err != nil {
		return core.RestoreResult{}, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-TH-Backup-Passphrase", passphrase)
	response, err := c.http.Do(request)
	if err != nil {
		return core.RestoreResult{}, fmt.Errorf("contact thd: %w", err)
	}
	defer response.Body.Close()
	if err := decodeAPIResponseError(response); err != nil {
		return core.RestoreResult{}, err
	}
	var result core.RestoreResult
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&result); err != nil {
		return core.RestoreResult{}, fmt.Errorf("decode daemon response: %w", err)
	}
	return result, nil
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
		return fmt.Errorf("contact thd: %w", err)
	}
	defer response.Body.Close()
	if err := decodeAPIResponseError(response); err != nil {
		return err
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

func decodeAPIResponseError(response *http.Response) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	var envelope errorEnvelope
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil {
		return fmt.Errorf("daemon returned HTTP %d", response.StatusCode)
	}
	return &APIError{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
}
