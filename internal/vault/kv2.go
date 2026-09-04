package vault

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Secret is a version of a KV v2 secret.
type Secret struct {
	Data map[string]any
	// Version is the KV v2 version of this read, used as the check-and-set
	// value of the following write. It is zero when the secret does not exist.
	Version int
}

// ReadKV2 reads the current version of a KV v2 secret. It returns
// ErrSecretNotFound when the path holds no readable version.
func (c *Client) ReadKV2(ctx context.Context, mount, path string) (*Secret, error) {
	var resp struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	err := c.requestWithReauth(ctx, "GET", kv2DataPath(mount, path), nil, &resp)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
			return nil, ErrSecretNotFound
		}
		return nil, err
	}
	if resp.Data.Data == nil {
		// A deleted version answers 200 with a null data block.
		return nil, ErrSecretNotFound
	}
	return &Secret{Data: resp.Data.Data, Version: resp.Data.Metadata.Version}, nil
}

// WriteKV2 writes a KV v2 secret using check-and-set. cas must be the version
// returned by the preceding ReadKV2, or zero to create the secret. It returns
// ErrCASMismatch when another writer won the race.
func (c *Client) WriteKV2(ctx context.Context, mount, path string, data map[string]any, cas int) (int, error) {
	body := map[string]any{
		"data":    data,
		"options": map[string]any{"cas": cas},
	}
	var resp struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	err := c.requestWithReauth(ctx, "POST", kv2DataPath(mount, path), body, &resp)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.isCASMismatch() {
			return 0, fmt.Errorf("%w: %v", ErrCASMismatch, apiErr)
		}
		return 0, err
	}
	return resp.Data.Version, nil
}

// kv2DataPath builds the API path of a KV v2 secret, escaping each segment so
// that unusual characters in a configured path cannot alter the request.
func kv2DataPath(mount, path string) string {
	return "/v1/" + escapePath(mount) + "/data/" + escapePath(path)
}

func escapePath(p string) string {
	segments := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/")
}
