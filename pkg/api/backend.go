package api

import "net/http"

// Backend is the transport-agnostic interface that service packages depend on
// instead of the concrete *Client. The cloud HTTP *Client satisfies it; an
// in-process offline implementation (pkg/api/offline) satisfies it too.
//
// The shape mirrors *Client so existing call sites work unchanged.
type Backend interface {
	Call(endpointKey, method string, data interface{}, urlParams, queryParams map[string]string) (*http.Response, error)
	DecodeError(resp *http.Response) error
}

var _ Backend = (*Client)(nil)
