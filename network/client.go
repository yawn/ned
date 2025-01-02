package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/mdlayher/vsock"
	"github.com/pkg/errors"
)

type Client struct {
	client http.Client
}

func NewClient() *Client {

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return vsock.Dial(EnclaveCID, Port, nil)
			},
		},
	}

	return &Client{client}
}

func (c *Client) Request(req *Request) (*Response, error) {

	body, err := json.Marshal(req)

	if err != nil {
		return nil, errors.Wrapf(err, "failed to encode request")
	}

	uri := fmt.Sprintf("http://localhost:%d/", Port)

	res, err := c.client.Post(uri, "application/json", bytes.NewBuffer(body))

	if err != nil {
		return nil, errors.Wrapf(err, "failed to send request")
	}

	defer res.Body.Close()

	var r Response

	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return nil, errors.Wrapf(err, "failed to decode response")
	}

	return &r, nil

}
