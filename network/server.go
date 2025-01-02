package network

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/mdlayher/vsock"
	"github.com/pkg/errors"
)

type Server struct {
	respond func(req *Request) (*Response, error)
}

func NewServer(respond func(req *Request) (*Response, error)) *Server {
	return &Server{respond}
}

func (s *Server) Serve() error {

	http.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {

		var req Request

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {

			slog.Error("failed to decode JSON",
				slog.String("error", err.Error()),
			)

			return

		}

		defer r.Body.Close()

		res, err := s.respond(&req)

		if err != nil {

			slog.Error("failed to respond",
				slog.String("error", err.Error()),
			)

			return

		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(res); err != nil {

			slog.Error("failed to encode JSON",
				slog.String("error", err.Error()),
			)

			return

		}

	})

	fh, err := vsock.Listen(Port, nil)

	if err != nil {
		return errors.Wrapf(err, "failed to listen on vsock")
	}

	return http.Serve(fh, nil)

}
