package osin

import (
	"net/http"
)

const (
	E_UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type"
)

// RevokeRequest store data for revoke
type RevokeRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint"`
	AccessData    *AccessData
}

// HandleRevokeRequest implementation https://tools.ietf.org/html/rfc7009
func (s *Server) HandleRevokeRequest(w *Response, r *http.Request) *RevokeRequest {
	r.ParseForm()

	var err error
	// generate info request
	tokenTypeHint := r.Form.Get("token_type_hint")
	token := r.Form.Get("token")
	ret := &RevokeRequest{
		Token: token,
		TokenTypeHint: tokenTypeHint,
	}

	if token == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	switch tokenTypeHint {
	case "access_token":
		// load access data
		ret.AccessData, err = w.Storage.LoadAccess(token)
		if err != nil {
			w.SetError(E_INVALID_REQUEST, "")
			w.InternalError = err
			return nil
		}
		if ret.AccessData == nil {
			w.SetError(E_INVALID_REQUEST, "")
			return nil
		}
		err = w.Storage.RemoveAccess(token)
		if err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return nil
		}
		return ret
	case "refresh_token":
		ret.AccessData, err = w.Storage.LoadRefresh(token)
		if err != nil {
			w.SetError(E_INVALID_REQUEST, "")
			w.InternalError = err
			return nil
		}
		if ret.AccessData == nil {
			w.SetError(E_INVALID_REQUEST, "")
			return nil
		}
		err = w.Storage.RemoveRefresh(token)
		if err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return nil
		}
		return ret
	}
	w.SetError(E_UNSUPPORTED_TOKEN_TYPE, "")
	return ret
}

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishRevokeRequest(w *Response, r *http.Request, rr *RevokeRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["result"] = "success"
}
