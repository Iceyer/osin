package osin

import (
	"net/http"
)

type RevokeRequest struct {
	AccessToken string
	AccessData  *AccessData
}

func (s *Server) HandleRevokeRequest(w *Response, r *http.Request) *RevokeRequest {
	r.ParseForm()

	// generate info request
	ret := &RevokeRequest{
		AccessToken: r.Form.Get("access_token"),
	}

	if ret.AccessToken == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	var err error

	// load access data
	ret.AccessData, err = w.Storage.LoadAccess(ret.AccessToken)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData == nil {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}
	err = w.Storage.RemoveAccess(ret.AccessToken)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}

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
