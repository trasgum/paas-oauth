package main

import (
	"net/http"
	"golang.org/x/net/context"

	"github.com/stratio/paas-oauth/common"
)

type User struct {
        Uid         string `json:"uid,omitempty"`
}

func getUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	return common.NewHttpError("getUsers not implemented", http.StatusNotImplemented)
}

func getUser(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	// Dummy User NOT CHECKED (missing oauth profile & refresh-token management). Dummy request, keep for compatibility
	// No http error is returned in order to keep compatibility when "verifying user" 
	return nil
}

func putUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	return common.NewHttpError("putUsers not implemented", http.StatusNotImplemented)
}

func deleteUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	return common.NewHttpError("deleteUsers not implemented", http.StatusNotImplemented)
}
