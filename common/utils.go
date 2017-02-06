package common

import (
	"net/http"
	"regexp"

)

type HttpError struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      int    `json:"-"`
}

func NewHttpError(description string, status int) *HttpError {
	return &HttpError{
		Title:       http.StatusText(status),
		Description: description,
		Status:      status,
	}
}

var (
	emailRe = regexp.MustCompile(`^[a-z0-9“”._%+-]+@(?:[a-z0-9-\[]+\.)+[a-z0-9-\]]{2,}$`)
)

func ValidateEmail(email string) bool {
	return emailRe.MatchString(email)
}
