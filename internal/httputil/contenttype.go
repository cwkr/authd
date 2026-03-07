package httputil

import (
	"mime"
	"slices"
	"strings"
)

func IsJSON(contentType string) bool {
	var mediaType, _, err = mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "application") && strings.HasSuffix(mediaType, "json")
}

func IsFormData(contentType string) bool {
	var mediaType, _, err = mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return slices.Contains([]string{"application/x-www-form-urlencoded", "multipart/form-data"}, mediaType)
}
