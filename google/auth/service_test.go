package auth

import (
	"testing"

	"github.com/FreeLeh/GoFreeDB/internal/google/fixtures"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestService_CheckWrappedTransport(t *testing.T) {
	path := fixtures.PathToFixture("service_account.json")

	service, err := NewServiceFromFile(path, []string{}, ServiceConfig{})
	assert.Nil(t, err, "should not have any error instantiating the service account wrapper")

	_, ok := service.HTTPClient().Transport.(*oauth2.Transport)
	assert.True(t, ok, "the HTTP client should be using the custom Google OAuth2 HTTP transport")
}

func TestNewService_CheckWrappedTransport(t *testing.T) {
	path := fixtures.PathToFixture("service_account.json")

	service, err := NewService(WithServiceKeyPath(path))
	assert.Nil(t, err, "should not have any error instantiating the service account wrapper")

	_, ok := service.HTTPClient().Transport.(*oauth2.Transport)
	assert.True(t, ok, "the HTTP client should be using the custom Google OAuth2 HTTP transport")
}
