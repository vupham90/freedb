package auth

import (
	"net/http"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	ghttp "google.golang.org/api/transport/http"
)

// ServiceConfig defines a list of configurations that can be used to customise how the Google
// service account authentication flow works.
type ServiceConfig struct {
	// HTTPClient allows the client to customise the HTTP client used to perform the REST API calls.
	// This will be useful if you want to have a more granular control over the HTTP client (e.g. using a connection pool).
	HTTPClient *http.Client

	ServiceKeyPath string
	Scopes         Scopes
}

// Service takes in service account relevant information and sets up *http.Client that can be used to access
// Google APIs seamlessly. Authentications will be handled automatically, including refreshing the access token
// when necessary.
type Service struct {
	googleAuthClient *http.Client
}

// HTTPClient returns a Google OAuth2 authenticated *http.Client that can be used to access Google APIs.
func (s *Service) HTTPClient() *http.Client {
	return s.googleAuthClient
}

// NewServiceFromFile creates a Service instance by reading the Google service account related information from a file.
//
// The "filePath" is referring to the service account JSON file that can be obtained by
// creating a new service account credentials in https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount.
//
// The "scopes" tells Google what your application can do to your spreadsheets.
func NewServiceFromFile(filePath string, scopes Scopes, config ServiceConfig) (*Service, error) {
	authConfig, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return NewServiceFromJSON(authConfig, scopes, config)
}

type ServiceOption func(*ServiceConfig)

func WithClient(client *http.Client) ServiceOption {
	return func(cfg *ServiceConfig) {
		cfg.HTTPClient = client
	}
}

func WithScope(s Scopes) ServiceOption {
	return func(cfg *ServiceConfig) {
		cfg.Scopes = s
	}
}

func WithServiceKeyPath(p string) ServiceOption {
	return func(cfg *ServiceConfig) {
		cfg.ServiceKeyPath = p
	}
}

func NewService(opts ...ServiceOption) (*Service, error) {
	cfg := &ServiceConfig{
		Scopes: GoogleSheetsReadWrite,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	client, _, err := ghttp.NewClient(
		getClientCtx(cfg.HTTPClient),
		option.WithScopes(cfg.Scopes...),
		option.WithCredentialsFile(cfg.ServiceKeyPath),
	)
	if err != nil {
		return nil, err
	}
	return &Service{
		googleAuthClient: client,
	}, nil
}

// NewServiceFromJSON works exactly the same as NewServiceFromFile, but instead of reading from a file, the raw content
// of the Google service account JSON file is provided directly.
func NewServiceFromJSON(raw []byte, scopes Scopes, config ServiceConfig) (*Service, error) {
	c, err := google.JWTConfigFromJSON(raw, scopes...)
	if err != nil {
		return nil, err
	}

	return &Service{
		googleAuthClient: c.Client(getClientCtx(config.HTTPClient)),
	}, nil
}
