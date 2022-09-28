package cmict

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/mitchellh/mapstructure"

	"golang.org/x/oauth2"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
)

func init() {
	identityprovider.RegisterOAuthProvider(&cmictProviderFactory{})
}

type cmictOauth struct {
	// ClientID is the application's ID.
	ClientID string `json:"clientID" yaml:"clientID"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"clientSecret" yaml:"clientSecret"`

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.Endpoint.
	Endpoint endpoint `json:"endpoint" yaml:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `json:"redirectURL" yaml:"redirectURL"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes" yaml:"scopes"`

	Config *oauth2.Config `json:"-" yaml:"-"`
}

// endpoint represents an OAuth 2.0 provider's authorization and token
// endpoint URLs.
type endpoint struct {
	AuthURL     string `json:"authURL" yaml:"authURL"`
	TokenURL    string `json:"tokenURL" yaml:"tokenURL"`
	UserInfoURL string `json:"userInfoURL" yaml:"userInfoURL"`
}

type cmictIdentity struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

type cmictProviderFactory struct {
}

func (f *cmictProviderFactory) Type() string {
	return "cmictOauthProvider"
}

func (f *cmictProviderFactory) Create(options oauth.DynamicOptions) (identityprovider.OAuthProvider, error) {
	var cmict cmictOauth
	if err := mapstructure.Decode(options, &cmict); err != nil {
		return nil, err
	}
	cmict.Config = &oauth2.Config{
		ClientID:     cmict.ClientID,
		ClientSecret: cmict.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   cmict.Endpoint.AuthURL,
			TokenURL:  cmict.Endpoint.TokenURL,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: cmict.RedirectURL,
		Scopes:      cmict.Scopes,
	}
	return &cmict, nil
}

func (a cmictIdentity) GetUserID() string {
	return a.Username
}

func (a cmictIdentity) GetUsername() string {
	return a.Username
}

func (a cmictIdentity) GetEmail() string {
	return a.Email
}

func (a *cmictOauth) IdentityExchangeCallback(req *http.Request) (identityprovider.Identity, error) {
	// OAuth2 callback, see also https://tools.ietf.org/html/rfc6749#section-4.1.2
	code := req.URL.Query().Get("code")
	ctx := req.Context()
	token, err := a.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	resp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)).Get(a.Endpoint.UserInfoURL)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var UserInfoResp cmictIdentity
	err = json.Unmarshal(data, &UserInfoResp)
	if err != nil {
		return nil, err
	}

	return UserInfoResp, nil
}
