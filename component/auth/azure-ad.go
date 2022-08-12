package auth

import (
	"context"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/Dreamacro/clash/log"
)

type AzureADAuthenticator struct {
	ClientID string
	AuthorityURL string
	Scopes []string

	client public.Client
}

type AzureADConfig struct {
	ClientID string
	AuthorityURL string
	Scopes []string
}

func (ad *AzureADAuthenticator) Verify(user string, pass string) bool {
	_, err := ad.client.AcquireTokenByUsernamePassword(
		context.Background(),
		ad.Scopes,
		user,
		pass,
	)
	if err != nil {
		log.Errorln("error executing login for %q: %v", user, err)
	}
	return err == nil
}

func (ad *AzureADAuthenticator) Users() (users  []string) {
	accounts := ad.client.Accounts()
	for _, ac := range accounts {
		users = append(users, ac.PreferredUsername)
	}
	return
}

func NewAzureADAuthenticator(clientID string, authorityURL string, scopes []string) (Authenticator, error)  {
	publicClientApp, err := public.New(clientID, public.WithAuthority(authorityURL))
	if err != nil {
		return nil, err
	}
	return &AzureADAuthenticator{
		client: publicClientApp,
		Scopes: scopes,
		AuthorityURL: authorityURL,
		ClientID: clientID,
	}, nil
}