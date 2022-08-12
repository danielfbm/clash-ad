package auth

import (
	"testing"
	"context"
	// "fmt"
	// "log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	// "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func TestAzureAD(t *testing.T) {
	t.Skip()
	clientId := ""
	authorityURL := ""
	username := ""
	pass := "" //nolint
	scopes := []string{"profile"}


	publicClientApp, err := public.New(clientId, public.WithAuthority(authorityURL))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("got public client app")


	result, err := publicClientApp.AcquireTokenByUsernamePassword(
		context.Background(),
		scopes,
		username,
		pass,
	)
	t.Logf("result: %v err:  %v", result.Account, err)


	var userAccount public.Account
	accounts := publicClientApp.Accounts()
	t.Log("has accounts len()", len(accounts))
	if len(accounts) > 0 {

		// Assuming the user wanted the first account
		userAccount = accounts[0]

		t.Log("preferredUserName", userAccount.PreferredUsername)
		// found a cached account, now see if an applicable token has been cached
		result, err := publicClientApp.AcquireTokenSilent(context.Background(), scopes, public.WithSilentAccount(userAccount))
		// accessToken := result.AccessToken
		if err != nil {
			t.Fatal(err)
		}

		t.Log("has accounts with result", result.Account)
	} else {
		t.Log("no accounts....")
	}

	result, err = publicClientApp.AcquireTokenByUsernamePassword(
		context.Background(),
		scopes,
		username,
		pass,
	)
	t.Logf("result: %v err:  %v", result.Account, err)

	t.Fail()
}