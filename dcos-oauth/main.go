package main

import (
	"os"

	"github.com/codegangsta/cli"
	"golang.org/x/net/context"

	"github.com/stratio/paas-oauth/common"
)

func main() {
	serveCommand := cli.Command{
		Name:      "serve",
		ShortName: "s",
		Usage:     "Serve the API",
		Flags:     []cli.Flag{common.FlAddr, common.FlZkAddr, flIssuerURL, flClientID, flSecretKeyPath,
		flSegmentKey, flOauthAppKey, flOauthAppSecret, flOauthTokenUrl, flOauthAuthUrl,
		flOauthProfileUrl,flOauthCallbackUrl,flAuthorizedRole},
		Action:    action(serveAction),
	}

	common.Run("dcos-oauth", serveCommand)
}

func serveAction(c *cli.Context) error {
	ctx := context.Background()

	ctx = context.WithValue(ctx, "issuer-url", c.String("issuer-url"))
	ctx = context.WithValue(ctx, "client-id", c.String("client-id"))
	ctx = context.WithValue(ctx, "segment-key", c.String("segment-key"))
	ctx = context.WithValue(ctx, "oauth-app-key", c.String("oauth-app-key"))
	ctx = context.WithValue(ctx, "oauth-app-secret", c.String("oauth-app-secret"))
	ctx = context.WithValue(ctx, "oauth-token-url", c.String("oauth-token-url"))
	ctx = context.WithValue(ctx, "oauth-auth-url", c.String("oauth-auth-url"))
	ctx = context.WithValue(ctx, "oauth-callback-url", c.String("oauth-callback-url"))
	ctx = context.WithValue(ctx, "oauth-profile-url", c.String("oauth-profile-url"))
	ctx = context.WithValue(ctx, "authorized-role", c.String("authorized-role"))

	secretKey, err := common.ReadLine(c.String("secret-key-path"))
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, "secret-key", secretKey)

	// TODO not used everywhere yet
	ctx = context.WithValue(ctx, "zk-path", "/dcos/users")

	return common.ServeCmd(c, ctx, routes)
}

func action(f func(c *cli.Context) error) func(c *cli.Context) {
	return func(c *cli.Context) {
		err := f(c)
		if err != nil {
			os.Exit(1)
		}
	}
}
