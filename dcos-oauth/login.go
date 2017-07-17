package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/stratio/paas-oauth/common"
	"golang.org/x/net/context"
	"regexp"
)

type loginRequest struct {
	Uid string `json:"uid,omitempty"`
	Password string `json:"password,omitempty"`
	Token string `json:"token,omitempty"`
}

type loginResponse struct {
	Token string `json:"token,omitempty"`
}

type profileAttributesStruct struct {
	Mail string `json:"mail"`
	Roles []string `json:"roles"`
}

type profileStruct struct {
        Id string `json:"id"`
	Attributes []profileAttributesStruct `json:"attributes"`
}

func handleLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	code := r.URL.Query()["code"]

	defer func() {
		if r:= recover(); r != nil {
			log.Error("Error creating oauth2 client")
		}
	}()

	if len(code) != 1 {
		return common.NewHttpError("Only one code is allowed", http.StatusBadRequest)
	}

	matchCode, err := regexp.MatchString(`^ST-.{2}-[\s\S]{20}-.{1,30}`, code[0])
	if matchCode == false || err != nil {
		return common.NewHttpError("Unformated paramter code", http.StatusBadRequest)
	}

	o2cli := oauth2Client(ctx)

	log.WithFields(log.Fields{"method": r.Method, "uri": r.RequestURI}).Debug("Requesting OAuth Token...")
	token, err := o2cli.RequestToken(oauth2.GrantTypeAuthCode, code[0])

	if err != nil {
		log.WithFields(log.Fields{"method": r.Method, "uri": r.RequestURI}).WithError(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false,
					     MinVersion: tls.VersionTLS11,
		},
	}
	client := &http.Client{Transport: tr}

	profileUrl := ctx.Value("oauth-profile-url").(string) + token.AccessToken

	resp, err := client.Get(profileUrl)

	if err != nil {
		log.WithFields(log.Fields{"method": r.Method, "uri": r.RequestURI}).WithError(err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.WithFields(log.Fields{"method": r.Method, "uri": r.RequestURI}).WithError(err)
	}

	var um profileStruct
	err = json.Unmarshal([]byte(contents), &um)

	if err != nil {
		log.WithFields(log.Fields{"method": r.Method, "uri": r.RequestURI}).WithError(err)
	}

        var mail string
        var roles []string

	// Look for user attributes: mail and roles
	for _, val := range um.Attributes {
		if val.Mail != "" {
			mail = val.Mail
		}
		if val.Roles != nil {
			roles = val.Roles
		}
	}

	// check if user is authorized
	authorized_role := ctx.Value("authorized-role").(string)
	authorized := false
	for _, val := range roles {
		if val == authorized_role {
			authorized = true
		}
	}
	if !authorized {
		return common.NewHttpError("User " + mail + " unauthorized (missing role)", http.StatusUnauthorized)
	}
	const cookieMaxAge = 3600 * 6 // 6 hours
	// required for IE 6, 7 and 8
	expiresTime := time.Now().Add(cookieMaxAge * time.Second)

	claims := jose.Claims{
		"uid": mail,
		"exp": expiresTime.Unix(),
	}

	secretKey, _ := ctx.Value("secret-key").([]byte)

	clusterToken, err := jose.NewSignedJWT(claims, jose.NewSignerHMAC("secret", secretKey))
	if err != nil {
		return common.NewHttpError("JWT creation error", http.StatusInternalServerError)
	}
	encodedClusterToken := clusterToken.Encode()

	domain := ctx.Value("domain").(string)
	path := ctx.Value("path").(string)

	authCookie := &http.Cookie{
		Name:     "dcos-acs-auth-cookie",
		Value:    encodedClusterToken,
		Path:     path,
		HttpOnly: true,
		Expires:  expiresTime,
		MaxAge:   cookieMaxAge,
		Secure: true,
	}

	if domain != "" {
		authCookie.Domain = domain
	}

	http.SetCookie(w, authCookie)

	user := User{
		Uid:         um.Id,
		Description: um.Id,
	}
	userBytes, err := json.Marshal(user)
	if err != nil {
		log.WithFields(log.Fields{"method": r.Method, "uri": r.RequestURI}).WithError(err)
		return common.NewHttpError("JSON marshalling failed", http.StatusInternalServerError)
	}
	infoCookie := &http.Cookie{
		Name:    "dcos-acs-info-cookie",
		Value:   base64.URLEncoding.EncodeToString(userBytes),
		Path:    path,
		Expires: expiresTime,
		MaxAge:  cookieMaxAge,
		Secure: true,
	}

        if domain != "" {
                infoCookie.Domain = domain
        }

	http.SetCookie(w, infoCookie)

	http.Redirect(w, r, "https://"+r.Host, http.StatusFound)

	return nil
}

func handleLogout(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	// required for IE 6, 7 and 8
	expiresTime := time.Unix(1, 0)

	for _, name := range []string{"dcos-acs-auth-cookie", "dcos-acs-info-cookie"} {
                domain := ctx.Value("domain").(string)
                path := ctx.Value("path").(string)
		cookie := &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     path,
			HttpOnly: true,
			Expires:  expiresTime,
			MaxAge:   -1,
		}
                if domain != "" {
                        cookie.Domain = domain
                }

		http.SetCookie(w, cookie)
	}

	return nil
}

func oauth2Client(ctx context.Context) *oauth2.Client {
	key := ctx.Value("oauth-app-key").(string)
	secret := ctx.Value("oauth-app-secret").(string)
	tokenUrl := ctx.Value("oauth-token-url").(string)
	authUrl := ctx.Value("oauth-auth-url").(string)
	callbackUrl := ctx.Value("oauth-callback-url").(string)
	conf := oauth2.Config{
		Credentials: oauth2.ClientCredentials{ID: key, Secret: secret},
		TokenURL:    tokenUrl,
		AuthMethod:  oauth2.AuthMethodClientSecretBasic,
		RedirectURL: callbackUrl,
		AuthURL:     authUrl,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false,
			MinVersion: tls.VersionTLS11,
		},
	}
	client := &http.Client{Transport: tr}

	o2cli, _ := oauth2.NewClient(client, conf)
	return o2cli
}
