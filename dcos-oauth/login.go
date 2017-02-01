package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/stratio/paas-oauth/common"
	"golang.org/x/net/context"
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
	log.Printf("Code: %s", code)

	o2cli := oauth2Client(ctx)

	token, err := o2cli.RequestToken(oauth2.GrantTypeAuthCode, code[0])

	if err != nil {
		log.Print("error %w", err)
	}

	log.Printf("Token: %+v", token)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	profileUrl := ctx.Value("oauth-profile-url").(string) + token.AccessToken

	log.Printf("Getting profile: %s", profileUrl)

	resp, err := client.Get(profileUrl)

	if err != nil {
		log.Print("error %w", err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Print("error %w", err)
	}

	log.Printf("Profile: %s", contents)

	var um profileStruct
	err = json.Unmarshal([]byte(contents), &um)

	if err != nil {
		log.Print("error %w", err)
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
        log.Printf("UserID: %s, Mail: %s, Roles: %v" , um.Id, mail, roles)
	for _, val := range roles {
		if val == authorized_role {
			log.Printf("authorized role!!: %s", val)
			authorized = true
		}
	}
	if !authorized {
		return common.NewHttpError("User " + mail + " unauthorized (missing role: " + authorized_role + ")", http.StatusUnauthorized)
	}
	

	claims := jose.Claims{
		"uid": mail,
	}

	secretKey, _ := ctx.Value("secret-key").([]byte)

	clusterToken, err := jose.NewSignedJWT(claims, jose.NewSignerHMAC("secret", secretKey))
	if err != nil {
		return common.NewHttpError("JWT creation error", http.StatusInternalServerError)
	}
	encodedClusterToken := clusterToken.Encode()

	const cookieMaxAge = 388800
	// required for IE 6, 7 and 8
	expiresTime := time.Now().Add(cookieMaxAge * time.Second)

	authCookie := &http.Cookie{
		Name:     "dcos-acs-auth-cookie",
		Value:    encodedClusterToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  expiresTime,
		MaxAge:   cookieMaxAge,
	}
	http.SetCookie(w, authCookie)

	user := User{
		Uid:         mail,
	//	Description: uid,
	//	IsRemote:    false,
	}
	userBytes, err := json.Marshal(user)
	if err != nil {
		log.Printf("Marshal: %v", err)
		return common.NewHttpError("JSON marshalling failed", http.StatusInternalServerError)
	}
	infoCookie := &http.Cookie{
		Name:    "dcos-acs-info-cookie",
		Value:   base64.URLEncoding.EncodeToString(userBytes),
		Path:    "/",
		Expires: expiresTime,
		MaxAge:  cookieMaxAge,
	}
	http.SetCookie(w, infoCookie)

	http.Redirect(w, r, "https://"+r.Host, http.StatusFound)

	return nil
}

func handleLogout(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	// required for IE 6, 7 and 8
	expiresTime := time.Unix(1, 0)

	for _, name := range []string{"dcos-acs-auth-cookie", "dcos-acs-info-cookie"} {
		cookie := &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Expires:  expiresTime,
			MaxAge:   -1,
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
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	o2cli, _ := oauth2.NewClient(client, conf)
	return o2cli
}
