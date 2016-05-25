package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"crypto/tls"
	"golang.org/x/net/context"
	"github.com/coreos/go-oidc/jose"
	"github.com/samuel/go-zookeeper/zk"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/dcos/dcos-oauth/common"
)

type loginRequest struct {
	Uid string `json:"uid,omitempty"`

	Password string `json:"password,omitempty"`

	Token string `json:"token,omitempty"`
}

type loginResponse struct {
	Token string `json:"token,omitempty"`
}

type secondStruct struct {
	Mail string `json:"mail"`
}

type testStruct struct {
	Clip [] secondStruct `json:"attributes"`
}

func handleLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	code := r.URL.Query()["code"]
	log.Printf("Code: %s", code)

	o2cli := oauth2Client(ctx)

	token, err := o2cli.RequestToken(oauth2.GrantTypeAuthCode, code[0])

	if err!=nil{
		log.Print("error %w",err)
	}

	log.Printf("Token: %+v", token)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}


	profileUrl := ctx.Value("oauth-profile-url").(string) + token.AccessToken

	log.Printf("Getting profile: %s", profileUrl)
	
	resp, err := client.Get(profileUrl)

	if err!=nil {
		log.Print("error %w",err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)

	if err!=nil {
		log.Print("error %w",err)
	}

	log.Printf("Profile: %s", contents)

	var um testStruct
	err = json.Unmarshal([]byte(contents),&um)

	if err!=nil {
		log.Print("error %w",err)
	}

	uid:=um.Clip[1].Mail
	c := ctx.Value("zk").(*zk.Conn)

	users, _, err := c.Children("/dcos/users")
	if err != nil && err != zk.ErrNoNode {
		return common.NewHttpError("invalid email", http.StatusInternalServerError)
	}

	userPath := fmt.Sprintf("/dcos/users/%s", uid)
	if len(users) == 0 {
		// create first user
		log.Printf("creating first user %v", uid)
		err = common.CreateParents(c, userPath, []byte(uid))
		if err != nil {
			return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
		}
	}

	exists, _, err := c.Exists(userPath)
	if err != nil || !exists {
		return common.NewHttpError("User unauthorized", http.StatusUnauthorized)
	}

	claims := jose.Claims{
		"uid": uid,
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
		Domain: ".m1.dcos",
	}
	http.SetCookie(w, authCookie)

	user := User{
		Uid:         uid,
		Description: uid,
		IsRemote:    false,
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
		Domain: ".m1.dcos",
	}
	http.SetCookie(w, infoCookie)

	json.NewEncoder(w).Encode(loginResponse{Token: encodedClusterToken})

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
