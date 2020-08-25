package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btnguyen2k/consu/reddo"
	"github.com/btnguyen2k/consu/semita"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"

	"main/cocostore"
)

const (
	exterMyAppId = "demo"

	sessionKeyLoginToken  = "auth_jwt"
	sessionKeySessionInfo = "sess_info"
)

var (
	exterRsaPubKey       *rsa.PublicKey
	httpClient           = &http.Client{Timeout: 10 * time.Second}
	errorSessionNotReady = errors.New("session is not ready, try again latter")

	forceLogin                  = false
	urlExterBase                = "http://localhost"
	urlExterApiBase             = urlExterBase + ":3000"
	urlExterApiInfo             = urlExterApiBase + "/info"
	urlExterApiVerifyLoginToken = urlExterApiBase + "/api/verifyLoginToken"
	urlExterPageBase            = urlExterBase + ":8080"
	urlExterXLogin              = urlExterPageBase + "/app/#/xlogin"
	urlExterXCheck              = urlExterPageBase + "/app/#/xcheck"
)

type SessionInfo struct {
	Id            string    `json:"jti"`
	Type          string    `json:"type"`
	UserId        string    `json:"uid"`
	Channel       string    `json:"sub"`
	ExpiredAtUnix int64     `json:"exp"`
	ExpiredAt     time.Time `json:"-"`
	CreatedAtUnix int64     `json:"iat"`
	CreatedAt     time.Time `json:"-"`
}

func main() {
	if strings.TrimSpace(os.Getenv("FORCE_LOGIN")) != "" {
		forceLogin = true
	}
	if strings.TrimSpace(os.Getenv("EXTER_BASE_URL")) != "" {
		urlExterBase = strings.TrimRight(strings.TrimSpace(os.Getenv("EXTER_BASE_URL")), "/")
		urlExterApiBase = urlExterBase
		urlExterApiInfo = urlExterApiBase + "/info"
		urlExterApiVerifyLoginToken = urlExterApiBase + "/api/verifyLoginToken"
		urlExterPageBase = urlExterBase
		urlExterXLogin = urlExterPageBase + "/app/#/xlogin"
		urlExterXCheck = urlExterPageBase + "/app/#/xcheck"
	}

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	go goUpdateExterInfo(ticker, httpClient)

	// Echo instance
	e := echo.New()
	// e.Use(session.Middleware(sessions.NewCookieStore([]byte("s3cr3t"))))
	// e.Use(session.Middleware(memstore.NewMemStore([]byte("s3cr3t"))))
	e.Use(session.Middleware(cocostore.NewCompressedCookieStore([]byte("s3cr3t"))))
	gob.Register(SessionInfo{})

	// Routes
	e.GET("/login", handlerLogin)
	e.GET("/loginCallback", handlerLoginCallback)
	e.GET("/logout", handlerLogout)
	e.Any("/secure", handlerSecure, middleSecurity)
	e.Any("/secure/", handlerSecure, middleSecurity)
	e.Any("/secure/*", handlerSecure, middleSecurity)
	e.GET("/*", hello)

	port := 6789
	if os.Getenv("HEROKU") != "" {
		port, _ = strconv.Atoi(os.Getenv("PORT"))
	}

	// Start server
	e.Logger.Fatal(e.Start(":" + strconv.Itoa(port)))
}

func _readAll(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func _parseRsaPublicKeyFromPem(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	} else {
		switch pub := pub.(type) {
		case *rsa.PublicKey:
			return pub, nil
		default:
			return nil, errors.New("not RSA public key")
		}
	}
}

func _parseJwtToken(jwtStr string) (*SessionInfo, error) {
	token, err := jwt.Parse(jwtStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return exterRsaPubKey, nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var sess SessionInfo
		js, _ := json.Marshal(token.Claims)
		err := json.Unmarshal(js, &sess)
		sess.CreatedAt = time.Unix(sess.CreatedAtUnix, 0)
		sess.ExpiredAt = time.Unix(sess.ExpiredAtUnix, 0)
		return &sess, err
	}
	return nil, errors.New("invalid claim")
}

func _validateJwtToken(jwtStr string) (string, *SessionInfo, error) {
	postData, _ := json.Marshal(map[string]interface{}{
		"token": jwtStr,
		"app":   exterMyAppId,
	})
	resp, err := httpClient.Post(urlExterApiVerifyLoginToken, "application/json", bytes.NewReader(postData))
	if err != nil {
		return "", nil, err
	}
	body, err := _readAll(resp)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != 200 {
		return "", nil, errors.New(fmt.Sprintf("[ERROR] Error verifying Exter token, HTTP status: %d", resp.StatusCode))
	}
	data := make(map[string]interface{})
	if err := json.Unmarshal(body, &data); err != nil {
		return "", nil, errors.New(fmt.Sprintf("[ERROR] Error verifying Exter token: %s", err.Error()))
	}
	s := semita.NewSemita(data)
	if status, err := s.GetValueOfType("status", reddo.TypeInt); err != nil || status == nil || status.(int64) != 200 {
		return "", nil, errors.New(fmt.Sprintf("[ERROR] Error verifying Exter token. Error: %s / API status: %v", err, status))
	}

	newJwtStr, err := s.GetValueOfType("data", reddo.TypeString)
	if err != nil || newJwtStr == nil || newJwtStr.(string) == "" {
		return "", nil, errors.New(fmt.Sprintf("[ERROR] Error verifying Exter token. Error: %s / New token: %v", err, newJwtStr))
	}
	sess, err := _parseJwtToken(newJwtStr.(string))
	if err != nil {
		return "", nil, err
	}

	if sess.Type != "login" {
		return newJwtStr.(string), sess, errorSessionNotReady
	}
	if sess.UserId == "" {
		return "", nil, errors.New(fmt.Sprintf("[ERROR] Error verifying Exter token. User id is empty"))
	}
	return newJwtStr.(string), sess, nil
}

/*--------------------------------------------------------------------------------*/

func goUpdateExterInfo(ticker *time.Ticker, httpClient *http.Client) {
	for t := time.Now(); true; t = <-ticker.C {
		resp, err := httpClient.Get(urlExterApiInfo)
		if err != nil {
			log.Println("[ERROR] Error while fetching Exter info: " + err.Error())
		}
		body, err := _readAll(resp)
		if err != nil {
			log.Println("[ERROR] Error while fetching Exter info: " + err.Error())
		}
		if resp.StatusCode != 200 {
			log.Println("[ERROR] Error while fetching Exter info: " + resp.Status + " / " + string(body))
		}
		data := make(map[string]interface{})
		if err := json.Unmarshal(body, &data); err != nil {
			log.Println("[ERROR] Error while fetching Exter info: " + err.Error())
		}
		s := semita.NewSemita(data)
		status, err := s.GetValueOfType("status", reddo.TypeInt)
		if err != nil || status.(int64) != 200 {
			log.Printf("[ERROR] Error while fetching Exter info: %s", body)
		}
		rsaPublicKeyPem, err := s.GetValueOfType("data.rsa_public_key", reddo.TypeString)
		if rsaPublicKeyPem == nil {
			rsaPublicKeyPem = ""
		}
		pubKey, err := _parseRsaPublicKeyFromPem(rsaPublicKeyPem.(string))
		if err != nil {
			log.Printf("[ERROR] Cannot extract Exter RSA public key: %e / %s", err, body)
		}
		exterRsaPubKey = pubKey
		log.Printf("[goUpdateExterInfo] fired at %v", t)
	}
}

/*--------------------------------------------------------------------------------*/

// Handler
func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}

// Handler
func handlerLogin(c echo.Context) error {
	returnUrl := url.QueryEscape(c.QueryParam("returnUrl"))
	returnUrl = c.Scheme() + "://" + c.Request().Host + "/loginCallback?token=${token}&returnUrl=" + returnUrl
	urlLogin := urlExterXCheck
	if forceLogin {
		urlLogin = urlExterXLogin
	}
	return c.Redirect(http.StatusFound, urlLogin+"?app="+exterMyAppId+"&returnUrl="+url.QueryEscape(returnUrl))
}

// Handler
func handlerLogout(c echo.Context) error {
	returnUrl := c.QueryParam("returnUrl")
	if returnUrl == "" {
		returnUrl = "/"
	}
	httpSess, _ := session.Get("session", c)
	httpSess.Values = make(map[interface{}]interface{})
	err := httpSess.Save(c.Request(), c.Response())
	if err != nil {
		log.Printf("[ERROR] Error while saving session: %s", err)
	}
	html := fmt.Sprintf(`Log out successfully. Click to <a href="%s">continue</a>.`, returnUrl)
	return c.HTML(http.StatusOK, html)
}

// Handler
func handlerLoginCallback(c echo.Context) error {
	returnUrl := c.QueryParam("returnUrl")
	// extract and validate authToken
	jwtStr := c.QueryParam("token")
	_, err := _parseJwtToken(jwtStr)
	if err != nil {
		urlLogin := "/login?returnUrl=" + url.QueryEscape(returnUrl)
		html := fmt.Sprintf(`Invalid login token: %s.<br/><a href="%s">Login again</a>`, err, urlLogin)
		return c.HTML(http.StatusOK, html)
	}
	jwtStr, sess, err := _validateJwtToken(jwtStr)
	if err != nil {
		urlLogin := "/login?returnUrl=" + url.QueryEscape(returnUrl)
		html := fmt.Sprintf(`Invalid login token: %s.<br/><a href="%s">Login again</a>`, err, urlLogin)
		return c.HTML(http.StatusOK, html)
	}

	// store authToken in session
	httpSess, _ := session.Get("session", c)
	httpSess.Values[sessionKeyLoginToken] = jwtStr
	httpSess.Values[sessionKeySessionInfo] = sess
	err = httpSess.Save(c.Request(), c.Response())
	if err == cocostore.ErrorValueTooLong {
		log.Printf("[WARN] Session is too big, cleaning up")
		// special case: cleanup session if leftover values make its length exceeds limit
		httpSess.Values = map[interface{}]interface{}{sessionKeyLoginToken: jwtStr, sessionKeySessionInfo: sess}
		err = httpSess.Save(c.Request(), c.Response())
		if err == cocostore.ErrorValueTooLong {
			log.Printf("[ERROR] Session is too big to store in cookie")
		} else if err != nil {
			log.Printf("[ERROR] Error while saving session: %s", err)
		}
	} else if err != nil {
		log.Printf("[ERROR] Error while saving session: %s", err)
	}
	html := fmt.Sprintf(`Login successfully.<br/>
<pre>
- ID        : %s
- Token type: %s
- Channel   : %s
- User id   : %s
- Expiry    : %s
</pre>
<a href="%s">Click</a> to continue.`, sess.Id, sess.Type, sess.Channel, sess.UserId, sess.ExpiredAt, returnUrl)
	return c.HTML(http.StatusOK, html)
}

// Handler
func handlerSecure(c echo.Context) error {
	httpSess, _ := session.Get("session", c)
	data := make(map[string]interface{})
	data["method"] = c.Request().Method
	data["url"] = c.Request().URL.String()
	data["time"] = time.Now()
	data["session"] = httpSess.Values[sessionKeySessionInfo]
	js, _ := json.Marshal(data)
	urlLogout := "/logout?returnUrl=" + url.QueryEscape(c.Request().RequestURI)
	html := fmt.Sprintf(`Login data:<br/>
<textarea style="width: 100%%" rows="4">
%s
</textarea>
<a href="%s">Click logout</>
`, js, urlLogout)
	return c.HTML(http.StatusOK, html)
}

/*----------------------------------------------------------------------*/
func middleSecurity(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		httpSess, _ := session.Get("session", c)
		jwtStr, ok := httpSess.Values[sessionKeyLoginToken].(string)
		urlLogin := "/login?returnUrl=" + url.QueryEscape(c.Request().RequestURI)
		if !ok || jwtStr == "" {
			return c.Redirect(http.StatusFound, urlLogin)
		}
		_, _, err := _validateJwtToken(jwtStr)
		if err != nil {
			log.Printf("Session validation failed [%s], redirect to login page...", err.Error())
			return c.Redirect(http.StatusFound, urlLogin)
		}
		return next(c)
	}
}
