package main

import (
	"apple-login-backend/read_pkcs8"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"math/big"
	"net/http"
	"time"
)

const (
	host               = "0.0.0.0:9999"
	appleKeyServiceURL = "https://appleid.apple.com/auth/keys"
	appleUrl           = "https://appleid.apple.com"
	keyID              = "your key id"
	teamID             = "your team id"
	clientID           = "your client id"
	appleP8            = "/path/to/your/private/key.p8"
	authUrl2           = "https://appleid.apple.com/auth/oauth2/v2/token"
)

var (
	applePrivateKeys = make(map[string]AppleKey)
)

func main() {
	if err := AppleKeyInit(); err != nil {
		fmt.Printf("初始化AppleKey失败: %s\n", err.Error())
		return
	}

	r := gin.Default()
	r.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
			fmt.Printf("绑定LoginRequest失败: %s\n", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		spew.Dump(req)

		var claim jwt.RegisteredClaims
		idToken, err := jwt.ParseWithClaims(req.IDToken, &claim, func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("no kid in header")
			}
			if kid == "" {
				return nil, fmt.Errorf("empty kid in header")
			}

			return GetAppleKey(kid)
		})
		if err != nil {
			fmt.Printf("ParseWithClaims失败: %s\n", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		issuer, err := claim.GetIssuer()
		if err != nil {
			fmt.Printf("GetIssuer失败: %s\n", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if issuer != appleUrl {
			fmt.Printf("issuer not match")
			c.JSON(http.StatusBadRequest, gin.H{"error": "issuer not match"})
			return
		}

		verifyResp, err := VerifyAppleIDToken(req.Code)
		if err != nil {
			fmt.Printf("VerifyAppleIDToken失败: %s\n", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}

		fmt.Println("来自客户端的IDToken-claim")
		spew.Dump(claim)

		fmt.Println("请求苹果验证IDToken")
		spew.Dump(verifyResp)

		remoteToken, err := jwt.Parse(verifyResp.IDToken, func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("no kid in header")
			}
			if kid == "" {
				return nil, fmt.Errorf("empty kid in header")
			}

			return GetAppleKey(kid)
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fmt.Println("检验两个IDToken是否相等", remoteToken.Claims.GetAudience() == claim.GetAudience())
		c.JSON(http.StatusOK, gin.H{"token": idToken.Raw})
	})

	if err := r.Run(host); err != nil {
		fmt.Printf("调用gin.Run() 失败: %v\n", err)
		return
	}
}

func AppleKeyInit() error {
	var resp AppleKeyResponse
	ret, err := resty.New().R().SetResult(&resp).Get(appleKeyServiceURL)
	if err != nil {
		return err
	}

	if ret.StatusCode() != http.StatusOK {
		return fmt.Errorf("请求 AppleKeyServiceURL 失败: %v", ret)
	}

	for _, key := range resp.Keys {
		applePrivateKeys[key.KeyID] = key
	}

	return nil
}

type AppleKeyResponse struct {
	Keys []AppleKey `json:"keys"`
}

// AppleKey An object that defines a single JSON Web Key. JWKSet.Keys
// @see https://developer.apple.com/documentation/sign_in_with_apple/jwkset/keys
type AppleKey struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Usage     string `json:"use"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func GetAppleKey(keyID string) (*rsa.PublicKey, error) {
	key, ok := applePrivateKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %s not found", keyID)
	}

	modBytes, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString(key.Modulus) failed: %v", err)
	}
	modules := new(big.Int).SetBytes(modBytes)

	expBytes, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString(key.Exponent) failed: %v", err)
	}
	exponent := new(big.Int).SetBytes(expBytes)
	return &rsa.PublicKey{N: modules, E: int(exponent.Uint64())}, nil
}

type LoginRequest struct {
	Code    string `json:"code" form:"code" validate:"required"`
	IDToken string `json:"id_token" form:"id_token" validate:"required"`
}

func VerifyAppleIDToken(code string) (*VerifyResponse, error) {
	bearerToken, err := makeAuthToken()
	if err != nil {
		return nil, err
	}

	var verifyResp VerifyResponse
	resp, err := resty.New().
		SetDebug(true).R().SetFormData(map[string]string{
		"client_id":     clientID,
		"client_secret": bearerToken,
		"code":          code,
		"grant_type":    "authorization_code",
	}).SetResult(&verifyResp).Post(authUrl2)

	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode() != http.StatusOK {
		log.Fatal(resp)
	}

	// Output: {
	//	"access_token": "adg61...670r9",
	//	"token_type": "Bearer",
	//	"expires_in": 3600,
	//	"refresh_token": "rca7...lABoQ",
	//	"id_token": "eyJra...96sZg"
	//}
	return &verifyResp, nil
}

func makeAuthToken() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    teamID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{appleUrl},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour * 24)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	method := jwt.SigningMethodES256
	token := &jwt.Token{
		Header: map[string]interface{}{
			"kid": keyID,
			"alg": method.Alg(),
		},
		Claims: claims,
		Method: method,
	}

	key, err := read_pkcs8.Read(appleP8)
	if err != nil {
		log.Fatal(err)
	}

	return token.SignedString(key)
}

type VerifyResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}
