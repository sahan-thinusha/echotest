package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"net/http"
	"time"
)
import (
	"github.com/labstack/echo/v4"
)

func main() {
	genToken()

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: func(auth string, c echo.Context) (interface{}, error) {
			keySet, err := jwk.Fetch(context.Background(), "https://raw.githubusercontent.com/sahan-thinusha/ks/main/jwks.json")
			if err != nil {
				fmt.Println(err.Error())
			}
			token, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
				if token.Method.Alg() != jwa.RS256.String() {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				kid, ok := token.Header["kid"].(string)
				if !ok {
					return nil, fmt.Errorf("kid header not found")
				}
				keys, ok := keySet.LookupKeyID(kid)
				if !ok {
					return nil, fmt.Errorf("key %v not found", kid)
				}
				publickey := &rsa.PublicKey{}
				fmt.Println(publickey)
				err = keys.Raw(publickey)
				if err != nil {
					fmt.Println(err)
					return nil, fmt.Errorf("could not parse pubkey")
				}
				return publickey, nil
			})

			if err != nil {
				fmt.Println("validate ", err)
				return nil, err
			}
			if !token.Valid {
				return nil, errors.New("invalid token")
			}
			return token, nil
		},
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	e.Logger.Fatal(e.Start(":8080"))

}
func validateJWT() {

}

func genToken() string {

	privateSigningKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEArLhb2l1jw+X1bXbri9eQaQtZ2eZaaoKxiaVpl/DtCWTFeRXK\nXCUGtyJisdsdQq9OU2ZIN9uYsPGKTilgJP4pPQc038dJCOApLPl9LRjFO30dlxrh\nloS4LS/bi5T7bvrPpekWlgCGfaTAYT/ur1ph/MLBzOHVCMC2BN2M/9TNiHTDqjuy\naWC5sIsSOvCMuGB2aI/fBLasIfTVlUaFlESMXKuEdMqVy7wCwJm4dFCx1RGvWRik\nPnhjjigqJtdmedCHCnLEPjQAmcf325LKNmWCsGaAK4eR7cqjpwzVM9+KCbjNYmAZ\nMDI3miSIPckUj7tLskUCdr2XRcV4WvIhiCThuwIDAQABAoIBAQCYycVHV9HHG4eO\nO+KGJDy1D7t+DE3zZoWS0+ai6BdndeNSB7qo5IAaRKq11rT9poJNOG+uKe3aqPDF\nz8gjMUpdmCBnzKyI03LZPCJFYGIpC7a/UqI4OlOKdYlq4nHBbNF/XMAEFZbjUnh0\nDtAgAn4n0EkL6sI/KepaR3pRXXgrulrBda3HAvpfRoqOUUJTKJQrSERTJfXxQ+VB\nq0Bhgumn/XQIsMtvl1pRLZOQEce2MN8kERNGiIkviMt56tnr4m5QHivIqI1ij9Pl\nzcDjD0O4uiRuKYVDw/ruV3v4Ww89pbbDJZsISiG9VvAxdExXwv6k7CuvOxNi7AvB\nPcdnu/OxAoGBANWYJIHLhd59a2ZqhspfMrkA2sntd6xAikYr6P4QVXZ3ud4bY023\nA87aW+VCH8CCvCCG1L9CZNc2It4F/xmSkG4MG8EscXi89CK6B/6lchiG3wqawVW9\n4ql228pscZphFPa6JSLhVzuj3wUZmabBJYHWp7TMTnOeO/dScKOjmyEHAoGBAM8C\nzR+EBPD35TUCJPVm1Agw9WwDccs0KyW8OH1YzcSNQmxKPq6xZYEqCq/jnGop7WSM\np23Lvf1Mii5haTECktksofl+CHw1eSFrZuRThtqYvtGvn4dq2eoWQGGRPAoq/UhX\ngiTDLevPukj3WqtIeOGNoxyiusvgsohLwFNKn/CtAoGADC0YJ64Ke5x6uuPnuzGi\nGpnJ3ykCYXdsaoOmTJVxyccZeWfmSU/dj7Uy9+bFGJxbTR9ikWSfiwUzB6Uf3b1V\nLnDSRDjcXx2mbTRdsE6OKofFvz0DOHgSq8Zy0R9Nepd+MnJ6G3rtFiFJXWkQMUlh\ncf1iohPjhQPIN1kjwrBY75ECgYApgiFJQXqQKtTN1Tk977lyTwbW+rXVjgdc0Knv\nEGBqGf0Io7Z/5tg4lwp/jD8v1mpgcAeeb20QHknS1Pt3tVFmtJlh4pCm/z3jopqG\nC+2NZXVVrEZrq9Q4KPAN4EZOr6IL4GgbIPvTPdrXiKmokKaUa4caVdLo0Ixb4fyV\ndvAtHQKBgGbW10DMKVP0Y2FbaYKQzVvmzRBPN8KtA8HM7ZUfxOdwMt5a8W94fi44\nNezs0GapQrsY37RUWFW8FKiUo8CDsVBv+OB2r2WyzOVBjU2D/VjgmgqsmeL6f5y6\ngF7wzv+YL90COgMdivjQXBqwV61jw9UjVHqC2hShSEhk+7a8Mv1p\n-----END RSA PRIVATE KEY-----"
	kid := "MTk5NjA3YjRkNGRmZmI4NTYyMzEzZWFhZGM1YzAyZWMyZTg0ZGQ4Yw"

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateSigningKey))
	if err != nil {
		log.Println(err)
	}
	token := jwt.New(jwt.SigningMethodRS256)

	headers := token.Header
	headers["kid"] = kid

	claims := token.Claims.(jwt.MapClaims)

	roles := []string{}

	userId := ""

	userId = "abcd"

	claims["user"] = userId
	claims["roles"] = roles
	exp := time.Now().Add(time.Hour * 24).Unix()
	claims["exp"] = exp

	tokenString, err := token.SignedString(key)
	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return ""
	}

	fmt.Println("Token : ", tokenString)
	return tokenString
}
