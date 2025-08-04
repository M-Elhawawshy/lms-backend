package main

import (
	"crypto/rsa"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"log"
	"os"
	"time"
)

type jwtCustomClaims struct {
	UserType string `json:"user_type"`
	jwt.RegisteredClaims
}

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Println("could not load env inside init")
	}
	// Load private key
	if base64Pem := os.Getenv("JWT_PRIVATE_KEY_BASE64"); base64Pem != "" {
		decodedPem, err := base64.StdEncoding.DecodeString(base64Pem)
		if err != nil {
			log.Fatalf("Failed to decode JWT_PRIVATE_KEY_BASE64: %v", err)
		}
		privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(decodedPem)
		if err != nil {
			log.Fatalf("Failed to parse RSA private key from decoded PEM: %v", err)
		}
	} else {
		privData, readErr := os.ReadFile("./config/keys/private.pem")
		if readErr != nil {
			panic("Failed to read private.pem: " + readErr.Error())
		}
		privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privData)
		if err != nil {
			panic("Failed to parse private.pem: " + err.Error())
		}
	}

	// Load public key
	if pubPem := os.Getenv("JWT_PUBLIC_KEY"); pubPem != "" {
		publicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(pubPem))
		if err != nil {
			panic("Failed to parse public key from environment: " + err.Error())
		}
	} else {
		pubData, readErr := os.ReadFile("./config/keys/public.pem")
		if readErr != nil {
			panic("Failed to read public.pem: " + readErr.Error())
		}
		publicKey, err = jwt.ParseRSAPublicKeyFromPEM(pubData)
		if err != nil {
			panic("Failed to parse public.pem: " + err.Error())
		}
	}

	if privateKey == nil || publicKey == nil {
		panic("JWT keys were not initialized properly")
	}
}

func createToken(userType, userID string, expirationDate time.Time) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims = &jwtCustomClaims{
		userType,
		jwt.RegisteredClaims{
			Issuer:    "LMS - UserService",
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expirationDate),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}

	return token.SignedString(privateKey)
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &jwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
}
