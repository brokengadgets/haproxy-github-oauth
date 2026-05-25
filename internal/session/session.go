// Package session issues and verifies HMAC-SHA256 signed JWTs for authenticated users.
package session

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims holds the JWT payload for an authenticated session.
type Claims struct {
	Teams []string `json:"teams"`
	jwt.RegisteredClaims
}

// Store signs and verifies session JWTs.
type Store struct {
	secret   []byte
	duration time.Duration
}

// New creates a Store that issues tokens valid for the given duration.
func New(secret string, duration time.Duration) *Store {
	return &Store{
		secret:   []byte(secret),
		duration: duration,
	}
}

// Issue creates a signed JWT for the given GitHub login and team memberships.
func (s *Store) Issue(login string, teams []string) (string, error) {
	now := time.Now()
	claims := Claims{
		Teams: teams,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   login,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.duration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a JWT, returning the embedded claims.
func (s *Store) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("verify jwt: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid jwt claims")
	}
	return claims, nil
}
