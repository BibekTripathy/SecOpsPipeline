package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Cost is the bcrypt cost for user passwords. Passwords are human-chosen and
// low-entropy, so unlike PATs they do need a deliberately slow hash.
const Cost = 12

// HashPassword hashes a user's web-login password.
func HashPassword(plain string) (string, error) {
	if len(plain) < 12 {
		return "", fmt.Errorf("password must be at least 12 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plain), Cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

// CheckPassword verifies a password against its stored hash.
func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
