package cosign

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"strings"
)

func Parse(token string) (Token, error) {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token expected three segments got %d", len(parts))
	}

	parsedToken := &StringToken{
		TokenEncoded:     token,
		HeaderEncoded:    parts[0],
		ClaimsEncoded:    parts[1],
		SignatureEncoded: parts[2],
	}

	headerBytes, err := jwt.DecodeSegment(parsedToken.HeaderEncoded)

	if err != nil {
		return nil, fmt.Errorf("could not decode header: %w", err)
	}

	parsedToken.HeaderBytes = headerBytes

	err = json.Unmarshal(headerBytes, &parsedToken.Header)

	if err != nil {
		return nil, fmt.Errorf("could not unmarshal header: %w", err)
	}

	claimsBytes, err := jwt.DecodeSegment(parsedToken.ClaimsEncoded)

	if err != nil {
		return nil, fmt.Errorf("could not decode claims: %w", err)
	}

	parsedToken.ClaimsBytes = claimsBytes

	signature, err := jwt.DecodeSegment(parsedToken.SignatureEncoded)

	if err != nil {
		return nil, fmt.Errorf("could not decode signature: %w", err)
	}

	parsedToken.SignatureBytes = signature

	if parsedToken.Header.CoSignerVersion == CoSignerV1 && parsedToken.Header.PreviousSigner != nil {
		parsedToken.PreviousToken, err = parsedToken.AssemblePreviousToken()

		if err != nil {
			return nil, fmt.Errorf("could not create previous token: %w", err)
		}
	}

	return parsedToken, nil
}
