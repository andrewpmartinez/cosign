package cosign

import (
	"crypto"
	"fmt"
	"github.com/golang-jwt/jwt"
	"strings"
)

const CoSignerV1 = "v1"

type Token interface {
	AddSigner(kid string, privateKey crypto.PrivateKey, signingMethod jwt.SigningMethod) (Token, error)
	Kids() []string
	Kid() string
	Previous() Token
	Verify(publicKeyProvider PublicKeyProvider) *VerifyResult
	VerifyAll(publicKeyProvider PublicKeyProvider) (bool, []*VerifyResult)
	VerifyOne(publicKeyProvider PublicKeyProvider) *VerifyResult
	Tokens() ([]string, []Token)
	Token() string
	AssemblePreviousToken() (Token, error)
}

type VerifyResult struct {
	Token   Token
	IsValid bool
	Error   error
}

var _ Token = (*StringToken)(nil)

type StringToken struct {
	HeaderEncoded string
	HeaderBytes   []byte
	Header        *Header

	ClaimsEncoded string
	ClaimsBytes   []byte

	SignatureEncoded string
	SignatureBytes   []byte

	TokenEncoded string

	PreviousToken Token
}

func (s *StringToken) Token() string {
	return s.TokenEncoded
}

func (s *StringToken) AssemblePreviousToken() (Token, error) {
	if s.Header.CoSignerVersion == CoSignerV1 && s.Header.PreviousSigner != nil {
		return Parse(s.Header.PreviousSigner.HeaderEncoded + "." + s.ClaimsEncoded + "." + s.Header.PreviousSigner.SignatureEncoded)
	}

	return nil, nil
}

func (s *StringToken) Verify(publicKeyProvider PublicKeyProvider) *VerifyResult {
	result := &VerifyResult{
		Token:   nil,
		IsValid: false,
		Error:   nil,
	}
	token, err := jwt.Parse(s.TokenEncoded, func(_ *jwt.Token) (interface{}, error) {
		return publicKeyProvider.GetPublicKey(s.Header.KeyId)
	})

	if err != nil {
		result.Error = err
	}

	if token != nil {
		result.Token = s
		result.IsValid = token.Valid
	}

	return result
}

func (s *StringToken) VerifyOne(publicKeyProvider PublicKeyProvider) *VerifyResult {
	var cur Token = s

	for cur != nil {
		result := cur.Verify(publicKeyProvider)

		if result.Error == nil && result.IsValid {
			return &VerifyResult{
				Token:   cur,
				IsValid: true,
			}
		}
		cur = cur.Previous()
	}

	return &VerifyResult{
		Token:   s,
		IsValid: false,
		Error:   nil,
	}
}

func (s *StringToken) VerifyAll(publicKeyProvider PublicKeyProvider) (bool, []*VerifyResult) {
	var results []*VerifyResult
	var cur Token = s
	allValid := true

	for cur != nil {
		result := cur.Verify(publicKeyProvider)
		results = append(results, result)

		if !result.IsValid {
			allValid = false
		}

		cur = cur.Previous()
	}

	if len(results) == 0 {
		return false, nil
	}

	return allValid, results
}

func (s *StringToken) Tokens() ([]string, []Token) {
	var tokenStrs []string
	var tokens []Token

	var cur Token = s

	for cur != nil {
		tokens = append(tokens, cur)
		tokenStrs = append(tokenStrs, cur.Token())
		cur = cur.Previous()
	}

	return tokenStrs, tokens
}

func (s *StringToken) AddSigner(kid string, privateKey crypto.PrivateKey, signingMethod jwt.SigningMethod) (Token, error) {
	header := &Header{
		KeyId:           kid,
		Algorithm:       signingMethod.Alg(),
		CoSignerVersion: CoSignerV1,
		PreviousSigner: &Signer{
			HeaderEncoded:    s.HeaderEncoded,
			SignatureEncoded: s.SignatureEncoded,
		},
	}

	headerJson, headerEncoded, err := header.Encode()

	if err != nil {
		return nil, err
	}

	sigEncoded, err := signingMethod.Sign(string(headerEncoded)+"."+s.ClaimsEncoded, privateKey)

	if err != nil {
		return nil, fmt.Errorf("could not sign: %w", err)
	}

	sig, err := jwt.DecodeSegment(sigEncoded)

	if err != nil {
		return nil, fmt.Errorf("could not decode signature: %w", err)
	}

	parts := []string{string(headerEncoded), s.ClaimsEncoded, sigEncoded}

	newToken := &StringToken{
		HeaderEncoded:    string(headerEncoded),
		HeaderBytes:      headerJson,
		Header:           header,
		ClaimsEncoded:    s.ClaimsEncoded,
		ClaimsBytes:      s.ClaimsBytes,
		SignatureEncoded: sigEncoded,
		SignatureBytes:   sig,
		TokenEncoded:     strings.Join(parts, "."),
		PreviousToken:    s,
	}

	return newToken, nil
}

func (s *StringToken) Kid() string {
	return s.Header.KeyId
}

func (s *StringToken) Previous() Token {
	return s.PreviousToken
}

func (s *StringToken) Kids() []string {
	var kids []string

	var cur Token = s

	for cur != nil {
		kids = append(kids, cur.Kid())
		cur = cur.Previous()
	}

	return kids
}
