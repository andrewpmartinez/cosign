package cosign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
	"math/big"
	"strings"
	"testing"
)

func TestStringToken_AssemblePreviousToken(t *testing.T) {
	req := require.New(t)

	signer, err := newTestSigner()

	req.NoError(err)
	req.NotNil(signer)

	t.Run("returns nil, nil if no cosigner header", func(t *testing.T) {
		req := require.New(t)

		token := &StringToken{
			Header: &Header{
				KeyId:           "123",
				Algorithm:       jwt.SigningMethodHS256.Alg(),
				CoSignerVersion: "",
				PreviousSigner: &Signer{
					HeaderEncoded:    "1234",
					SignatureEncoded: "5678",
				},
			},
		}

		nextToken, err := token.AssemblePreviousToken()

		req.Nil(err)
		req.Nil(nextToken)
	})

	t.Run("returns nil, nil if no next signer", func(t *testing.T) {
		req := require.New(t)

		token := &StringToken{
			Header: &Header{
				KeyId:           "123",
				Algorithm:       jwt.SigningMethodHS256.Alg(),
				CoSignerVersion: CoSignerV1,
				PreviousSigner:  nil,
			},
		}

		nextToken, err := token.AssemblePreviousToken()

		req.Nil(err)
		req.Nil(nextToken)
	})

	t.Run("returns the next token", func(t *testing.T) {
		req := require.New(t)

		claims := map[string]interface{}{
			"claim1": "val1",
		}

		header := map[string]interface{}{}

		newToken, err := signer.SignToken(header, claims)
		req.NoError(err)
		req.NotNil(newToken)

		parts := strings.Split(newToken, ".")
		req.Len(parts, 3)

		token := &StringToken{
			Header: &Header{
				KeyId:           "123",
				Algorithm:       jwt.SigningMethodHS256.Alg(),
				CoSignerVersion: CoSignerV1,
				PreviousSigner: &Signer{
					HeaderEncoded:    parts[0],
					SignatureEncoded: parts[2],
				},
			},
			ClaimsEncoded: parts[1],
		}

		nextToken, err := token.AssemblePreviousToken()

		req.NoError(err)
		req.NotNil(nextToken)
		req.Equal(parts[0]+"."+parts[1]+"."+parts[2], nextToken.Token())
	})
}

func TestStringToken_Verify(t *testing.T) {
	req := require.New(t)

	signer, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer)

	t.Run("verifies with proper public key", func(t *testing.T) {
		req := require.New(t)

		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		tokenStr, err := signer.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(tokenStr)

		token, err := Parse(tokenStr)
		req.NoError(err)
		req.NotNil(token)

		result := token.Verify(signer)
		req.NotNil(result)
		req.NotNil(result.Token)
		req.Equal(token, result.Token)
		req.True(result.IsValid)
		req.NoError(result.Error)
	})

	t.Run("does not verify with unmatched kid", func(t *testing.T) {
		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		otherSigner, err := newTestSigner()
		req.NoError(err)
		req.NotNil(otherSigner)

		tokenStr, err := signer.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(tokenStr)

		token, err := Parse(tokenStr)
		req.NoError(err)
		req.NotNil(token)

		result := token.Verify(otherSigner)
		req.NotNil(result)
		req.NotNil(result.Token)
		req.Equal(token, result.Token)
		req.False(result.IsValid)
		req.Error(result.Error)
	})

	t.Run("does not verify with invalid public key", func(t *testing.T) {
		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		otherSigner, err := newTestSigner()
		req.NoError(err)
		req.NotNil(otherSigner)

		tokenStr, err := signer.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(tokenStr)

		token, err := Parse(tokenStr)
		req.NoError(err)
		req.NotNil(token)

		result := token.Verify(MapKeyProvider{
			signer.KeyId: otherSigner.PublicKey,
		})
		req.NotNil(result)
		req.NotNil(result.Token)
		req.Equal(token, result.Token)
		req.False(result.IsValid)
		req.Error(result.Error)
	})
}

func TestStringToken_VerifyOne(t *testing.T) {
	req := require.New(t)

	signer1, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer1)

	signer2, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer2)

	signer3, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer3)

	otherSigner, err := newTestSigner()
	req.NoError(err)
	req.NotNil(otherSigner)

	t.Run("three signers added one after the other", func(t *testing.T) {

		req := require.New(t)

		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		jwtStr1, err := signer1.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(jwtStr1)

		token1, err := Parse(jwtStr1)
		req.NoError(err)
		req.NotNil(token1)

		token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
		req.NoError(err)
		req.NotNil(token2)

		token3, err := token2.AddSigner(signer3.KeyId, signer3.PrivateKey, signer3.SigningMethod)
		req.NoError(err)
		req.NotNil(token3)

		t.Run("can verify one with 1st signer", func(t *testing.T) {
			req := require.New(t)

			result := token3.VerifyOne(signer1)
			req.NotNil(result)
			req.NoError(result.Error)
			req.True(result.IsValid)
			req.Equal(token1, result.Token)
		})

		t.Run("can verify one with 2nd signer", func(t *testing.T) {
			req := require.New(t)

			result := token3.VerifyOne(signer2)
			req.NotNil(result)
			req.NoError(result.Error)
			req.True(result.IsValid)
			req.Equal(token2, result.Token)
		})

		t.Run("can verify one with 3rd signer", func(t *testing.T) {
			req := require.New(t)

			result := token3.VerifyOne(signer3)
			req.NotNil(result)
			req.NoError(result.Error)
			req.True(result.IsValid)
			req.Equal(token3, result.Token)
		})
	})

	t.Run("three signers parsed from the last", func(t *testing.T) {

		req := require.New(t)

		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		jwtStr1, err := signer1.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(jwtStr1)

		token1, err := Parse(jwtStr1)
		req.NoError(err)
		req.NotNil(token1)

		token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
		req.NoError(err)
		req.NotNil(token2)

		token3, err := token2.AddSigner(signer3.KeyId, signer3.PrivateKey, signer3.SigningMethod)
		req.NoError(err)
		req.NotNil(token3)

		token, err := Parse(token3.Token())
		req.NoError(err)
		req.NotNil(token)

		t.Run("can verify one with 1st signer", func(t *testing.T) {
			req := require.New(t)

			result := token.VerifyOne(signer1)
			req.NotNil(result)
			req.NoError(result.Error)
			req.True(result.IsValid)
			req.Equal(token1, result.Token)
		})

		t.Run("can verify one with 2nd signer", func(t *testing.T) {
			req := require.New(t)

			result := token.VerifyOne(signer2)
			req.NotNil(result)
			req.NoError(result.Error)
			req.True(result.IsValid)
			req.Equal(token2, result.Token)
		})

		t.Run("can verify one with 3rd signer", func(t *testing.T) {
			req := require.New(t)

			result := token.VerifyOne(signer3)
			req.NotNil(result)
			req.NoError(result.Error)
			req.True(result.IsValid)
			req.Equal(token3, result.Token)
		})
	})
}

func TestStringToken_VerifyAll(t *testing.T) {
	req := require.New(t)

	signer1, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer1)

	signer2, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer2)

	signer3, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer3)

	otherSigner, err := newTestSigner()
	req.NoError(err)
	req.NotNil(otherSigner)

	t.Run("three signers added one after the other", func(t *testing.T) {
		req := require.New(t)

		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		jwtStr1, err := signer1.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(jwtStr1)

		token1, err := Parse(jwtStr1)
		req.NoError(err)
		req.NotNil(token1)

		token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
		req.NoError(err)
		req.NotNil(token2)

		token3, err := token2.AddSigner(signer3.KeyId, signer3.PrivateKey, signer3.SigningMethod)
		req.NoError(err)
		req.NotNil(token3)

		t.Run("can verify with all signers", func(t *testing.T) {
			req := require.New(t)

			allSigners := MapKeyProvider{
				signer1.KeyId: signer1.PublicKey,
				signer2.KeyId: signer2.PublicKey,
				signer3.KeyId: signer3.PublicKey,
			}

			valid, results := token3.VerifyAll(allSigners)
			req.True(valid)
			req.Len(results, 3)

			req.NotNil(results[0])
			req.True(results[0].IsValid)
			req.NoError(results[0].Error)

			req.NotNil(results[1])
			req.True(results[1].IsValid)
			req.NoError(results[1].Error)

			req.NotNil(results[2])
			req.True(results[2].IsValid)
			req.NoError(results[2].Error)
		})

		t.Run("does not verify with zero signers", func(t *testing.T) {
			req := require.New(t)

			allSigners := MapKeyProvider{}

			valid, results := token3.VerifyAll(allSigners)
			req.False(valid)
			req.Len(results, 3)

			req.NotNil(results[0])
			req.False(results[0].IsValid)
			req.Error(results[0].Error)

			req.NotNil(results[1])
			req.False(results[1].IsValid)
			req.Error(results[1].Error)

			req.NotNil(results[2])
			req.False(results[2].IsValid)
			req.Error(results[2].Error)
		})

		t.Run("does not verify with one missing signer", func(t *testing.T) {
			req := require.New(t)

			signers := MapKeyProvider{
				signer1.KeyId: signer1.PublicKey,
				signer3.KeyId: signer3.PublicKey,
			}

			valid, results := token3.VerifyAll(signers)
			req.False(valid)
			req.Len(results, 3)

			req.NotNil(results[0])
			req.True(results[0].IsValid)
			req.NoError(results[0].Error)

			req.NotNil(results[1])
			req.False(results[1].IsValid)
			req.Error(results[1].Error)

			req.NotNil(results[2])
			req.True(results[2].IsValid)
			req.NoError(results[2].Error)
		})
	})

	t.Run("three signers parsed from the last", func(t *testing.T) {
		req := require.New(t)

		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		jwtStr1, err := signer1.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(jwtStr1)

		token1, err := Parse(jwtStr1)
		req.NoError(err)
		req.NotNil(token1)

		token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
		req.NoError(err)
		req.NotNil(token2)

		token3, err := token2.AddSigner(signer3.KeyId, signer3.PrivateKey, signer3.SigningMethod)
		req.NoError(err)
		req.NotNil(token3)

		token, err := Parse(token3.Token())
		req.NoError(err)
		req.NotNil(token)

		t.Run("can verify with all signers", func(t *testing.T) {
			req := require.New(t)

			allSigners := MapKeyProvider{
				signer1.KeyId: signer1.PublicKey,
				signer2.KeyId: signer2.PublicKey,
				signer3.KeyId: signer3.PublicKey,
			}

			valid, results := token3.VerifyAll(allSigners)
			req.True(valid)
			req.Len(results, 3)

			req.NotNil(results[0])
			req.True(results[0].IsValid)
			req.NoError(results[0].Error)

			req.NotNil(results[1])
			req.True(results[1].IsValid)
			req.NoError(results[1].Error)

			req.NotNil(results[2])
			req.True(results[2].IsValid)
			req.NoError(results[2].Error)
		})

		t.Run("does not verify with zero signers", func(t *testing.T) {
			req := require.New(t)

			allSigners := MapKeyProvider{}

			valid, results := token3.VerifyAll(allSigners)
			req.False(valid)
			req.Len(results, 3)

			req.NotNil(results[0])
			req.False(results[0].IsValid)
			req.Error(results[0].Error)

			req.NotNil(results[1])
			req.False(results[1].IsValid)
			req.Error(results[1].Error)

			req.NotNil(results[2])
			req.False(results[2].IsValid)
			req.Error(results[2].Error)
		})

		t.Run("does not verify with one missing signer", func(t *testing.T) {
			req := require.New(t)

			signers := MapKeyProvider{
				signer1.KeyId: signer1.PublicKey,
				signer3.KeyId: signer3.PublicKey,
			}

			valid, results := token3.VerifyAll(signers)
			req.False(valid)
			req.Len(results, 3)

			req.NotNil(results[0])
			req.True(results[0].IsValid)
			req.NoError(results[0].Error)

			req.NotNil(results[1])
			req.False(results[1].IsValid)
			req.Error(results[1].Error)

			req.NotNil(results[2])
			req.True(results[2].IsValid)
			req.NoError(results[2].Error)
		})
	})
}

func TestStringToken_Token(t *testing.T) {
	req := require.New(t)

	signer1, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer1)

	claims := map[string]any{
		"claim10": "val10",
	}

	headers := map[string]any{}

	jwtStr1, err := signer1.SignToken(headers, claims)
	req.NoError(err)
	req.NotEmpty(jwtStr1)

	token, err := Parse(jwtStr1)
	req.NoError(err)
	req.NotNil(token)

	t.Run("returns a token", func(t *testing.T) {
		req := require.New(t)

		tokenString := token.Token()

		req.NotEmpty(tokenString)
		req.Equal(jwtStr1, tokenString)
	})
}

func TestStringToken_Tokens(t *testing.T) {
	req := require.New(t)

	signer1, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer1)

	signer2, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer2)

	signer3, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer3)

	claims := map[string]any{
		"claim10": "val10",
	}

	headers := map[string]any{}

	jwtStr1, err := signer1.SignToken(headers, claims)
	req.NoError(err)
	req.NotEmpty(jwtStr1)

	token1, err := Parse(jwtStr1)
	req.NoError(err)
	req.NotNil(token1)

	token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
	req.NoError(err)
	req.NotNil(token2)

	token3, err := token2.AddSigner(signer3.KeyId, signer3.PrivateKey, signer3.SigningMethod)
	req.NoError(err)
	req.NotNil(token3)

	t.Run("last token returns three tokens", func(t *testing.T) {
		req := require.New(t)

		token, err := Parse(token3.Token())
		req.NoError(err)
		req.NotNil(token)

		tokenStrings, tokens := token.Tokens()

		req.Len(tokens, 3)
		req.Len(tokenStrings, 3)

		t.Run("string tokens and struct tokens match", func(t *testing.T) {
			req := require.New(t)
			req.Equal(tokens[0].Token(), tokenStrings[0])
			req.Equal(tokens[1].Token(), tokenStrings[1])
			req.Equal(tokens[2].Token(), tokenStrings[2])
		})
	})

	t.Run("first token returns 1 token", func(t *testing.T) {
		req := require.New(t)

		token, err := Parse(token1.Token())
		req.NoError(err)
		req.NotNil(token)

		tokenStrings, tokens := token.Tokens()

		req.Len(tokens, 1)
		req.Len(tokenStrings, 1)

		t.Run("string tokens and struct tokens match", func(t *testing.T) {
			req := require.New(t)
			req.Equal(tokens[0].Token(), tokenStrings[0])
		})
	})
}

func TestStringToken_AddSigner(t *testing.T) {
	req := require.New(t)

	signer1, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer1)

	signer2, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer2)

	signer3, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer3)

	claims := map[string]any{
		"claim10": "val10",
	}

	headers := map[string]any{}

	jwtStr1, err := signer1.SignToken(headers, claims)
	req.NoError(err)
	req.NotEmpty(jwtStr1)

	token1, err := Parse(jwtStr1)
	req.NoError(err)
	req.NotNil(token1)

	t.Run("can add a signer", func(t *testing.T) {
		token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
		req.NoError(err)
		req.NotNil(token2)
		req.Equal(token1, token2.Previous())
	})
}

func TestStringToken_Kids(t *testing.T) {
	req := require.New(t)

	signer1, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer1)

	signer2, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer2)

	signer3, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer3)

	claims := map[string]any{
		"claim10": "val10",
	}

	headers := map[string]any{}

	jwtStr1, err := signer1.SignToken(headers, claims)
	req.NoError(err)
	req.NotEmpty(jwtStr1)

	token1, err := Parse(jwtStr1)
	req.NoError(err)
	req.NotNil(token1)

	token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
	req.NoError(err)
	req.NotNil(token2)

	t.Run("first token returns proper kid", func(t *testing.T) {
		req := require.New(t)
		req.Equal(signer1.KeyId, token1.Kid())
	})

	t.Run("second token returns proper kid", func(t *testing.T) {
		req := require.New(t)
		req.Equal(signer2.KeyId, token2.Kid())
	})

	t.Run("second token returns all kids", func(t *testing.T) {
		req := require.New(t)

		kids := token2.Kids()

		req.Len(kids, 2)
		req.Equal(signer2.KeyId, kids[0])
		req.Equal(signer1.KeyId, kids[1])
	})

	t.Run("first token returns their kid", func(t *testing.T) {
		req := require.New(t)

		kids := token1.Kids()

		req.Len(kids, 1)
		req.Equal(signer1.KeyId, kids[0])
	})
}

func TestStringToken_Claims(t *testing.T) {
	req := require.New(t)

	signer1, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer1)

	signer2, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer2)

	signer3, err := newTestSigner()
	req.NoError(err)
	req.NotNil(signer3)

	otherSigner, err := newTestSigner()
	req.NoError(err)
	req.NotNil(otherSigner)

	t.Run("three signers added one after the other", func(t *testing.T) {
		req := require.New(t)

		claims := map[string]any{
			"claim10": "val10",
		}

		headers := map[string]any{}

		jwtStr1, err := signer1.SignToken(headers, claims)
		req.NoError(err)
		req.NotEmpty(jwtStr1)

		token1, err := Parse(jwtStr1)
		req.NoError(err)
		req.NotNil(token1)

		token2, err := token1.AddSigner(signer2.KeyId, signer2.PrivateKey, signer2.SigningMethod)
		req.NoError(err)
		req.NotNil(token2)

		token3, err := token2.AddSigner(signer3.KeyId, signer3.PrivateKey, signer3.SigningMethod)
		req.NoError(err)
		req.NotNil(token3)

		t.Run("all have the same claims", func(t *testing.T) {
			req := require.New(t)

			tokenClaims := token3.Claims()
			req.Equal(tokenClaims, token2.Claims())
			req.Equal(tokenClaims, token1.Claims())
		})
	})
}

type testSigner struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    crypto.PrivateKey
	PublicKey     crypto.PublicKey
	KeyId         string
}

func (signer *testSigner) GetPublicKey(kid string) (crypto.PublicKey, error) {
	if kid == signer.KeyId {
		return signer.PublicKey, nil
	}

	return nil, fmt.Errorf("no public key for key id: %s", kid)
}

func newTestSigner() (*testSigner, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, err
	}

	signer := &testSigner{
		SigningMethod: jwt.SigningMethodES256,
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		KeyId:         randomString(10),
	}

	return signer, nil
}

func (signer *testSigner) SignToken(header map[string]any, claims map[string]any) (string, error) {
	header["kid"] = signer.KeyId
	header["alg"] = signer.SigningMethod.Alg()

	token := jwt.New(signer.SigningMethod)
	token.Claims = jwt.MapClaims(claims)
	token.Header = header

	return token.SignedString(signer.PrivateKey)
}

const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randomString(size int) string {
	var sb strings.Builder
	alphabetLength := big.NewInt(int64(len(alphabet)))
	for i := 0; i < size; i++ {
		num, _ := rand.Int(rand.Reader, alphabetLength)
		sb.WriteByte(alphabet[num.Int64()])
	}
	return sb.String()
}
