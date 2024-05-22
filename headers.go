package cosign

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
)

const (
	HeaderAttr         = "hdr"
	SignatureAttr      = "sig"
	VersionAttr        = "cos"
	PrevsiouSignerAttr = "pre"
)

type Signer struct {
	HeaderEncoded    string `json:"hdr,omitempty"`
	SignatureEncoded string `json:"sig,omitempty"`
}

type Header struct {
	KeyId           string  `json:"kid,omitempty"`
	Algorithm       string  `json:"alg,omitempty"`
	CoSignerVersion string  `json:"cos,omitempty"`
	PreviousSigner  *Signer `json:"pre,omitempty"`
}

func (h *Header) Encode() ([]byte, []byte, error) {
	headerJson, err := json.Marshal(h)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal header json: %w", err)
	}

	return headerJson, []byte(jwt.EncodeSegment(headerJson)), nil
}
