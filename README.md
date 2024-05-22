# COSIGN
![cosign-25.png](images/cosign-25.png)

A go-lang library allowing multiple signers of a single JWT. Done in a way
that maintains backwards compatability with standard single signer verification.

## Usage

Take any existing JWT, parse it, and add one or more additional signers.

```go
jwtString := "ey...===="
token, err := cosing.parse(jwtString
doubleSignedToken, err := token.AddSigner("kid1234", secondSignerPrivateKey, jwt.SigningMethodES256)
doubleSignedTokenString := doubleSignedToken.Token()
fmt.Printf("The cosigned token: %s", doubleSignedTokenString)
```

The "signing method" must match the private key usage (RS256 for SHA245 + RSA, ES256 for SHA256+P256, etc.).

Verification can be performed in a variety of ways. The last signer can always be verified using standard JWT 
verification. The cosigners can be verified by first parsing the JWT with `cosign.Parse(token)` and then using
one of the verify functions:

- `Verify(pubKeyProvider)` - Verify the current token is signed by any of the public keys provided by the public key provider.
- `VerifyOne(pubKeyProvider)` - Verify that the current token or cosigned tokens verifies against the public keys provided.
- `VerifyAll(pubKeyProvider)` - Verify that the current token and all cosigned tokens verify against the public keys provided.

```go
token, err := cosign.Parse(doubleSignedTokenString)
pubKeyProvider := cosign.MapPubKeyProvider{
	"kid1234": &secondSignerPrivateKey.PublicKey
}
result := token.VerifyOne(pubKeyProvider)

if result.Error {
	fmt.Printf("Error: %s\n", result.Error)
} else {
	fmt.Printf("Is Valid: %b\n", result.IsValid)
}
```

The top token and cosigned tokens can be accessed via: `token.Previous()` or `token.Tokens()`. When moving
to other cosigned tokens, keep in mind that verification is from "this token signer and the previous". 
Meaning if you have three cosigners, the last signer is the first token. Using `token.Previous()` will move to the 
token signed by the 2nd to last signer. Performing verification via `Verify*()` on that token will only check the 
2nd and 1st tokens.

# Why?

I worked on a project where I needed to be able to have older clients verify a JWT from a single signer, but
newer clients could verify from any number of signers. Issuing multiple JWTs was too much to handle and
nesting JWTs inside of each other caused the JWT size to grow too large for my use case. For the initial
application the claims were identical no matter how many signers there are. Cosign requires that the claim
set not change between signers. Said another way, all cosigners sign the same claims.