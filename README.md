# COSIGN
![cosign-25.png](images/cosign-25.png)

A go-lang library that allows multiple signers of a single JWT. Done in a way
that maintains backward compatibility with standard single signer verification.

## Usage

Take any existing JWT, parse it, and add one or more additional signers.

```go
jwtString := "ey...===="
token, err := cosign.parse(jwtString
doubleSignedToken, err := token.AddSigner("kid1234", secondSignerPrivateKey, jwt.SigningMethodES256)
doubleSignedTokenString := doubleSignedToken.Token()
fmt.Printf("The cosigned token: %s", doubleSignedTokenString)
```

The "signing method" must match the private key usage (RS256 for SHA245 + RSA, ES256 for SHA256+P256, etc.).

Verification can be performed in a variety of ways. The last signer can always be verified using standard JWT 
verification. The cosigners can be verified by first parsing the JWT with `cosign.Parse(token)` and then using
one of the verify functions:

- `Verify(pubKeyProvider)` - Verify the current token is signed by a known public key.
- `VerifyOne(pubKeyProvider)` - Verify that the token was signed by at least one known public key.
- `VerifyAll(pubKeyProvider)` - Verify that the toke was signed by only known public keys.

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

Each single cosigned token is logically multiple individual tokens signed with different private keys. Cosign "unpacks" these JWTs during parsing.
The logical tokens can be accessed via: `token.Previous()` or `token.Tokens()`. 

When using `token.VerifyOne()` or `token.VerifyAll()` the referenced token and all previous tokens are verified, but any tokens higher up, are not.
For example, if an arbitrary token named `myToken` was signed three times, using `cosign.Parse(myToken)` will return a single `Token` instance that
has references to two other token instances. 

```
topToken, _ := cosign.Parse(myToken)
middleToken := topToken.Previous()
bottomToken := middleToken.Previous()
thisWillBeNil := bottomToken.Previous()
```
If `middleToken.VerifyOne()` is run, it will verify against `middleToken` and `bottomToken`; as verification is down down through the token, not up.


# Why?

I worked on a project where I needed to be able to have older clients verify a JWT from a single signer, but
newer clients could verify from any number of signers. Issuing multiple JWTs was too much to handle, and
nesting JWTs inside each other caused the JWT size to grow too large for my use case. For the initial
application, the claims were identical, no matter how many signers there were. Cosign requires that the claim
set not change between signers. Said another way, all cosigners sign the same claims.
