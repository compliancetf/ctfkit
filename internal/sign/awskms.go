package sign

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// openTimeout bounds the GetPublicKey call Open makes.
const openTimeout = 30 * time.Second

func init() { schemes["awskms"] = openAWSKMS }

// KMSAPI is the subset of *kms.Client the awskms signer calls.
type KMSAPI interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// AWSKMS signs with an AWS KMS key of spec ECC_NIST_P256 (ECDSA_SHA_256).
type AWSKMS struct {
	api   KMSAPI
	keyID string
	pub   *ecdsa.PublicKey
}

// openAWSKMS opens awskms:KEY_ARN with the default AWS credential chain;
// the region is the key's.
func openAWSKMS(keyARN string) (Signer, error) {
	a, err := arn.Parse(keyARN)
	if err != nil || a.Service != "kms" || a.Region == "" || a.AccountID == "" || !strings.HasPrefix(a.Resource, "key/") || a.Resource == "key/" {
		return nil, fmt.Errorf("--signer \"awskms:%s\" is not a KMS key ARN; use awskms:arn:PARTITION:kms:REGION:ACCOUNT:key/KEY_ID", keyARN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(a.Region))
	if err != nil {
		// Not the SDK text: it can quote a credential_process command.
		return nil, errors.New("cannot load the AWS configuration for --signer; check AWS_PROFILE and the AWS config and credentials files")
	}
	return NewAWSKMS(ctx, kms.NewFromConfig(cfg), keyARN)
}

// NewAWSKMS reads the public key of keyID through api and refuses a key
// that cannot sign ECDSA_SHA_256 on P-256. The kid is sha256 of the SPKI
// DER KMS returns; Verdict refuses it unless the profile lists it.
func NewAWSKMS(ctx context.Context, api KMSAPI, keyID string) (*AWSKMS, error) {
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("kms key %s: GetPublicKey: %w", keyID, err)
	}
	switch {
	case out.KeySpec != types.KeySpecEccNistP256:
		return nil, fmt.Errorf("kms key %s: key spec %s, want %s", keyID, out.KeySpec, types.KeySpecEccNistP256)
	case out.KeyUsage != types.KeyUsageTypeSignVerify:
		return nil, fmt.Errorf("kms key %s: key usage %s, want %s", keyID, out.KeyUsage, types.KeyUsageTypeSignVerify)
	case !slices.Contains(out.SigningAlgorithms, types.SigningAlgorithmSpecEcdsaSha256):
		return nil, fmt.Errorf("kms key %s: does not sign %s", keyID, types.SigningAlgorithmSpecEcdsaSha256)
	}
	parsed, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms key %s: public key SPKI: %w", keyID, err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("kms key %s: public key is not an ECDSA P-256 SPKI", keyID)
	}
	// KeyID re-marshals the key; it must be the SPKI KMS returned, so the kid
	// is sha256 of exactly those bytes.
	if der, err := x509.MarshalPKIXPublicKey(pub); err != nil || !bytes.Equal(der, out.PublicKey) {
		return nil, fmt.Errorf("kms key %s: public key SPKI is not in canonical form", keyID)
	}
	return &AWSKMS{api: api, keyID: keyID, pub: pub}, nil
}

// Public returns the KMS key's public key.
func (k *AWSKMS) Public() *ecdsa.PublicKey { return k.pub }

// Sign signs a SHA-256 digest (MessageType DIGEST) and returns the ASN.1
// DER signature KMS produces for ECDSA_SHA_256, the form verdicts carry.
func (k *AWSKMS) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("kms sign: digest is not 32 bytes")
	}
	out, err := k.api.Sign(ctx, &kms.SignInput{
		KeyId:            &k.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms key %s: Sign: %w", k.keyID, err)
	}
	return out.Signature, nil
}
