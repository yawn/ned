package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/fxamacker/cbor/v2"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/pkg/errors"
	"github.com/veraison/go-cose"
	"github.com/yawn/ned/network"
)

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     EnvelopedData `asn1:"explicit,optional,tag:0"`
}

type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type EnvelopedData struct {
	Version              int
	RecipientInfos       []RecipientInfo `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
}

type RecipientInfo struct {
	Version                int
	RecipientIdentifier    []byte `asn1:"tag:0"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type Host struct {
	cfg    aws.Config
	client *kms.Client
	keyID  string
	res    *network.Response
	sec    *rsa.PrivateKey
}

func (h *Host) InitializeAWSConfig() error {

	cfg, err := config.LoadDefaultConfig(context.Background())

	if err != nil {
		return errors.Wrapf(err, "failed to load AWS default config")
	}

	h.cfg = cfg

	return nil

}

func (h *Host) InitializeConfig() error {

	client := imds.NewFromConfig(h.cfg)

	res, err := client.GetMetadata(context.Background(), &imds.GetMetadataInput{
		Path: "tags/instance/KeyID",
	})

	if err != nil {
		return errors.Wrapf(err, "failed to get instance metadata for tags")
	}

	body, err := io.ReadAll(res.Content)

	if err != nil {
		return errors.Wrapf(err, "failed to read instance metadata for tag KeyID")
	}

	defer res.Content.Close()

	h.keyID = string(body)

	slog.Info("fetched configuration from imds",
		slog.Any("KeyID", h.keyID),
	)

	return nil
}

func (h *Host) GenerateKeyPair() error {

	sec, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return errors.Wrapf(err, "failed to generate privatekey")
	}

	slog.Info("generated RSA keypair - this is dynamic and may or may not be ephemeral / rotated etc")

	h.sec = sec

	return nil

}

func (h *Host) GenerateAttestationDocument() error {

	pub, err := x509.MarshalPKIXPublicKey(&h.sec.PublicKey)

	if err != nil {
		return errors.Wrapf(err, "failed to encode public key to DER")
	}

	slog.Info("converted public key to ASN.1 DER")
	spew.Dump(pub)

	client := network.NewClient()

	res, err := client.Request(&network.Request{
		PublicKey: pub,
	})

	if err != nil {
		return errors.Wrapf(err, "failed to request attestation document")
	}

	h.res = res

	slog.Info("requested and received attestation document from enclave in the form of an untagged COSE message")
	spew.Dump(res.RecipientInfo.AttestationDocument)

	slog.Info("upstream recipients (like KMS) decode and verify this document and inspect the fields to verify the attestation")
	spew.Dump(res.Document)

	return nil

}

func (h *Host) InitializeKMS() error {

	h.client = kms.NewFromConfig(h.cfg)

	return nil

}

func (h *Host) EncryptMessage(message []byte) ([]byte, error) {

	res, err := h.client.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:     &h.keyID,
		Plaintext: message,
	})

	if err != nil {
		return nil, errors.Wrapf(err, "failed to encrypt message")
	}

	slog.Info("encrypted message",
		slog.String("plaintext", string(message)),
	)

	spew.Dump(res.CiphertextBlob)

	return res.CiphertextBlob, nil

}

func (h *Host) DecryptMessage(message []byte) error {

	_, err := h.client.Decrypt(context.Background(), &kms.DecryptInput{
		CiphertextBlob: message,
	})

	if err == nil {
		return errors.New("decryption succeeded - this should not happen")
	}

	slog.Info("decryption without attestation document failed as expected",
		slog.String("error", err.Error()),
	)

	res, err := h.client.Decrypt(context.Background(), &kms.DecryptInput{
		CiphertextBlob: message,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    h.res.RecipientInfo.AttestationDocument,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanism(h.res.RecipientInfo.KeyEncryptionAlgorithm),
		},
	})

	if err != nil {
		return errors.Wrapf(err, "failed to decrypt message")
	}

	slog.Info("decrypted message, leading to an empty plaintext blob and a present ciphertext for recipient",
		slog.Int("plaintext_len", len(res.Plaintext)),
		slog.Int("ciphertext_for_recipient_len", len(res.CiphertextForRecipient)),
	)

	slog.Info("ciphertext for recipient is a BER encoded RCF5652 CMS message - it can be parsed using 'xxd -r -p | openssl cms -inform DER -cmsout -print'",
		slog.String("BER", hex.EncodeToString(res.CiphertextForRecipient)),
	)

	var (
		cms ContentInfo
		der = ber.DecodePacket(res.CiphertextForRecipient).Bytes()
	)

	slog.Info("converted BER to DER to enable parsing through the golang standard library")

	if _, err := asn1.Unmarshal(der, &cms); err != nil {
		return errors.Wrapf(err, "failed to unmarshal ASN.1")
	}

	key, err := rsa.DecryptOAEP(sha256.New(),
		nil,
		h.sec,
		cms.Content.RecipientInfos[0].EncryptedKey,
		nil,
	)

	if err != nil {
		return errors.Wrapf(err, "failed to decrypt encrypted key")
	}

	slog.Info("decrypted encrypted key part of the CMS message using OAEP and our private key",
		slog.Any("key", key),
	)

	var (
		ciphertext []byte
		data       = cms.Content.EncryptedContentInfo.EncryptedContent.Bytes
		nonce      = cms.Content.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.Bytes
	)

	for len(data) > 0 {

		var v asn1.RawValue

		rest, err := asn1.Unmarshal(data, &v)

		if err != nil {
			return errors.Wrapf(err, "failed to collect encrypted content bytes from ASN.1")
		}

		ciphertext = append(ciphertext, v.Bytes...)
		data = rest

	}

	s, err := aes.NewCipher(key)

	if err != nil {
		return errors.Wrapf(err, "failed to create AES cipher")
	}

	var (
		cbc    = cipher.NewCBCDecrypter(s, nonce)
		blocks = int(math.Ceil(float64(len(ciphertext)) / float64(s.BlockSize())))
		last   = blocks - 1
	)

	for i := 0; i < blocks; i++ {

		var (
			from = i * s.BlockSize()
			to   = from + s.BlockSize()
		)

		slog.Info("decrypting aes-cbc block",
			slog.Int("block", i),
			slog.Int("blocks", blocks),
		)

		block := ciphertext[from:to]
		cbc.CryptBlocks(block, block)

		// remove padding
		if i == last {

			pad := int(block[len(block)-1])

			slog.Info("removing pkcs#7 padding",
				slog.Int("pad", pad),
			)

			ciphertext = ciphertext[:len(ciphertext)-pad]

		}

	}

	slog.Info("successfully decrypted message using AES-CBC",
		slog.String("plaintext", string(ciphertext)),
	)

	return nil

}

func _main_host() error {

	host := &Host{}

	if err := host.InitializeAWSConfig(); err != nil {
		return errors.Wrapf(err, "failed to initialize AWS config")
	}

	if err := host.InitializeConfig(); err != nil {
		return errors.Wrapf(err, "failed to initialize config")
	}

	if err := host.GenerateKeyPair(); err != nil {
		return errors.Wrapf(err, "failed to generate key pair")
	}

	if err := host.GenerateAttestationDocument(); err != nil {
		return errors.Wrapf(err, "failed to generate attestation document")
	}

	if err := host.InitializeKMS(); err != nil {
		return errors.Wrapf(err, "failed to initialize KMS client")
	}

	msg, err := host.EncryptMessage([]byte("hello world - goodbye world!"))

	if err != nil {
		return errors.Wrapf(err, "failed to encrypt message")
	}

	if err := host.DecryptMessage(msg); err != nil {
		return errors.Wrapf(err, "failed to decrypt message")
	}

	return nil

}

func _main_enclave() error {

	sess, err := nsm.OpenDefaultSession()

	if err != nil {
		return errors.Wrapf(err, "failed to open NSM session")
	}

	defer sess.Close()

	server := network.NewServer(func(req *network.Request) (*network.Response, error) {

		r, err := sess.Send(&request.Attestation{
			Nonce:     req.Nonce,
			PublicKey: req.PublicKey,
			UserData:  req.UserData,
		})

		if err != nil {
			return nil, errors.Wrapf(err, "failed to send request to NSN")
		}

		var obj cose.UntaggedSign1Message

		if err := cbor.Unmarshal(r.Attestation.Document, &obj); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal cose message")
		}

		var doc network.Document

		if err := cbor.Unmarshal(obj.Payload, &doc); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal cbor payload")
		}

		res := network.Response{
			Document: &doc,
			RecipientInfo: &network.RecipientInfo{
				AttestationDocument:    r.Attestation.Document,
				KeyEncryptionAlgorithm: network.RSAES_OAEP_SHA_256,
			},
		}

		return &res, nil

	})

	if err := server.Serve(); err != nil {
		return errors.Wrapf(err, "failed to serve")
	}

	return nil
}

func main() {

	var entry func() error

	if _, err := os.Stat("/dev/nsm"); os.IsNotExist(err) {
		entry = _main_host
	} else {
		entry = _main_enclave
	}

	if err := entry(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}

}
