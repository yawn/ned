package network

const (
	EnclaveCID         = 20
	Port               = 8080
	RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"
)

type Document struct {
	CABundle    [][]byte          `json:"ca_bundle" cbor:"ca_bundle"`
	Certificate []byte            `json:"certificate" cbor:"certificate"`
	Digest      string            `json:"digest" cbor:"digest"`
	ModuleID    string            `json:"module_id" cbor:"module_id"`
	Nonce       []byte            `json:"nonce" cbor:"nonce"`
	PCRs        map[uint64][]byte `json:"pcrs" cbor:"pcrs"`
	PublicKey   []byte            `json:"public_key" cbor:"public_key"`
	Timestamp   uint64            `json:"timestamp" cbor:"timestamp"`
	UserData    []byte            `json:"user_data" cbor:"user_data"`
}

type RecipientInfo struct {
	AttestationDocument    []byte `json:"attestation_document"`
	KeyEncryptionAlgorithm string `json:"key_encryption_algorithm"`
}

type Request struct {
	Nonce     []byte `json:"nonce,omitempty"`
	PublicKey []byte `json:"public_key,omitempty"`
	UserData  []byte `json:"user_data,omitempty"`
}

type Response struct {
	Document      *Document      `json:"document"`
	RecipientInfo *RecipientInfo `json:"recipient_info"`
}
