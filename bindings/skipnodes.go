package bindings

import (
	"encoding/json"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/comms/messages"
	"gitlab.com/xx_network/comms/signature"
	"gitlab.com/xx_network/crypto/tls"
	"gitlab.com/xx_network/primitives/id"
	"hash"
	"io/ioutil"
	"net/http"
)

type SkipNodes struct {
	SkipNodes    []*id.ID               `json:"skipNodes"`
	RsaSignature *messages.RSASignature `json:"rsaSignature"`
}

func (s *SkipNodes) GetSig() *messages.RSASignature {
	if s.RsaSignature != nil {
		return s.RsaSignature
	}
	s.RsaSignature = new(messages.RSASignature)
	return s.RsaSignature
}

func (s *SkipNodes) Digest(nonce []byte, h hash.Hash) []byte {
	h.Reset()

	for _, nid := range s.SkipNodes {
		h.Write(nid.Bytes())
	}
	h.Write(nonce)

	// Return the hash
	return h.Sum(nil)
}

func DownloadAndVerifySkipNodes(url, cert string) ([]*id.ID, error) {
	// Build a request for the file
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to retrieve skip nodes from %s", url)
	}
	defer resp.Body.Close()

	skipNodesEncoded, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to read signed "+
			"skip nodes response request")
	}

	var decoded *SkipNodes
	err = json.Unmarshal(skipNodesEncoded, &decoded)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to unmarshal skipnodes")
	}

	// Load the certificate from it's PEM contents
	schedulingCert, err := tls.LoadCertificate(cert)
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to parse scheduling cert (%s)", cert)
	}

	// Extract the public key from the cert
	schedulingPubKey, err := tls.ExtractPublicKey(schedulingCert)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to extract public key from cert")
	}

	err = signature.VerifyRsa(decoded, schedulingPubKey)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to verify signature on skip nodes list")
	}

	return decoded.SkipNodes, nil
}
