// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

type testConstResolver struct {
	hardcodedReceivers []ReceiverSymmetricKey
}

var _ SymmetricKeyResolver = (*testConstResolver)(nil)

func (r *testConstResolver) ResolveKeys(identifiers [][]byte) ([]*SymmetricKey, error) {
	ret := []*SymmetricKey{}
	for _, ident := range identifiers {
		var key *SymmetricKey
		for _, receiver := range r.hardcodedReceivers {
			if bytes.Equal(receiver.Identifier, ident) {
				key = &receiver.Key
				break
			}
		}
		ret = append(ret, key)
	}
	return ret, nil
}

func makeEmptyKeyring(t *testing.T) *keyring {
	keyring := newKeyring()
	keyring.iterable = true
	return keyring
}

func makeKeyringWithOneKey(t *testing.T) (*keyring, []BoxPublicKey) {
	keyring := makeEmptyKeyring(t)
	keyring.iterable = true
	receiverBoxSecretKey, err := keyring.CreateEphemeralKey()
	require.NoError(t, err)
	keyring.insert(receiverBoxSecretKey)
	receiverBoxKeys := []BoxPublicKey{receiverBoxSecretKey.GetPublicKey()}
	return keyring, receiverBoxKeys
}

func makeSigningKey(t *testing.T, keyring *keyring) *sigPrivKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := &sigPrivKey{
		public:  newSigPubKey(pub),
		private: priv,
	}
	keyring.insertSigningKey(k)
	return k
}

func makeResolverWithOneKey(t *testing.T) (SymmetricKeyResolver, []ReceiverSymmetricKey) {
	var sharedSymmetricKey SymmetricKey // zeros
	receiver := ReceiverSymmetricKey{
		Key:        sharedSymmetricKey,
		Identifier: []byte("dummy identifier"),
	}
	receivers := []ReceiverSymmetricKey{receiver}
	resolver := &testConstResolver{hardcodedReceivers: receivers}
	return resolver, receivers
}

func TestSigncryptionBoxKeyHelloWorld(t *testing.T) {
	msg := []byte("hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)

	senderSigningPrivKey := makeSigningKey(t, keyring)

	sealed, err := SigncryptSeal(msg, keyring, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	senderPub, opened, err := SigncryptOpen(sealed, keyring, nil)
	require.NoError(t, err)

	require.Equal(t, senderPub, senderSigningPrivKey.GetPublicKey())

	require.Equal(t, opened, msg)
}

func TestSigncryptionResolvedKeyHelloWorld(t *testing.T) {
	msg := []byte("hello world")
	keyring := makeEmptyKeyring(t)

	resolver, receivers := makeResolverWithOneKey(t)

	senderSigningPrivKey := makeSigningKey(t, keyring)

	sealed, err := SigncryptSeal(msg, keyring, senderSigningPrivKey, nil, receivers)
	require.NoError(t, err)

	senderPub, opened, err := SigncryptOpen(sealed, keyring, resolver)
	require.NoError(t, err)

	require.Equal(t, senderPub, senderSigningPrivKey.GetPublicKey())

	require.Equal(t, opened, msg)
}

func TestSigncryptionEmptyCiphertext(t *testing.T) {
	keyring, _ := makeKeyringWithOneKey(t)

	emptyMessage := []byte("")
	_, _, err := SigncryptOpen(emptyMessage, keyring, nil)
	require.Equal(t, err, ErrFailedToReadHeaderBytes)
}

// This test checks that we throw io.ErrUnexpectedEOF if we reach the end of
// the stream without having seen a proper termination packet.
func TestSigncryptionTruncatedAtPacketBoundary(t *testing.T) {
	msg := []byte("hello world")
	keyring, receiverBoxKeys := makeKeyringWithOneKey(t)

	senderSigningPrivKey := makeSigningKey(t, keyring)

	sealed, err := SigncryptSeal(msg, keyring, senderSigningPrivKey, receiverBoxKeys, nil)
	require.NoError(t, err)

	// Figure out how many bytes are in the header packet:
	// Assert the MessagePack bin8 type.
	require.Equal(t, byte(0xc4), sealed[0])
	// Grab the bin length.
	bin8Len := sealed[1]
	// Account for the leading two bytes.
	headerLen := bin8Len + 2
	// Truncate the message.
	truncated := sealed[0:headerLen]

	_, _, err = SigncryptOpen(truncated, keyring, nil)
	require.Equal(t, err, io.ErrUnexpectedEOF)
}
