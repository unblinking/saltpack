// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyVersionValidator(t *testing.T) {
	in := []byte{0x01}
	key := newSigPrivKey(t)
	smg, err := Sign(Version1(), in, key)
	require.NoError(t, err)

	_, _, err = Verify(SingleVersionValidator(Version2()), smg, kr)
	require.NotNil(t, err)
}

func testVerify(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)
	skey, msg, err := Verify(SingleVersionValidator(version), smsg, kr)
	require.NoError(t, err, "input:      %x\nsigned msg: %x", in, smsg)
	assert.True(t, PublicKeyEqual(skey, key.GetPublicKey()),
		"sender key %x, expected %x", skey.ToKID(), key.GetPublicKey().ToKID())
	assert.Equal(t, in, msg)
}

func testVerifyNewMinorVersion(t *testing.T, version Version) {
	in := []byte{0x01}

	newVersion := version
	newVersion.Minor++

	tso := testSignOptions{
		corruptHeader: func(sh *SignatureHeader) {
			sh.Version = newVersion
		},
	}
	key := newSigPrivKey(t)
	smg, err := testTweakSign(version, in, key, tso)
	require.NoError(t, err)

	_, _, err = Verify(SingleVersionValidator(newVersion), smg, kr)
	require.NoError(t, err)
}

func testVerifyConcurrent(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			skey, msg, err := Verify(SingleVersionValidator(version), smsg, kr)
			if !assert.NoError(t, err, "input:      %x\nsigned msg: %x", in, smsg) {
				// Don't fall through, as the tests below will panic.
				return
			}
			assert.True(t, PublicKeyEqual(skey, key.GetPublicKey()),
				"sender key %x, expected %x", skey.ToKID(), key.GetPublicKey().ToKID())
			assert.Equal(t, in, msg)
		}()
	}
	wg.Wait()
}

type emptySigKeyring struct{}

func (k emptySigKeyring) LookupSigningPublicKey(kid []byte) SigningPublicKey { return nil }

func testVerifyEmptyKeyring(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)

	_, _, err = Verify(SingleVersionValidator(version), smsg, emptySigKeyring{})
	require.Equal(t, ErrNoSenderKey{Sender: key.GetPublicKey().ToKID()}, err)
}

func testVerifyDetachedEmptyKeyring(t *testing.T, version Version) {
	key := newSigPrivKey(t)
	msg := randomMsg(t, 128)
	sig, err := SignDetached(version, msg, key)
	require.NoError(t, err)

	_, err = VerifyDetached(SingleVersionValidator(version), msg, sig, emptySigKeyring{})
	require.Equal(t, ErrNoSenderKey{Sender: key.GetPublicKey().ToKID()}, err)
}

func testVerifyErrorAtEOF(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)

	var reader io.Reader = bytes.NewReader(smsg)
	errAtEOF := errors.New("err at EOF")
	reader = errAtEOFReader{reader, errAtEOF}
	_, stream, err := NewVerifyStream(SingleVersionValidator(version), reader, kr)
	require.NoError(t, err)

	msg, err := ioutil.ReadAll(stream)
	requireErrSuffix(t, err, errAtEOF.Error())

	// Since the bytes are still verified, the verified message
	// should still compare equal to the original input.
	assert.Equal(t, in, msg)
}

func TestVerify(t *testing.T) {
	tests := []func(*testing.T, Version){
		testVerify,
		testVerifyNewMinorVersion,
		testVerifyConcurrent,
		testVerifyEmptyKeyring,
		testVerifyDetachedEmptyKeyring,
		testVerifyErrorAtEOF,
	}
	runTestsOverVersions(t, "test", tests)
}

type pubkeyOnlySigKeyring struct{}

func (p pubkeyOnlySigKeyring) LookupSigningPublicKey(kid []byte) SigningPublicKey {
	return newSigPubKey(kid)
}

const hardcodedV1SignedMessage = `
BEGIN KEYBASE SALTPACK SIGNED MESSAGE. kXR7VktZdyH7rvq v5wcIkHbsMGwMrf
bu4PmUTnBUI2QWi Nu9smFqPCiRfB9h PAUmWFHLkTKGMdN tdrKMtkDu0UhJEj 7gM6Tt8OeykFHq9
R4FnzgakB19YwYa CGVfWxxXpK9OaMI S00BurzWOWBXIxe EoTHvgyx1oHUVdX HRNjJCXTvsSJVa8
Qyg3bN37HAfS8ek gZG6JflV06S2Olp gLdhxNZKIo2zF9P sD5pDFXvoVVzeNC D4vZtMiNQrniEYo
qY903nTYqyGQ4yl UULZ6yP14CcSPfg 8r8CXVi5Z2. END KEYBASE SALTPACK SIGNED
MESSAGE.
`

const hardcodedVerifyKey = "f596585d050597c03a87d653c4be89f7327dbd86b921dd05acfc9df33eb7a962"

func TestHardcodedSignedMessageV1(t *testing.T) {
	decodedKey, err := hex.DecodeString(hardcodedVerifyKey)
	require.NoError(t, err)
	keyring := pubkeyOnlySigKeyring{}
	signer, plaintext, _, err := Dearmor62Verify(SingleVersionValidator(Version1()), hardcodedV1SignedMessage, keyring)
	require.NoError(t, err)
	require.Equal(t, "test message!", string(plaintext))
	require.Equal(t, decodedKey, signer.ToKID())
}

func TestBadSignedMessages(t *testing.T) {
	// expect "bad framing" error if trying to verify an encrypted message
	encryptedMessage := `
BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiPgBwdlv6bV9N8 dSkCbjKrku5ZO7I
sQfGHBd7ZxroT7P 1oooGf4WjNkflSq ujGii7s89UFEybr MCxPEHJ7oOvWtnu Hos4mnLWEggEbcO
1799w2eUijCv0AO E4GK7kPKPSFiF5m enAE17GVaRn34Vv wlwxB9LgFzNfg4m D03qjZnVIeBstvT
TGBDN7BnaSiUjW4 Ao0VbJmjuwI2gqt BqTefCIubT0ZvxO zFN8PAoclVLLbWf pPgjOB7eVp3Bbnq
6nhA8Ql55rMNEx8 9XOTpJh4yJBzA5E rpiLelEIo0LfHMA 4WEI2Lk1FXF3txw LPSWpzStekiIImR
tY2Uhf7hcRZFs1P yRr4WYFoWpjotGA 2k6S0L8QHGPbsGl jJKz5m1at0o8XxA MrWrtBnOmkK1kgS
TNm9UX5DiaVxyJ8 4JKgJVTt8JxMacq 37vn4jogmZJr45r gNSrakw8sFv8CaD xMNXqUWkhQ9U8ZI
N1ePua5gTPaECSD ZonBMFRUDpHBFHQ z7hhFmOww4qkUXm xQdpNDg9Ex7YvRT 0CPvP9FsEelrNFH
4xiDSnDAYMguoC6 yC5YmGrYxusmfWC 7CAMYK0lQuuIucF aZCvYRTGRjDj0BA 8vvlXPHcjkyE956
RPY6fYiwVBf2dZg 8lRgd4NjOHdz6v9 6vt3nHGx4ZiUUNT 70xwTjNVIVbH5kV UTI0igySEhyh49z
X5rcwPdcuA2zO4d nyrYEqrAT55ZPsp stRGwbHgQRm36wD c06Z4xYUJv5AtUr R02MT9AqytNeLvu
KvYolx5Wlm95FtR k6EaQ0hfC4oS1nF 6qRgICgl4JaSLBi baciijBMud23IJg aOHE9dR9ZnGJsLm
tgDdKRzle5KLksB sSZiiGKf5uAFr9A Tx9JhFZv3B9GP5v 2s3U289T97Y0hhS UEcuMcyDSbyOLko
dSbguBO4iKLGL6A T1lPhaCzg4n4vZv wW3qEKEflxsRu8O GoS5bg3586PGYP6 UlTCS6uZDZDvZpa
FuHsCazBwbC8RMw mK04rfrmwew. END KEYBASE SALTPACK ENCRYPTED MESSAGE.
`

	_, _, _, err := Dearmor62Verify(SingleVersionValidator(Version1()), encryptedMessage, pubkeyOnlySigKeyring{})
	require.Error(t, err)
	require.IsType(t, ErrBadFrame{}, err)
}

const hardcodedV1DetachedSignature = `
BEGIN KEYBASE SALTPACK DETACHED SIGNATURE. kXR7VktZdyH7rvq v5wcIkPOwOUCix9
HfoZZdGgIjzeYWi Nu9smFqPCiRfB9h PAUmWFHLkUaLXQd DTZrK37uaKi9dgf 60zJCgqbheQLTVP
Vr2Dw2x1MLOenwI dt3P0dRsyh2WvQW OeqH28kbuzPiA0f OPQ0Y26dpV8A8uE DUDdJed0edSYEbx
v. END KEYBASE SALTPACK DETACHED SIGNATURE.
`

func TestHardcodedDetachedSignatureV1(t *testing.T) {
	decodedKey, err := hex.DecodeString(hardcodedVerifyKey)
	require.NoError(t, err)
	keyring := pubkeyOnlySigKeyring{}
	signer, _, err := Dearmor62VerifyDetached(SingleVersionValidator(Version1()), []byte("test message!"), hardcodedV1DetachedSignature, keyring)
	require.NoError(t, err)
	require.Equal(t, decodedKey, signer.ToKID())
}
