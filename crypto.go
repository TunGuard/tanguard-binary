package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/curve25519"
)

func HexToBase64(hexStr string) string {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return hexStr
	}
	return base64.StdEncoding.EncodeToString(b)
}

func cryptoRandRead(buf []byte) (int, error) {
	return rand.Read(buf)
}

func curve25519ScalarMult(scalar []byte) []byte {
	basePoint := make([]byte, 32)
	basePoint[0] = 9
	out, err := curve25519.X25519(scalar, basePoint)
	if err != nil {
		panic("curve25519: " + err.Error())
	}
	return out
}

func ValidateHexKey(hexKey string) (string, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(b))
	}
	return hexKey, nil
}

func PrivToPub(privHex string) (string, error) {
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes")
	}
	pub := curve25519ScalarMult(privBytes)
	return hex.EncodeToString(pub), nil
}

func GenerateKeyPair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	n, err := cryptoRandRead(priv)
	if err != nil {
		return nil, nil, err
	}
	if n != 32 {
		return nil, nil, fmt.Errorf("short random read: %d", n)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub = curve25519ScalarMult(priv)
	return priv, pub, nil
}
