package serverkey

type Repository interface {
	LoadServerKeyPair() (publicKey, privateKey []byte, err error)
}
