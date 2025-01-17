package main

import(
	"crypto"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

//	"encoding/pem"

//	"os"
)

func main(){
	rng := rand.Reader
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)	
/*	
	derStream := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{
		Type : "RSA PRIVATE KEY",
		Bytes : derStream,
	}
	file, _:= os.Create("private.pem")
	
	_ = pem.Encode(file, block)
	
*/	
	derStream,_:= x509.MarshalPKIXPublicKey(&priv.PublicKey)
	peyhash := sha256.Sum256(derStream)
	
	fmt.Printf("Publickey hash [%X]\n",string(peyhash[:]))
	
	msg := []byte("lyw write")
	hash := sha256.Sum256(msg)

	signature, _ := rsa.SignPKCS1v15(rng, priv, crypto.SHA256, hash[:])
	
			
	err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hash[:], signature)
	if err != nil{
		fmt.Println(err)
		return
	}

	fmt.Println("OK")
	fmt.Println(signature)
	pp:= hex.EncodeToString(signature)
	fmt.Println(pp)
	
}	
