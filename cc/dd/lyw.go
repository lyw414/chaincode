package main

import(
	"crypto"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
//	"math/big"
	"encoding/json"
	"fmt"

	"encoding/pem"

)

type userDate struct{
	TatalNum int 
	Rsapk rsa.PublicKey
	Type1 int
	Transe []string
}

func GenerateCLT() ([]byte,[]byte){
	priv,_:= rsa.GenerateMultiPrimeKey(rand.Reader,3,1024)
	derStream := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{
		Type : "RSA PRIVATE KEY",
		Bytes : derStream,
	}

	vk := pem.EncodeToMemory(block)

	derStream,_ = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	block = &pem.Block{
		Type : "RSA PUBLIC KEY",
		Bytes : derStream,
	}
	pk := pem.EncodeToMemory(block)

	return vk,pk	
//	return string(vk[:]),string(pk[:])
}

func GetRsaKeyFromPem(vk []byte) (*rsa.PrivateKey){
	
	block, _ := pem.Decode(vk)
	key,_:= x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

func GetRsaPkFromPem(pk []byte) (*rsa.PublicKey){
	block, _ := pem.Decode(pk)
	pub,_ := x509.ParsePKIXPublicKey(block.Bytes)
	key,_:= pub.(*rsa.PublicKey)	
	return key
}


func main(){
	rng := rand.Reader
	
	fmt.Println("============== Begin Trans ==================")
	fmt.Println("============== Generate Pem ==================")
//	vk,pk := GenerateCLT()

	pk := []byte("-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPGLNsWDMgwa+mCRvmcWTnYRuS\nh3yU5XoF9ouGXWh+ivSJUEhF9nbiDcXGo0cy/yY2nG6P7GXM/80PQD4MrskVwyNC\nAfSmpw9olxJBdVWrTc/zHoxUW+5A7IFgcPryySK21eQIDnj4XtNQQy/ozR4JzA7D\nXioKp7BxMqEODNkjewIDAQAB\n-----END RSA PUBLIC KEY-----")
	vk := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIICfQIBAQKBgQCPGLNsWDMgwa+mCRvmcWTnYRuSh3yU5XoF9ouGXWh+ivSJUEhF\n9nbiDcXGo0cy/yY2nG6P7GXM/80PQD4MrskVwyNCAfSmpw9olxJBdVWrTc/zHoxU\nW+5A7IFgcPryySK21eQIDnj4XtNQQy/ozR4JzA7DXioKp7BxMqEODNkjewIDAQAB\nAoGAZ6KUD5uxK8Aa3j0qn7LwSULjHTRS3eN0hG0Sj7WGwF8Sy4ABV+owH3eqA20u\nkWmbWPaX583EuWPT2tJ/C1qAF5pCQI0V2a26kQH1ZSoOWGkjydNPxM4PJ6HwOj06\nRFjie2vLySn3lkcGa3Aji1IW94vp1JWY5br+5eoqTu+5ogECKxrCS8v68uV4H/3D\neAOOtk7hJIVN2tydXgO26Pb5rcntINs2t20PBmb9FvUCKxpTCTBJsZo0mCFKSysd\ngVDqGgqAtav5h6CyXucVys6dI4KjObrUS7av84cCKxLWSjNrEkh1etfSHY8rjK0U\nkvgAaZy6by9gOLl75Fpswp9u8ksks5YWfm0CKxiEhAdca7TzDUncNzx1445oK07i\n59G/u4l4+BkEW/qpsnwm6ErRFZ+WKxsCKxC3c0SkEdMvr0kqFFrAsQ3rZOKX26IQ\nXJTJN9SVUKpMbYMVBqZTkUfnmwowgYowgYcCKzQBLXKWYPReMmoc/i5UPQWJAh/Q\n2GtvUXHDndd81F3i4EAfqhu6aRQV6ZkCKwPtvtg0QhjT8O0RSaaIWJ/NbOqoZWEg\nZL+6bnc0B/sbw6M0gS5dE8kfqqkCKyNB+XwsV31LkuNQ5ad+EgHXjfPxDuo+AhZ1\n5KPWh7Fegu1UTVLhYpfCQMk=\n-----END RSA PRIVATE KEY-----")
	fmt.Println(string(vk[:]),string(pk[:]))
	fmt.Println("============== Translate pem to rsakey ==================")
	ss := GetRsaKeyFromPem(vk)
	fmt.Println(ss)
	dd := GetRsaPkFromPem(pk)
	fmt.Println(dd)
	fmt.Println("============== Rsa Vk sign  ==================")
//	msg := "D44A6A1C7C66BCED3AB3A54C211135D58AC2F2393F1F4CA821286E296AC67AE1lywtest2000"	
//	msg := "合约:慈善募资\n总额:1000.\n生效条件:上传凭证与提款结果\n执行效果:转账给施工账户\n"
	msg := "lywtest钱转了，合同地址在这里 xxxxxx施工队账户xxxxx"
	hash := sha256.Sum256([]byte(msg))
	fmt.Printf("sign Date [%s] sha256 [%X]\n",msg,string(hash[:]))
	signature, _ := rsa.SignPKCS1v15(rng, ss, crypto.SHA256, hash[:])
//	fmt.Printf("Signed result:\n[%X]\n",string(signature[:]))

	fmt.Println(signature)	
	p := fmt.Sprintf("%X",string(signature[:]))
	sss,_:=hex.DecodeString(p)
	fmt.Println(sss)
	
	fmt.Printf("LYW TEST [%s]\n",p)

	fmt.Println("============== Rsa pk Verify =================")
	err := rsa.VerifyPKCS1v15(dd, crypto.SHA256, hash[:], signature)
	if err != nil {
		fmt.Println("Verify Err")
		return
	}
	fmt.Println("Verify OK!")		
	fmt.Println("============== transstruct ====================")
	s := userDate{
		TatalNum : 22,
		Type1 : 11,
		Transe : []string{"dsdada","deeee"},
	}
	s.Rsapk = *dd
/*
	s.tatalNum = 11
	s.type1 = 22
	s.transe = []string{"dsdada","deeee"}
*/
	fmt.Println(s)

	bi,ee:= json.Marshal(s)
	if ee != nil {
		fmt.Println("Err")
	}
	fmt.Println(bi)
	var si userDate
	json.Unmarshal(bi,&si)
	fmt.Println(si)

	dad := []string{"222"}
	dad = append(dad,"1111")
	
	fmt.Println(dad)

	var kk float64
	var jj []string
	jj = []string{"2eqeqe","33333"}
	kk = 2.31
	tmp := fmt.Sprintf("%f64 %s",kk,jj)
	fmt.Println(tmp)
	return
}	
	
