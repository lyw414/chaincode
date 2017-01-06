package main

import(
	"fmt"
	"errors"
//	"strconv"
	"crypto/x509"
	"encoding/pem"
	"crypto/sha256"
	"crypto/rsa"
	"encoding/json"
	"encoding/hex"
	"crypto"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

func getrsapkfrompem(pkpem string) ( rsa.PublicKey,error) {
	block,_:= pem.Decode([]byte(pkpem))
	pub,_:= x509.ParsePKIXPublicKey(block.Bytes)
	rsapk := pub.(*rsa.PublicKey)
	return *rsapk,nil
}

func getsha256hex(msg string) (string,error){
	if msg == ""{
		return "",errors.New("In getsha256 :: msg is null")
	}
	hash := sha256.Sum256([]byte(msg))
	return fmt.Sprintf("%X",string(hash[:])),nil
}

func verifysignsha256(singdata string,sign string,rsapk rsa.PublicKey) (error){
	hash := sha256.Sum256([]byte(singdata))
	bytesign,_:= hex.DecodeString(sign)
	return rsa.VerifyPKCS1v15(&rsapk, crypto.SHA256, hash[:],bytesign)
}

func structtobyte(data interface{})([]byte,error){
	b,err:= json.Marshal(data)
	if err != nil{
		return nil,errors.New("In structtobyte :: Get bytes Err!")
	}
	return b,nil
}
//表示需要判断的条件类别 如参与需合约能够支持（金额是否满）,执行条件（xx是否签名）,可扩展为结构
func analysiscontract(contracttx string,itype int) (string){
	feild := strings.Split(contracttx,"\n")
	if itype == 0 {
		//参与捐款 返回 募集金额
		feild1 := strings.Split(feild[1],":") 
		return feild1[1] 
	}
	if itype == 1 {
		//返回条件
		return ""
	}
	return ""
}

func createcontract(stub shim.ChaincodeStubInterface,args []string) (string,error){
	if len(args) != 3 {
		return "",errors.New("In createcontract :: Incorrect number of arguments. Expecting 3!")
	}
	var contract cebaccount
	//获取合约发起人 合约内容 合约签名
	contracttx := args[0]
	pubpem := args[1] 
	contractsign := args[2]


	//获取合约键值 公钥证书hash
	contract_name,err := getsha256hex(pubpem) 
	if err != nil{
		return "",errors.New("In createcontract :: Get pubpem sha256 Err!")
	}
	
	contract_name = "lywtest"	
	//查询合约键值是否已存在
	valuebytes,err := stub.GetState(contract_name)
	if err != nil{
		return "",errors.New("In createcontract :: GetState Err! key:" + contract_name)
	}
	if valuebytes != nil {
		return "",errors.New("In createcontract :: Account Exist!")
	}

	//将pem证书转换为 rsa 公约成分 并存储于合约结构中
	contract.Rsapk,err = getrsapkfrompem(pubpem)
	if err != nil {
		return "",errors.New("In createcontract :: getrsapkfrompem Err!")
	}

	//合约账号属性 1 查询使用
	contract.AccountType = 1

	//验证合约签名 确认合约发起人
	err = verifysignsha256(contracttx,contractsign,contract.Rsapk)

	if err != nil{
		return "",errors.New("In createcontract :: Verify sign failed!")
	}
	//合约账户余额为0 添加注资操作
	contract.Sum = 0.
	//将合约内容放入账户结构中 规定 第一个元素为 合约状态 第二个元素为 合约内容 第三个元素为 合约发起人/执行人
	contract.Trance = append(contract.Trance,"effective")
	contract.Trance = append(contract.Trance,contracttx)
	contract.Trance = append(contract.Trance,contract_name)
	contract.Trance = append(contract.Trance,"")

	//将账户结构转换为字节
	contract_byte,err := structtobyte(contract)
	if err != nil{
		return "",errors.New("In createcontract :: structtobyte Err!")
	}
	err = stub.PutState(contract_name,contract_byte)
	if err != nil {
		return "",errors.New("In createcontract :: PutState Err!key:" + contract_name)
	}
	return contract_name,nil
}

func executecontract(stub shim.ChaincodeStubInterface,args []string) (error){
	//执行脚本，验证签名是否正确，这里简单人为是转账操作，并更新合约状态
	if len(args) != 4 {
		return errors.New("In executecontract:: Incorrect number of arguments. Expecting 4")
	}
	var contract cebaccount
	contractname := args[0]
	accountname := args[1]
	executetx := args[2]
	contractsign := args[3]
	//账户是否存在
	contractbytes,err := stub.GetState(contractname)
	if err != nil {
		return errors.New("In executecontract :: GetState Err")
	}

	if contractbytes == nil {
		return errors.New("In executecontract :: contractname not exist")

	}

	//获取合约结构
	err = json.Unmarshal(contractbytes,&contract)
	if err != nil{
		return errors.New("In executecontract :: Unmarshal Err!")
	}
	
	//获取签名数据
	msg := contractname + accountname + executetx
	//验证签名
	err = verifysignsha256(msg,contractsign,contract.Rsapk)	
	if err != nil {
		return errors.New("In executecontract :: verifysignsha256 Err!")
	}

	//执行合约转账 不是真的转账 是改变合约当前内容 此处为延生点方法很多 模板从简
	//1 将合约当前 金额 设置为 0
	contract.Sum = 0.
	//2 将合约状态改为finish
	contract.Trance[0] = "finished"
	//3 将执行结果放入 第四个 域中
	contract.Trance[3] = executetx + "  " + accountname
	
	//将合约更新至账本中
	contract_byte,err := structtobyte(contract)
	if err != nil{
		return errors.New("In createcontract :: structtobyte Err!")
	}
	err = stub.PutState(contractname,contract_byte)
	if err != nil {
		return errors.New("In createcontract :: PutState Err!key:" + contractname)
	}
	return nil
}
