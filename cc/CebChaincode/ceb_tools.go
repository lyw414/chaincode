package main

import(
	"fmt"
	"errors"
	"strconv"
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
func transeAtoB(stub shim.ChaincodeStubInterface,args []string) (error){
	//A账户名（公钥hash) 、B账户名（公钥hash）、金额、A对交易数据签名
	if len(args) != 4 {
		return errors.New("Transfer :: Incorrect number of arguments. Expecting 4")
	}
	transfer_accoutname1 := args[0]
	transfer_accoutname2 := args[1]
	transfer_sum,_:= strconv.ParseFloat(args[2],64)
	transfer_sign := args[3]
	//判断A账户是否存在
	transfer_valuebytes1,err := stub.GetState(transfer_accoutname1)
	if err != nil {
		return errors.New("Transfer :: GetState Err! Key: " + transfer_accoutname1)
	}
	if transfer_valuebytes1 == nil {
		return errors.New("Transfer :: user [" + transfer_accoutname1 + "] not exist!")
	}

	//获取A账户结构体
	var transfer_account1 cebaccount
	transfer_err := json.Unmarshal(transfer_valuebytes1,&transfer_account1)
	if transfer_err != nil {
		return errors.New("Transfer :: Unmarshal Err!")
	}

	//获取交易数据
	transfer_msg := transfer_accoutname1 + transfer_accoutname2 + args[2]

	//验证A账户交易（验证A签名）
	err = verifysignsha256(transfer_msg,transfer_sign,transfer_account1.Rsapk)
	if err != nil {
		return errors.New("Transfer :: verifysignsha256 Err!")
	}
	
	//验证A账户余额是否足够支付交易
	if transfer_account1.Sum < transfer_sum {
		return errors.New("Transfer :: Sum Err!")
	}

	//判断B账户是否存在
	transfer_valuebytes2,err := stub.GetState(transfer_accoutname2)
	if err != nil {
		return errors.New("Transfer :: GetState Err! Key: " + transfer_accoutname1)
	}

	if transfer_valuebytes2 == nil {
		return errors.New("Transfer :: user [" + transfer_accoutname2 + "] not exist!")
	}

	//获取B账户结构体
	var transfer_account2 cebaccount
	var amount float64
	transfer_err = json.Unmarshal(transfer_valuebytes2,&transfer_account2)
	if transfer_err != nil {
		return errors.New("Transfer :: Unmarshal Err!")
	}
	
	//进行交易处理
	// B 账户类型判断 A 账户类型判断 此处应添加 常规账户与合约的处理规则 如下简单的实现合约 与 用户
	if transfer_account2.AccountType == 1 {
	//合约账户需要满足合约规则后结算出交易金额,B为慈善合约 需满足 捐款金额累加后不大于 筹款总额
	//下列处理应有相应的统一结构与方法 此处简单处理
		if transfer_account2.Trance[0] != "effective" {
			return errors.New("Trans :: Contract uneffective!")
		}
		xx,_ := strconv.ParseFloat(analysiscontract(transfer_account2.Trance[1],0),64)
		//金额未筹集满
		if xx > transfer_account2.Sum {
			amount = xx - transfer_account2.Sum 
			//剩余金额是否小于捐款，若小于只部分捐出 并更新合约的状态
			if amount <= transfer_sum {
				transfer_sum = amount	
				transfer_account2.Trance[0] = "waitforexcute"
			}
			
		}
	}

	if transfer_account1.AccountType == 1 {
	//合约账户需要满足合约规则后结算出交易金额
		transfer_sum = transfer_sum
	}
	
	//转账 A transfer_sum 转 B
	transfer_account1.Sum = transfer_account1.Sum - transfer_sum
	transfer_account2.Sum = transfer_account2.Sum + transfer_sum
	//添加交易记录
	transfer_account1.Trance = append(transfer_account1.Trance,"To " + transfer_accoutname2 + " " + strconv.FormatFloat(transfer_sum,'f', -1, 64) )
	transfer_account2.Trance = append(transfer_account2.Trance,"From " + transfer_accoutname1 + " " + strconv.FormatFloat(transfer_sum,'f', -1, 64) )
	//将A账户结构转为字节
	transfer_valuebytes1,transfer_err = json.Marshal(transfer_account1)
	if transfer_err != nil {
		return errors.New("Transfer :: marshal Err!")
	}
	//将A账户信息存入账本
	err = stub.PutState(transfer_accoutname1,transfer_valuebytes1)
	if err != nil {
		return errors.New("OpenAccount :: PutState Error!!!,Key : " + transfer_accoutname1)
	}
	//将B账户结构转为字节 
	transfer_valuebytes2,transfer_err = json.Marshal(transfer_account2)
	if transfer_err != nil {
		return errors.New("Transfer :: marshal Err!")
	}
	//将B账户信息存入账本
	err = stub.PutState(transfer_accoutname2,transfer_valuebytes2)
	if err != nil {
		return errors.New("OpenAccount :: PutState Error!!!,Key : " + transfer_accoutname2)
	}

	return nil
}
