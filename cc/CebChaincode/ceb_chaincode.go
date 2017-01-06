/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

//WARNING - this chaincode's ID is hard-coded in chaincode_example04 to illustrate one way of
//calling chaincode from a chaincode. If this example is modified, chaincode_example04.go has
//to be modified as well with the new ID of chaincode_example02.
//chaincode_example05 show's how chaincode ID can be passed in as a parameter instead of
//hard-coding.

import (
	"errors"
	"fmt"
	"strconv"
	"crypto/x509"
	"encoding/pem"
	"crypto/sha256"
	"crypto/rsa"
	"encoding/json"
	"encoding/hex"
	"crypto"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

type cebaccount struct{
	AccountType int
	Rsapk rsa.PublicKey
	Trance []string
	Sum float64
}
	
var account cebaccount
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Println("LYW Test in Init")
	var A, B string    // Entities
	var Aval, Bval int // Asset holdings
	var err error

	if len(args) != 4 {
		return nil, errors.New("Incorrect number of arguments. Expecting 4")
	}

	// Initialize the chaincode
	A = args[0]
	Aval, err = strconv.Atoi(args[1])
	if err != nil {
		return nil, errors.New("Expecting integer value for asset holding")
	}
	B = args[2]
	Bval, err = strconv.Atoi(args[3])
	if err != nil {
		return nil, errors.New("Expecting integer value for asset holding")
	}
	fmt.Printf("Aval = %d, Bval = %d\n", Aval, Bval)

	// Write the state to the ledger
	err = stub.PutState(A, []byte(strconv.Itoa(Aval)))
	if err != nil {
		return nil, err
	}

	err = stub.PutState(B, []byte(strconv.Itoa(Bval)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	if function == "delete" {
		// Deletes an entity from its state
		return t.delete(stub, args)
	}

	var pempk string
	var sum float64
	var accounttype int
	var err error
	var valuebytes []byte

	// 开户
	if function == "OpenAccount"{
		if len(args) != 3 {
			return nil, errors.New("OpenAccount :: Incorrect number of arguments. Expecting 3")
		}
		pempk = args[0]
		accounttype,_= strconv.Atoi(args[1])
		sum,_ = strconv.ParseFloat(args[2],64)
	
		fmt.Println(pempk)
		block, _ := pem.Decode([]byte(pempk))
		pub,_ := x509.ParsePKIXPublicKey(block.Bytes)
		key,_:= pub.(*rsa.PublicKey)

		hash := sha256.Sum256([]byte(pempk))
		name := fmt.Sprintf("%X",string(hash[:]))
		stub.DelState(name)

		valuebytes, err= stub.GetState(name)
		if err != nil {
			return nil, errors.New("OpenAccount :: GetState Err!!! Key: " + name)
		}
		
		if valuebytes != nil {
			return nil, errors.New("OpenAccount :: Account Exist!!!")
		}

		fmt.Println(key)
		fmt.Println(name)
		account = cebaccount{
			Rsapk : *key,
			AccountType : accounttype,
			Trance : []string{},
			Sum : sum,
		}
		if account.Sum > 0. {
			account.Trance = append(account.Trance,fmt.Sprintf("Banker Give %s %f",name,sum))
		}
		fmt.Println(account)
		
		b,er:= json.Marshal(account)
		if er != nil {
			fmt.Println("Err in Marshal")
		}
		fmt.Println(b)
		err = stub.PutState(name,b)
		if err != nil {
			return nil, errors.New("OpenAccount :: PutState Error!!!,Key : " + name)
		}	
		return []byte(name),nil
	}
	
	if function == "Transfer" {
		// add lyw user for test
		Transfer_lyw := cebaccount {
			Trance : []string{},
			Sum : 100.,
			AccountType : 0,
		}

		lywb,_:= json.Marshal(Transfer_lyw)
		stub.PutState("lyw",lywb)

		if len(args) != 4 {
			return nil, errors.New("Transfer :: Incorrect number of arguments. Expecting 4")
		}
		fmt.Println("======================  transe ==============================")
		transfer_accoutname1 := args[0]	
		transfer_accoutname2 := args[1]	
		transfer_sum,_:= strconv.ParseFloat(args[2],64)
		//is user1 exist
		transfer_valuebytes1,err := stub.GetState(transfer_accoutname1)
		if err != nil {
			return nil,errors.New("Transfer :: GetState Err! Key: " + transfer_accoutname1)
		}
		if transfer_valuebytes1 == nil {
			return nil, errors.New("Transfer :: user [" + transfer_accoutname1 + "] not exist!")
		}

		//get user1 account struct
		var transfer_account1 cebaccount
		transfer_err := json.Unmarshal(transfer_valuebytes1,&transfer_account1)
		if transfer_err != nil {
			return nil,errors.New("Transfer :: Unmarshal Err!")
		}
		fmt.Println(transfer_account1)
		// varify is user do trans
		transfer_msg := transfer_accoutname1 + transfer_accoutname2 + args[2]
		trnasfer_hasd := sha256.Sum256([]byte(transfer_msg))
		transfer_sign,_:= hex.DecodeString(args[3])
		fmt.Printf("Date[%s]\nHash [%X]\nSign [%x]\n",transfer_msg,string(trnasfer_hasd[:]),string(transfer_sign[:]))
		transfer_err = rsa.VerifyPKCS1v15(&transfer_account1.Rsapk, crypto.SHA256, trnasfer_hasd[:], transfer_sign)
		if transfer_err != nil {
			return nil, errors.New("Transfer :: user [" + transfer_accoutname1 + "] Verify Err!")
		}
		// is sum ok
		if transfer_account1.Sum < transfer_sum {
			return nil,errors.New("Transfer :: user [" + transfer_accoutname1 + "] Sum Err!")
		}
		// is user2 ok
		transfer_valuebytes2,err := stub.GetState(transfer_accoutname2)
		if err != nil {
			return nil,errors.New("Transfer :: GetState Err! Key: " + transfer_accoutname1)
		}
		if transfer_valuebytes2 == nil {
			return nil, errors.New("Transfer :: user [" + transfer_accoutname2 + "] not exist!")
		}
		
		// Get user2 struct
		var transfer_account2 cebaccount
		transfer_err = json.Unmarshal(transfer_valuebytes2,&transfer_account2)
		if transfer_err != nil {
			return nil,errors.New("Transfer :: Unmarshal Err!")
		}
		// Do Trans
		if transfer_account2.AccountType == 0 {
			transfer_account1.Sum = transfer_account1.Sum - transfer_sum
			transfer_account2.Sum = transfer_account2.Sum + transfer_sum
			transfer_account1.Trance = append(transfer_account1.Trance,"To " + transfer_accoutname2 + " " + args[2])	
			transfer_account2.Trance = append(transfer_account2.Trance,"From " + transfer_accoutname1 + " " + args[2])	
			// Update leger
			transfer_valuebytes1,transfer_err = json.Marshal(transfer_account1)
			if transfer_err != nil {
			return nil,errors.New("Transfer :: marshal Err!")
			}
			err = stub.PutState(transfer_accoutname1,transfer_valuebytes1)
			if err != nil {
				return nil, errors.New("OpenAccount :: PutState Error!!!,Key : " + transfer_accoutname1)
			}	
			transfer_valuebytes2,transfer_err = json.Marshal(transfer_account2)
			if transfer_err != nil {
				return nil,errors.New("Transfer :: marshal Err!")
			}
			err = stub.PutState(transfer_accoutname2,transfer_valuebytes2)
			if err != nil {
				return nil, errors.New("OpenAccount :: PutState Error!!!,Key : " + transfer_accoutname2)
			}	
		}
		
		if transfer_account2.AccountType == 1 {
			//需要判断合约状态 以及合约条件 此处正对 合约的 TX 内容解析 目前简单设计
			if transfer_account2.Trance[0] != "effective" {
				return nil,errors.New("Trans :: Contract uneffective!")
			}
			amount,_ := strconv.ParseFloat(analysiscontract(transfer_account2.Trance[1],0),64)
			if amount == transfer_account2.Sum {
				//设置合约为等待执行状态
				transfer_account2.Trance[0] = "waitforexcute"
				//更新合约
				transfer_valuebytes2,transfer_err = json.Marshal(transfer_account2)
				if transfer_err != nil {
					return nil,errors.New("Transfer :: marshal Err!")
				}
				err = stub.PutState(transfer_accoutname2,transfer_valuebytes2)
				if err != nil {
					return nil, errors.New("OpenAccount :: PutState Error!!!,Key : " + transfer_accoutname2)
				}
				return nil,errors.New("Trans :: Contract Is uneffective")	
			}
			
			lef := amount - transfer_account2.Sum
			
			if lef <= transfer_sum {
				//部分捐款
				transfer_sum = lef
				transfer_account2.Trance[0] = "waitforexcute"
			
			}
			transfer_account1.Sum = transfer_account1.Sum - transfer_sum
			transfer_account2.Sum = transfer_account2.Sum + transfer_sum
			transfer_account1.Trance = append(transfer_account1.Trance,"To " + transfer_accoutname2 + " " + strconv.FormatFloat(transfer_sum,'f', -1, 64) )
			transfer_account2.Trance = append(transfer_account2.Trance,"From " + transfer_accoutname1 + " " + strconv.FormatFloat(transfer_sum,'f', -1, 64) )	
			transfer_valuebytes1,transfer_err = json.Marshal(transfer_account1)
			if transfer_err != nil {
			return nil,errors.New("Transfer :: marshal Err!")
			}
			err = stub.PutState(transfer_accoutname1,transfer_valuebytes1)
			if err != nil {
				return nil, errors.New("OpenAccount :: PutState Error!!!,Key : " + transfer_accoutname1)
			}	
			transfer_valuebytes2,transfer_err = json.Marshal(transfer_account2)
			if transfer_err != nil {
				return nil,errors.New("Transfer :: marshal Err!")
			}
			err = stub.PutState(transfer_accoutname2,transfer_valuebytes2)
			if err != nil {
				return nil, errors.New("OpenAccount :: PutState Error!!!,Key : " + transfer_accoutname2)
			}	
			
					
		}
		return nil,nil
	}
	
	if function == "Issue" {
		return nil,nil

	}

	if function == "CreateContract" {
		fmt.Println("++++++++++++++++++++++++ CreateContract ++++++++++++++++++++++++++++++++++")
//		stub.DelState("D44A6A1C7C66BCED3AB3A54C211135D58AC2F2393F1F4CA821286E296AC67AE1")
		stub.DelState("lywtest")
		contract_name,err := createcontract(stub,args)
		if err != nil {
			return nil,errors.New("CreateContract :: createcontract Err!")
		}
		return []byte(contract_name),nil
	}
	
	if function == "ExecuteContract" {
		fmt.Println("++++++++++++++++++++++++ ExecuteContract ++++++++++++++++++++++++++++++++++")
		err = executecontract(stub,args)
		if err != nil {
			return nil,errors.New("ExecuteContract :: executecontract Err!")
		}
		return nil,nil 

	}
	
	return nil, nil
}

// Deletes an entity from state
func (t *SimpleChaincode) delete(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1")
	}

	A := args[0]

	// Delete the key from the state in ledger
	err := stub.DelState(A)
	if err != nil {
		return nil, errors.New("Failed to delete state")
	}

	return nil, nil
}

// Query callback representing the query of a chaincode
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function != "query" {
		return nil, errors.New("Invalid query function name. Expecting \"query\"")
	}
	var A string // Entities
	var err error
	var query_account cebaccount

	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting name of the person to query")
	}

	A = args[0]

	// Get the state from the ledger
	Avalbytes, err := stub.GetState(A)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + A + "\"}"
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		jsonResp := "{\"Error\":\"Nil amount for " + A + "\"}"
		return nil, errors.New(jsonResp)
	}
	
	json.Unmarshal(Avalbytes,&query_account)
	var tmp string
	tmp = fmt.Sprintf("Amount [%f]",query_account.Sum)
	for _,value := range query_account.Trance {
		tmp = tmp + value + "|"
	}

//	tmp := fmt.Sprintf("%f TransMessage %s",query_account.Sum,query_account.Trance)
	jsonResp := "{\"Name\":\"" + A + "\",\"Amount\":\"" + tmp + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return []byte(tmp), nil
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
