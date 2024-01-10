package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	//"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"strconv"
	//"time"
)

type add_request struct {
	Fname string
	Lname string
	Age   uint8
}

func GenerateTempIDString() string {
	var id_buffer bytes.Buffer
	var new_id_int int
	for i := 0; i < 6; i++ {
		new_id_int = mrand.Intn(10)
		id_buffer.WriteString(strconv.Itoa(new_id_int))
	}
	var id_string string = id_buffer.String()
	if TempFileExists(id_string) {
		return GenerateTempIDString()
	}
	return id_string
}

func TempFileExists(id_str string) bool {
	if _, err := os.Stat("./test_server_data/temp_files/" + id_str); err == nil {
		return true
	}
	return false
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	b, err := ioutil.ReadFile("./test_server_data/server_landing.html")
	if err != nil {
		w.Write([]byte("Failed to accept the data provided. /nHave you tried turning it off and on again?"))
	} else {
		w.Write(b)
	}
}

func RetrieveServer(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	var id_str string = req.Form.Get("temp_id")

	if TempFileExists(id_str) {
		b, err := ioutil.ReadFile("./test_server_data/temp_files/" + id_str)
		if err != nil {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("Failed to accept the data provided. /nHave you tried turning it off and on again?"))
		} else {
			w.Header().Set("Content-Disposition", "attachment; filename=new_signed_datafile.eid")
			w.Header().Set("Content-Type", "text/plain")
			w.Write(b)
		}
	} else {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(fmt.Sprintf("The provided passcode: '%v' is invalid.", id_str)))
	}
}

func AddServer(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	var age_num uint64
	age_num, _ = strconv.ParseUint(req.Form.Get("age"), 10, 8)
	var add_data add_request
	add_data.Fname = req.Form.Get("fname")
	add_data.Lname = req.Form.Get("lname")
	add_data.Age = uint8(age_num)

	w.Header().Set("Content-Type", "text/html")
	var json_bytes []byte
	json_bytes, _ = json.Marshal(add_data)
	var temp_id_str string = GenerateTempIDString()

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := json_bytes
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	pem_bytes, _ := ioutil.ReadFile("./test_server_data/certs/privkey.pem")
	block, _ := pem.Decode(pem_bytes)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	signature, _ := rsa.SignPSS(rand.Reader, key, newhash, hashed, &opts)

	os.WriteFile("./test_server_data/temp_files/"+temp_id_str, signature, 0666)
	w.Write([]byte("Signed successfully! Your temporary passcode is: "))
	w.Write([]byte(temp_id_str))
}

func PkeyServer(w http.ResponseWriter, req *http.Request) {
	b, err := ioutil.ReadFile("./test_server_data/certs/pkey")
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("Failed to accept the data provided. /nHave you tried turning it off and on again?"))
	} else {
		w.Header().Set("Content-Disposition", "attachment; filename=server_public_key")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(b)
	}
}

func VerifyServer(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	fmt.Println("--------------------------------------------------11111111111111111")

	var age_num uint64
	age_num, _ = strconv.ParseUint(req.Form.Get("age"), 10, 8)
	var add_data add_request
	add_data.Fname = req.Form.Get("fname")
	add_data.Lname = req.Form.Get("lname")
	add_data.Age = uint8(age_num)

	fmt.Println("--------------------------------------------------222222222222222222222222222")

	w.Header().Set("Content-Type", "text/html")
	var json_bytes []byte
	json_bytes, _ = json.Marshal(add_data)

	fmt.Println("--------------------------------------------------3333333333333333333333333333333")

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := json_bytes
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	fmt.Println("--------------------------------------------------444444444444444444444444444444444444444")

	pem_bytes, _ := ioutil.ReadFile("./test_server_data/certs/pkey")
	fmt.Println("--------------------------------------------------444444444444444444444444444444444444444")
	//block, _ := pem.Decode(pem_bytes)
	fmt.Println("--------------------------------------------------444444444444444444444444444444444444444")
	key, _ := x509.ParsePKCS1PublicKey(pem_bytes)
	fmt.Println("--------------------------------------------------444444444444444444444444444444444444444")

	fmt.Println("--------------------------------------------------555555555555555555555555555555555555555555555")

	signature_file, hhh, err := req.FormFile("signature_file")
	//signature_file, errrd := hhh.Open()
	fmt.Println("---------------------------------------")
	fmt.Println(hhh.Size)
	fmt.Println(signature_file)
	//fmt.Println(hhh)
	//fmt.Println(err)
	fmt.Println("---------------------------------------")
	if err != nil {
		fmt.Println(err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(signature_file)

	//defer signature_file.Close()
	fmt.Println(signature_file)
	fmt.Println(buf.String() + "-------------------------------------------KKKKKKKKKKKKKKKKKKKKKK")
	//io.Copy(&buf, signature_file)
	fmt.Println(buf.String() + "-------------------------------------------KKKKKKKKKKKKKKKKKKKKKK")
	var signature []byte = []byte(buf.String())
	//_, _ = signature_file.Read(signature) //[]byte(buf.String())

	err2 := rsa.VerifyPSS(key, newhash, hashed, signature, &opts)

	if err2 != nil {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("FAILURE: The provided information could not be verified."))
	} else {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(fmt.Sprintf("SUCCESS: Verified %v %v, age %v", add_data.Fname, add_data.Lname, add_data.Age)))
	}

	//w.Header().Set("Content-Type", "text/html")
	//w.Write([]byte(fmt.Sprintf("The time is %v", time.Now())))
}

func main() {
	http.HandleFunc("/", HelloServer)
	http.HandleFunc("/add", AddServer)
	http.HandleFunc("/retrieve", RetrieveServer)
	http.HandleFunc("/verify/", VerifyServer)
	http.HandleFunc("/pkey", PkeyServer)
	//err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
	err := http.ListenAndServe("0.0.0.0:443", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
