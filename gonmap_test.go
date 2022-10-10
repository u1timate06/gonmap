package gonmap

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/lcvvvv/gonmap/simplenet"
)

func TestScan(t *testing.T) {
	f, _ := os.OpenFile("nmap.log", os.O_WRONLY|os.O_CREATE, 0664)
	logger = Logger(log.New(f, "[gonmap] ", log.Ldate|log.Ltime|log.Lshortfile))
	defer f.Close()
	var scanner = New(9)
	scanner.OpenDeepIdentify()
	ctx := context.Background()
	scanner.SetTimeout(10 * time.Second)
	//host := "192.168.10.146"
	host := "127.0.0.1"
	port := 6000
	status, response := scanner.ScanTimeout(ctx, host, port, time.Second*300)
	if response != nil {
		fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	} else {
		fmt.Println(status, host, ":", port)
	}
	go func() {
		host := "192.168.10.146"
		port := 80
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()

	go func() {
		host := "192.168.10.146"
		port := 22
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()
	go func() {
		host := "192.168.10.146"
		port := 443
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()
	go func() {
		host := "192.168.10.146"
		port := 8080
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()
	go func() {
		host := "192.168.10.146"
		port := 43306
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()
	go func() {
		host := "192.168.10.146"
		port := 46379
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()
	//var scanner2 = New(9, false)
	//scanner2.OpenDeepIdentify()
	go func() {
		host := "192.168.10.162"
		port := 53
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()
	go func() {
		host := "192.168.11.10"
		port := 7913
		status, response := scanner.ScanTimeout(ctx, host, port, time.Second*30)
		if response != nil {
			fmt.Println(status, response.FingerPrint.Service, host, ":", port)
		} else {
			fmt.Println(status, host, ":", port)
		}
	}()
	select {}
}

func TestSend(t *testing.T) {
	rs, err := simplenet.Send("tcp", false, "192.168.10.146:46379", "1", 10*time.Second, 10)
	if err != nil {
		t.Error(err)
	} else {
		println(rs)
	}
}
