package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	baseURL   = "http://localhost:8053/api/add-a"
	zone      = "go53.test"
	ipAddress = "1.2.3.4"
	total     = 1_000_000
)

type ARecord struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
	IP   string `json:"ip"`
}

func main() {
	client := &http.Client{}

	for i := 1; i <= total; i++ {
		record := ARecord{
			Zone: zone,
			Name: fmt.Sprintf("%d", i),
			IP:   ipAddress,
		}

		body, err := json.Marshal(record)
		if err != nil {
			fmt.Printf("json error on %d: %v\n", i, err)
			continue
		}

		req, err := http.NewRequest("POST", baseURL, bytes.NewBuffer(body))
		if err != nil {
			fmt.Printf("request error on %d: %v\n", i, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("HTTP error on %d: %v\n", i, err)
			continue
		}
		resp.Body.Close()

		if i%10000 == 0 {
			fmt.Printf("Inserted %d records\n", i)
		}
	}
}
