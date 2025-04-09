package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Aptos struct {
	network string
}

const AptosNetworkDevNet = "devnet"
const AptosNetworkTestNet = "testnet"
const AptosNetworkMainNet = "mainnet"

type AptosGetPepperResult struct {
	Pepper  string `json:"pepper"`
	Address string `json:"address"`
}

type AptosError struct {
	Message string `json:"message"`
}

func NewAptos(network string) *Aptos {
	return &Aptos{network: network}
}

func (a *Aptos) GetName() string {
	return "aptos"
}

func (a *Aptos) ExtractAddressFromSignInput(ctx context.Context, input *SignInput) (*string, error) {

	body, err := json.Marshal(input)

	if err != nil {
		return nil, err
	}

	bodyReader := bytes.NewReader(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://api.%s.aptoslabs.com/keyless/pepper/v0/fetch", a.network), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 10 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		var respData AptosError
		err = json.Unmarshal(resBody, &respData)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(respData.Message)
	} else {
		var respData AptosGetPepperResult
		err = json.Unmarshal(resBody, &respData)
		if err != nil {
			return nil, err
		}
		return &respData.Address, nil
	}
}
