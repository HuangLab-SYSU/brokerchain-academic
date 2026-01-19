package utils

import (
	"errors"
	"math/big"
)

// WeiToEth Wei(string) -> ETH(string)
// decimals: 通常传 18
func WeiToEth(weiStr string, decimals int) (string, error) {
	if weiStr == "" {
		return "0", nil
	}

	wei, ok := new(big.Int).SetString(weiStr, 10)
	if !ok {
		return "", errors.New("invalid wei string")
	}

	weiFloat := new(big.Float).SetInt(wei)

	base := new(big.Float).SetInt(
		new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil),
	)

	eth := new(big.Float).Quo(weiFloat, base)

	// 固定 18 位小数（前端友好）
	return eth.Text('f', decimals), nil
}

func WeiToEthTrim(weiStr string) (string, error) {
	eth, err := WeiToEth(weiStr, 18)
	if err != nil {
		return "", err
	}

	// 去掉末尾 0 和 .
	for len(eth) > 1 && eth[len(eth)-1] == '0' {
		eth = eth[:len(eth)-1]
	}
	if eth[len(eth)-1] == '.' {
		eth = eth[:len(eth)-1]
	}
	return eth, nil
}
