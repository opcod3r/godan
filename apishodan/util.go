package apishodan

import (
	"bufio"
	"log"
	"os"
)

// LoadKeys reads API keys from a file where each line contains one key
func LoadKeys(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening keys file: %v", err)
	}
	defer file.Close()

	var keys []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		keys = append(keys, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading keys file: %v", err)
	}

	//log.Printf("Keys loaded: %v", keys)
	return keys
}
