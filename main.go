package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/opcod3r/godan/apishodan"
)

const (
	Author         = "@opcod3r"
	MaxGoroutines  = 5 // Define the maximum number of parallel goroutines
	RequestTimeout = 10 * time.Second
)

func main() {
	domain := flag.String("d", "", "> Domain to find subdomains")
	verbose := flag.Bool("v", false, "> Show all output")
	fileName := flag.String("o", "", "> Save domains into a file")
	inputFile := flag.String("f", "", "> File containing domains to find subdomains")
	keysFile := flag.String("k", "keys.txt", "> File containing Shodan API keys")
	flag.Parse()

	if *domain == "" && *inputFile == "" {
		fmt.Printf("[*] Usage: %s -d target.com [-f input_file] [-k keys_file]\n", os.Args[0])
		fmt.Printf("[*] Author: %s\n", Author)
		os.Exit(1)
	}

	keys := apishodan.LoadKeys(*keysFile)
	if len(keys) == 0 {
		log.Fatal("No API keys loaded")
	}
	//log.Printf("Loaded %d keys\n", len(keys))

	var domains []string

	if *domain != "" {
		//log.Printf("Adding domain %s to the list\n", *domain)
		domains = append(domains, *domain)
	}

	if *inputFile != "" {
		//log.Printf("Reading domains from file %s\n", *inputFile)
		fileDomains, err := readDomainsFromFile(*inputFile)
		if err != nil {
			log.Fatalf("Failed to read domains from file: %v", err)
		}
		domains = append(domains, fileDomains...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	for _, domainSearch := range domains {
		//log.Printf("Searching for subdomains of %s\n", domainSearch)
		key, err := apishodan.GetValidKey(ctx, keys, MaxGoroutines, *verbose)
		if err != nil {
			log.Fatalf("No valid keys available: %v", err)
		}

		api := apishodan.New(key)
		subdomain, err := api.GetSubdomain(ctx, domainSearch, *verbose)
		if err != nil {
			log.Panicln(err)
		}

		if *verbose {
			info, err := api.InfoAccount(ctx, *verbose)
			if err != nil {
				log.Panicln(err)
			}
			fmt.Printf("[*] Credits: %d\nScan Credits: %d\n\n", info.QueryCredits, info.ScanCredits)

			for _, v := range subdomain.Data {
				d := v.SubD + subdomain.Domain
				fmt.Printf("[*] Domain: %s\nIP/DNS: %s\nLast Scan made by Shodan: %s\n", d, v.Value, v.LastSeen)
			}
		} else {
			for _, v := range subdomain.SubDomains {
				if *fileName != "" {
					if err := writeToFile(*fileName, v); err != nil {
						log.Fatal(err)
					}
				}
				fmt.Printf("%s.%s\n", v, domainSearch)
			}
		}
	}
}

func readDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

func writeToFile(filename, data string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(data + "\n"); err != nil {
		return err
	}
	fmt.Println("[*] DONE writing to file:", filename)
	return nil
}
