package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/yeka/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	zipPath   string
	wordlist  string
	workers   int
	mutex     sync.Mutex
	wait      sync.WaitGroup
	found     bool
	foundPass string
	dstDir    string
)

func extractZip(r *zip.ReadCloser, password string) error {
	dstDir = strings.TrimSuffix(zipPath, ".zip")
	for _, f := range r.File {
		f.SetPassword(password)
		filePath := filepath.Join(dstDir, f.Name)

		if f.FileInfo().IsDir() {
			err := os.MkdirAll(filePath, os.ModePerm)
			if err != nil {
				return err
			}
			continue
		}
		err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm)
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		out, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, rc)
		if err != nil {
			return err
		}
	}
	return nil
}

func crackPassword(password string) bool {

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		fmt.Printf("Error opening zip: %s\n", err)
		os.Exit(1)
	}
	defer reader.Close()

	if len(reader.File) == 0 {
		fmt.Printf("Zip file is empty\n")
	}
	for _, f := range reader.File {
		f.SetPassword(password)
		_, err = f.Open()
		if err != nil {
			fmt.Printf("Zip file cant be decrypted with password: \033[34m%s\033[0m\n", password)
			return false
		}
	}
	err = extractZip(reader, password)
	if err != nil {
		fmt.Printf("Error extracting zip: %s\n", err)
	}
	return true
}

func worker(passwords <-chan string) {
	defer wait.Done()
	for password := range passwords {
		mutex.Lock()
		if found {
			mutex.Unlock()
			return
		}
		mutex.Unlock()

		if crackPassword(password) {
			mutex.Lock()
			found = true
			foundPass = password
			mutex.Unlock()
		}
	}
}

func main() {
	flag.StringVar(&zipPath, "zip", "", "zip file path")
	flag.StringVar(&wordlist, "wordlist", "", "wordlist file path")
	flag.IntVar(&workers, "workers", 12, "number of workers")
	flag.Parse()

	if zipPath == "" {
		fmt.Printf("Error: zip file path is empty. use -zip flag.\n")
		os.Exit(1)
	}

	if wordlist == "" {
		fmt.Printf("Error: wordlist file path is empty. use -wordlist flag.\n")
		os.Exit(1)
	}

	start := time.Now()

	fmt.Printf("Start bruteforcing %s\n", zipPath)

	file, err := os.Open(wordlist)
	if err != nil {
		fmt.Printf("Error opening zip: %s\n", err)
		os.Exit(1)
	}
	defer file.Close()
	passwords := make(chan string, workers)

	wait.Add(workers)
	for i := 0; i < workers; i++ {
		go worker(passwords)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mutex.Lock()
		if found {
			mutex.Unlock()
			break
		}
		mutex.Unlock()

		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			passwords <- password
		}
	}
	close(passwords)
	wait.Wait()

	elapsed := time.Since(start)

	if found {
		fmt.Printf("done Bruteforcing the %s with password \033[32m%s\033[0m\n", zipPath, foundPass)
		fmt.Printf("\033[32mZip extracted at: %s\033[0m\n", dstDir)
	} else {
		fmt.Printf("\033[31mno matching password found in %s\033[0m\n", wordlist)
	}
	fmt.Printf("Time elapsed: \033[33m%s\033[0m\n", elapsed)
}
