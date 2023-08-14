package mfa

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	EnvBindServer = "BIND"
	EnvPortServer = "PORT"
	EnvMongoURI   = "MONGO_URI"

	EnvLoadSkip  = "LOAD_SKIP"
	EnvLoadLimit = "LOAD_LIMIT"
)

func LoadEnvironmentVariables(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(file)
	// create a new scanner to read each row
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var (
			line       = scanner.Text()
			key, value string
		)
		if len(line) == 0 || !strings.Contains(line, "=") ||
			strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "//") {
			continue
		}
		arg := strings.Split(line, "=")
		if len(arg) > 0 {
			key = arg[0]
			key = strings.TrimSpace(key)
		}
		if len(key) == 0 {
			continue
		}
		if len(arg) > 1 {
			value = strings.Join(arg[1:], "=")
			value = strings.TrimSpace(value)
			value = strings.TrimPrefix(value, bytes.NewBuffer([]byte{0x22}).String())
			value = strings.TrimSuffix(value, bytes.NewBuffer([]byte{0x22}).String())
			value = strings.TrimPrefix(value, bytes.NewBuffer([]byte{0x27}).String())
			value = strings.TrimSuffix(value, bytes.NewBuffer([]byte{0x27}).String())
			value = strings.TrimPrefix(value, bytes.NewBuffer([]byte{0x60}).String())
			value = strings.TrimSuffix(value, bytes.NewBuffer([]byte{0x60}).String())
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
		//println("SetENV:", key, "=", strings.Repeat("*", len(value)))
	}
	return nil
}

func GetBindAddress() string {
	var (
		envBIND = os.Getenv(EnvBindServer)
		envPORT = os.Getenv(EnvPortServer)
	)
	if len(envBIND) == 0 {
		envBIND = "0.0.0.0"
	}
	if len(envPORT) == 0 {
		envPORT = "8080"
	}
	return fmt.Sprintf("%s:%s", envBIND, envPORT)
}

func GetMongoURI() (dbURI, dbname string) {
	conn, err := uri.ParseAndValidate(os.Getenv(EnvMongoURI))
	if err != nil {
		log.Fatalf("- GetMongoURI error: %s\n", err.Error())
		return
	}

	if conn.UsernameSet && !conn.PasswordSet {
		arr := strings.Split(conn.Original, "@")
		if len(arr) > 1 {
			var pwd string
			print("Enter password of MongoDB: ")
			if _, err := fmt.Scan(&pwd); err != nil {
				log.Fatalf("%s\n", err.Error())
			}
			print("\b\rPassword Fingerprint:      " + strings.Repeat("*", len(pwd)) + "\n") // hide password input
			conn.PasswordSet = true
			conn.Password = pwd
			conn.Original = arr[0] + ":" + pwd + "@" + strings.Join(arr[1:], "@")
			if _, err := uri.ParseAndValidate(conn.Original); err != nil {
				log.Fatalf("- GetMongoURI error: %s\n", "password invalid format")
				return
			}
		}
	}
	return conn.String(), conn.Database
}
