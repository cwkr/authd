package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cwkr/authd/passwordhash"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	var (
		format    string
		password  string
		cost      int
		givenHash string
	)
	flag.StringVar(&format, "fmt", "SSHA512", "password hash format (SSHA, SSHA256, SSHA512, BCRYPT)")
	flag.IntVar(&cost, "cost", bcrypt.DefaultCost, "bcrypt cost")
	flag.StringVar(&givenHash, "check", "", "check given password hash")
	flag.Parse()

	if password = flag.Arg(0); password == "" {
		if pw, err := term.ReadPassword(int(os.Stdin.Fd())); err != nil {
			panic(err)
		} else {
			password = string(pw)
		}
	}

	if givenHash != "" {
		if err := passwordhash.Check(givenHash, password); err != nil {
			panic(err)
		}
		fmt.Printf("%s: OK", strings.ToUpper(passwordhash.GetFormat(givenHash)))
	} else {
		if hash, err := passwordhash.New(format, password, cost); err != nil {
			panic(err)
		} else {
			println(hash)
		}
	}
}
