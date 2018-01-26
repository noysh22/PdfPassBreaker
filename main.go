package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	b "github.com/noysh22/pdf_breaker/breaker"
	unicommon "github.com/unidoc/unidoc/common"
)

const argc = 2

type argsT struct {
	filename      string
	passMaxLength uint
}

func parseArgs() (*argsT, error) {
	const passDefaultLength = 6

	if len(os.Args) < argc {
		printUsage()
		return nil, errors.New("Not enough arguments")
	}

	args := &argsT{}

	flag.StringVar(&args.filename, "f", "", "Filename for the pdf to break")
	flag.UintVar(&args.passMaxLength, "l", passDefaultLength, "Max length for the password")
	flag.Parse()

	if "" == args.filename {
		return nil, errors.New("-f is required")
	}

	return args, nil
}

func printUsage() {
	fmt.Println("====================== USAGE ======================")
	fmt.Println("pdf_breaker -f {filename} -l {passMaxLength}")
	fmt.Println("========================   ========================")
}

func main() {
	fmt.Println("PDF BREAKER")
	unicommon.SetLogger(unicommon.NewConsoleLogger(unicommon.LogLevelDebug))

	args, err := parseArgs()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("filename: %s\nmax length: %d\n", args.filename, args.passMaxLength)

	breaker, err := b.NewBreaker(args.filename, args.passMaxLength)
	if nil != err {
		fmt.Printf("Error: %v\n", err)
		return
	}

	pass, err := breaker.BruteForce()
	if nil != err {
		fmt.Printf("Error brute forcing: %v\n", err)
		return
	}

	fmt.Printf("PASSWORD CRACKED, Pass is: %s\n", pass)
	fmt.Println("Great success")
}
