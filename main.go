package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

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
	// const filepath = "/Users/noyshi01/Documents/slip.pdf"
	// file, err := os.Open(args.filename)
	// if err != nil {
	// 	panic(fmt.Sprintf("Error: %v\n", err))
	// }
	// defer file.Close()

	// reader, err := pdf.NewPdfReader(file)
	// if err != nil {
	// 	panic(fmt.Sprintf("Error: %v\n", err))
	// }

	// if isEncrypted, _ := reader.IsEncrypted(); isEncrypted {
	// 	fmt.Println("File encrypted")
	// } else {
	// 	fmt.Println("File not protected")
	// }
	// reader.CheckAccessRights([]byte(password))

	fmt.Println("Great success")
}
