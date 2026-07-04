package main

import (
	"context"
	"fmt"
	"go-browse/internal/network"
	"os"
	"strings"
)

func main() {
	ctx := context.Background()
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <url>\n", os.Args[0])
		os.Exit(1)
	}
	u, err := network.NewURL(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := load(u, ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func load(url *network.URL, ctx context.Context) error {
	body, err := url.Request(ctx, 10)
	if err != nil {
		return err
	}
	show(body, url.ViewSource)
	return nil
}

func show(body string, viewSource bool) {
	if viewSource {
		fmt.Print(body)
		return
	}
	inTag := false
	inEntity := false
	entity := strings.Builder{}

	for _, c := range body {
		switch {
		case c == '<':
			inTag = true
		case c == '>':
			inTag = false
		case inTag:
			// skip
		case c == '&':
			inEntity = true
			entity.Reset()
		case inEntity:
			if c == ';' {
				inEntity = false
				switch entity.String() {
				case "lt":
					fmt.Print("<")
				case "gt":
					fmt.Print(">")
				default:
					fmt.Printf("&%s;", entity.String()) // unknown entity, print as-is
				}
			} else {
				entity.WriteRune(c)
			}
		default:
			fmt.Print(string(c))
		}
	}
}
