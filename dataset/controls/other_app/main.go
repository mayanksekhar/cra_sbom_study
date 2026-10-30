package main

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

func main() {
	doc, err := html.Parse(strings.NewReader("<p>hello</p>"))
	if err != nil {
		panic(err)
	}
	var b strings.Builder
	if err := html.Render(&b, doc); err != nil {
		panic(err)
	}
	fmt.Println(b.String())
}
