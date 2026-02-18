package main

import (
	"net/http"
	"os/exec"
)

func main() {
	http.Get("https://example.com")
	exec.Command("ls")
}
