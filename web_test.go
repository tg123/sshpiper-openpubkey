package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// go test -v -run ExampleDebugTemplate -timeout 24h
func ExampleDebugTemplate() {
	r := gin.Default()
	r.LoadHTMLFiles(templatefile)

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, templatefile, gin.H{})
	})

	r.Run()

	fmt.Println("Force to run") // Output: fuck
}
