package main

import (
	"embed"
	"html/template"

	"github.com/gin-gonic/gin"
)

//go:embed html/*
var embeddedFS embed.FS

func loadTemplates(engine *gin.Engine) {
	tmpl := template.Must(template.New("").ParseFS(
		embeddedFS,
		"html/*.html",
	))
	engine.SetHTMLTemplate(tmpl)
}
