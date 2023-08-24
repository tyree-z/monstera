package pages

import (
	"html/template"
	"net/http"
)

type ErrorPageData struct {
    Title   string
    Heading string
    Message string
}

func RenderErrorPage(w http.ResponseWriter, statusCode int, templatePath string, data ErrorPageData) {
    tmpl, err := template.ParseFiles(templatePath)
    if err != nil {
        http.Error(w, "Error processing page", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(statusCode)
    tmpl.Execute(w, data)
}
