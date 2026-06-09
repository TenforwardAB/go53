package handlers

import (
	"net/http"
	"os"
)

const swaggerHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>go53 API Docs</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.32.4/swagger-ui.css" integrity="sha384-AHNbXeU7DPcgcihnwKYc3FOT0hTfhEwVFc2JRxxF5S/mplUdt/7G1g6nIblzENrX" crossorigin="anonymous">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.32.4/swagger-ui-bundle.js" integrity="sha384-FgJpbEfGqpFeiFJh0+HNvyohx84XMd+IwgPyxJxjuDFMHVYmoFqrDEJNrVFexwA0" crossorigin="anonymous"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({ url: "/openapi.yaml", dom_id: "#swagger-ui" });
    };
  </script>
</body>
</html>`

func OpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	data, ok := readOpenAPISpec()
	if !ok {
		http.Error(w, "openapi spec not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(data)
}

func readOpenAPISpec() ([]byte, bool) {
	for _, path := range []string{"docs/api/openapi.yaml", "../docs/api/openapi.yaml"} {
		data, err := os.ReadFile(path)
		if err == nil {
			return data, true
		}
	}
	return nil, false
}

func SwaggerUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerHTML))
}
