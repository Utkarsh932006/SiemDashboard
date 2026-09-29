package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed static/* templates/*
var embeddedFiles embed.FS

type Server struct {
	hub  *Hub
	tmpl *template.Template
	mux  *http.ServeMux
}

func NewServer(hub *Hub) (*Server, error) {
	tmpl, err := template.ParseFS(embeddedFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}

	s := &Server{
		hub:  hub,
		tmpl: tmpl,
		mux:  http.NewServeMux(),
	}

	s.routes()
	return s, nil
}

func (s *Server) routes() {
	staticFS, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		panic(err)
	}

	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.HandleFunc("GET /events/stream", ServerSentEventHandler(s.hub))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "index.html", nil)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
