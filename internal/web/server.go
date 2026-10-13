package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/Utkarsh932006/SiemDashboard/internal/storage"
)

//go:embed static/* templates/*
var embeddedFiles embed.FS

type Server struct {
	hub   *Hub
	store *storage.Store
	tmpl  *template.Template
	mux   *http.ServeMux
}

func NewServer(hub *Hub, store *storage.Store) (*Server, error) {
	tmpl, err := template.ParseFS(embeddedFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}

	s := &Server{
		hub:   hub,
		store: store,
		tmpl:  tmpl,
		mux:   http.NewServeMux(),
	}

	s.routes()
	return s, nil
}

func (s *Server) routes() {
	staticFS, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		panic(err)
	}

	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /events/stream", ServerSentEventHandler(s.hub))
	s.mux.HandleFunc("GET /api/alerts", s.handleAlertsQuery)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "index.html", nil)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
