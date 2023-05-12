package handlers

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	"github.com/seabasssec/cvereporter/internal/filehandler"
	"github.com/seabasssec/cvereporter/internal/structures"
)

// Custom writer for gzip middleware
type GzipWriter struct {
	http.ResponseWriter
	Writer io.Writer
}

func (w GzipWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

type Server struct {
	Router *chi.Mux
}

func NewServer() *Server {
	server := Server{
		Router: chi.NewRouter(),
	}

	server.Router.Route("/", func(r chi.Router) {
		r.Use(GzipHandle)
		r.Use(cors.Handler(cors.Options{
			// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
			AllowedOrigins: []string{"https://*", "http://*"},
			// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: false,
			MaxAge:           300, // Maximum value not ignored by any of major browsers
		}))
		r.Post("/updatedb", server.UpdateBase)
		r.Post("/report", server.CreateReport)
	})
	return &server
}

func (s *Server) CreateReport(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	var JSONRequest structures.JSONReportRequest
	if err := json.NewDecoder(r.Body).Decode(&JSONRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	first, err := strconv.Atoi(JSONRequest.FromYear)
	if err != nil {
		fmt.Println("Error in first parameter:", err)
		w.Write([]byte("Something went wrong."))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	last, err := strconv.Atoi(JSONRequest.ToYear)
	if err != nil {
		fmt.Println("Error in last parameter:", err)
		w.Write([]byte("Something went wrong."))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var years []string
	for i := first; i <= last; i++ {
		years = append(years, strconv.Itoa(i))
	}

	filename, err := filehandler.CreateReport(years, JSONRequest.Part, JSONRequest.Vendor, JSONRequest.Product, JSONRequest.Version, JSONRequest.Update, JSONRequest.Edition, JSONRequest.Language, JSONRequest.SWEdition, JSONRequest.TargetSW, JSONRequest.TargetHW, JSONRequest.Other)
	if err != nil {
		fmt.Println("Error with CheckActualy in UpdateBase:", err)
		w.Write([]byte("Something went wrong."))
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(filename))
	fmt.Println("DONE! Report is created!.")
	//w.Write([]byte("DONE! Report is created!."))

}

func (s *Server) UpdateBase(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	//w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Type", "application/json")
	var JSONUpdate structures.JSONUpdateDB
	if err := json.NewDecoder(r.Body).Decode(&JSONUpdate); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println(r.FormValue(JSONUpdate.FromYear), r.FormValue(JSONUpdate.ToYear))
	first, err := strconv.Atoi(JSONUpdate.FromYear)
	//first, err := strconv.Atoi(r.FormValue(JSONUpdate.FromYear))
	if err != nil {
		fmt.Println("Error in first parameter:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	last, err := strconv.Atoi(JSONUpdate.ToYear)
	//last, err := strconv.Atoi(r.FormValue(JSONUpdate.ToYear))
	if err != nil {
		fmt.Println("Error in last parameter:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// wg := &sync.WaitGroup{}
	// wg.Add(1)
	// go func() {
	for i := first; i <= last; i++ {
		err := filehandler.CheckActualy(strconv.Itoa(i))
		if err != nil {
			fmt.Println("Error with CheckActualy in UpdateBase:", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	// 	wg.Done()
	// }()
	// wg.Wait()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("DONE! All files are loaded or checked."))
	fmt.Println("DONE! All files are loaded or checked.")

}

func GzipHandle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			if !strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}
		}
		var writer = w
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {

			gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
			if err != nil {
				io.WriteString(w, err.Error())
				return
			}
			defer gz.Close()
			writer = GzipWriter{ResponseWriter: w, Writer: gz}
			w.Header().Set("Content-Encoding", "gzip")
		}
		if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
			gzr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer gzr.Close()
			r.Body = gzr
		}
		next.ServeHTTP(writer, r)
	})
}
