package lib

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/net/webdav"
)

// CorsCfg is the CORS config.
type CorsCfg struct {
	Enabled        bool
	Credentials    bool
	AllowedHeaders []string
	AllowedHosts   []string
	AllowedMethods []string
	ExposedHeaders []string
}

// Config is the configuration of a WebDAV instance.
type Config struct {
	*User
	Auth      bool
	Debug     bool
	NoSniff   bool
	Cors      CorsCfg
	Users     map[string]*User
	LogFormat string
	Anonymous    bool
	GetBlackList []string
}

// ServeHTTP determines if the request is for this plugin, and if all prerequisites are met.
func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := c.User
	requestOrigin := r.Header.Get("Origin")

	// Add CORS headers before any operation so even on a 401 unauthorized status, CORS will work.
	if c.Cors.Enabled && requestOrigin != "" {
		headers := w.Header()

		allowedHeaders := strings.Join(c.Cors.AllowedHeaders, ", ")
		allowedMethods := strings.Join(c.Cors.AllowedMethods, ", ")
		exposedHeaders := strings.Join(c.Cors.ExposedHeaders, ", ")

		allowAllHosts := len(c.Cors.AllowedHosts) == 1 && c.Cors.AllowedHosts[0] == "*"
		allowedHost := isAllowedHost(c.Cors.AllowedHosts, requestOrigin)

		if allowAllHosts {
			headers.Set("Access-Control-Allow-Origin", "*")
		} else if allowedHost {
			headers.Set("Access-Control-Allow-Origin", requestOrigin)
		}

		if allowAllHosts || allowedHost {
			headers.Set("Access-Control-Allow-Headers", allowedHeaders)
			headers.Set("Access-Control-Allow-Methods", allowedMethods)

			if c.Cors.Credentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}

			if len(c.Cors.ExposedHeaders) > 0 {
				headers.Set("Access-Control-Expose-Headers", exposedHeaders)
			}
		}
	}

	if r.Method == "OPTIONS" && c.Cors.Enabled && requestOrigin != "" {
		return
	}

	// Authentication
	if c.Auth {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		// Gets the correct user for this request.
		username, password, ok := r.BasicAuth()
		zap.L().Info("req", zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.Bool("auth", ok), zap.String("username", username))
		if !ok {
			http.Error(w, "Not authorized", 401)
			return
		}
		// zap.L().Info("login attempt", zap.String("username", username), zap.String("remote_address", r.RemoteAddr))
		if username != "" && username != "anonymous" {
			user, ok := c.Users[username]
			if !ok {
				http.Error(w, "Not authorized", 401)
				return
			}

			if !checkPassword(user.Password, password) {
				zap.L().Info("invalid password", zap.String("username", username), zap.String("remote_address", r.RemoteAddr))
				http.Error(w, "Not authorized", 401)
				return
			}

			u = user
			// zap.L().Info("user authorized", zap.String("username", username))
		} else if !c.Anonymous {
			http.Error(w, "Not authorized", 401)
			return
		}
	} else {
		// Even if Auth is disabled, we might want to get
		// the user from the Basic Auth header. Useful for Caddy
		// plugin implementation.
		username, _, ok := r.BasicAuth()
		if ok {
			if user, ok := c.Users[username]; ok {
				u = user
			}
		}
	}

	// Checks for user permissions relatively to this PATH.
	noModification := r.Method == "GET" || r.Method == "HEAD" ||
		r.Method == "OPTIONS" || r.Method == "PROPFIND" || r.Method == "COPY"

	allowed := u.Allowed(r.URL.Path, noModification)

	if allowed && r.Method == "COPY" || r.Method == "MOVE" {
		dest := r.Header.Get("Destination")
		if dest == "" {
			allowed = false
		} else if r.URL.Path == dest || strings.HasPrefix(dest, r.URL.Path+"/") {
			zap.L().Info("deny copy/move", zap.String("method", r.Method), zap.String("src", r.URL.Path), zap.String("dest", dest))
			allowed = false
		} else {
			allowed = u.Allowed(dest, false)
		}
	}
	zap.L().Debug("allowed & method & path", zap.Bool("allowed", allowed), zap.String("method", r.Method), zap.String("path", r.URL.Path))

	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.Method == "HEAD" {
		w = newResponseWriterNoBody(w)
	}

	// RFC4918, section 9.4:
	//
	// 		GET, when applied to a collection, may return the contents of an
	//		"index.html" resource, a human-readable view of the contents of
	//		the collection, or something else altogether.
	//
	if r.Method == "GET" && handleDirList(u.Handler.FileSystem, c.GetBlackList, w, r) {
		return
	}

	// Runs the WebDAV.
	//u.Handler.LockSystem = webdav.NewMemLS()
	u.Handler.ServeHTTP(w, r)
}

// responseWriterNoBody is a wrapper used to suprress the body of the response
// to a request. Mainly used for HEAD requests.
type responseWriterNoBody struct {
	http.ResponseWriter
}

// newResponseWriterNoBody creates a new responseWriterNoBody.
func newResponseWriterNoBody(w http.ResponseWriter) *responseWriterNoBody {
	return &responseWriterNoBody{w}
}

// Header executes the Header method from the http.ResponseWriter.
func (w responseWriterNoBody) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write suprresses the body.
func (w responseWriterNoBody) Write(data []byte) (int, error) {
	return 0, nil
}

// WriteHeader writes the header to the http.ResponseWriter.
func (w responseWriterNoBody) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func contains(s []string, searchterm string) bool {
	i := sort.SearchStrings(s, searchterm)
	return i < len(s) && s[i] == searchterm
}

func handleDirList(fs webdav.FileSystem, blacklist []string, w http.ResponseWriter, req *http.Request) bool {
	ctx := context.Background()
	f, err := fs.OpenFile(ctx, req.URL.Path, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if fi, _ := f.Stat(); fi == nil || !fi.IsDir() {
		return false
	}
	if !strings.HasSuffix(req.URL.Path, "/") {
		http.Redirect(w, req, req.URL.Path+"/", 302)
		return true
	}
	dirs, err := f.Readdir(-1)
	if err != nil {
		log.Print(w, "Error reading directory", http.StatusInternalServerError)
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")
	if req.URL.Path != "/" {
		fmt.Fprintf(w, "<a href=\"../\">..</a>/\n")
	}
	for _, d := range dirs {
		name := d.Name()
		if strings.HasPrefix(name, "._") || contains(blacklist, name) {
			continue
		}
		suffix := ""
		link := name
		if d.IsDir() {
			link += "/"
			suffix = "/"
		}
		if (d.Mode() & os.ModeSymlink) == os.ModeSymlink {
			suffix = "@"
		}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>%s\n", link, name, suffix)
	}
	fmt.Fprintf(w, "</pre>\n")
	return true
}
