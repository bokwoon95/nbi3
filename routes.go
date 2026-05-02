package nbi3

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nbi3/sq"
	"github.com/bokwoon95/nbi3/stacktrace"
	"golang.org/x/crypto/blake2b"
)

var urlFileExts = map[string]struct{}{
	".html": {}, ".css": {}, ".js": {}, ".txt": {}, ".json": {}, ".xml": {},
	".jpeg": {}, ".jpg": {}, ".png": {}, ".webp": {}, ".gif": {}, ".svg": {},
	".mp4": {}, ".mov": {}, ".webm": {},
	".tgz": {},
}

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}
	// Redirect the www subdomain to the bare domain.
	if r.Host == "www."+nbrew.CMSDomain {
		http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}
	// Redirect unclean paths to the clean path equivalent.
	urlPath := path.Clean(r.URL.Path)
	if urlPath != "/" {
		if _, ok := urlFileExts[path.Ext(urlPath)]; !ok {
			urlPath += "/"
		}
	}
	if urlPath != r.URL.Path {
		if r.Method == "GET" || r.Method == "HEAD" {
			uri := *r.URL
			uri.Path = urlPath
			http.Redirect(w, r, uri.String(), http.StatusMovedPermanently)
			return
		}
	}
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "camera=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "credentialless")
	w.Header().Add("Cross-Origin-Resource-Policy", "cross-origin")
	if nbrew.CMSDomainHTTPS {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
	contextData := ContextData{
		CDNDomain:   nbrew.CDNDomain,
		DevMode:     devMode,
		NotebrewCSS: template.CSS(notebrewCSS),
		NotebrewJS:  template.JS(notebrewJS),
		URLPath:     urlPath,
		Logger: nbrew.Logger.With(
			slog.String("method", r.Method),
			slog.String("url", scheme+r.Host+r.URL.RequestURI()),
		),
	}
	referer := r.Referer()
	if referer != "" {
		uri := *r.URL
		uri.Scheme = scheme
		uri.Host = r.Host
		uri.Fragment = ""
		uri.User = nil
		if referer != uri.String() {
			contextData.Referer = referer
		}
	}
	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, contextData, err)
		return
	}
	var sessionToken string
	header := r.Header.Get("Authorization")
	if header != "" {
		sessionToken = strings.TrimPrefix(header, "Bearer ")
	} else {
		cookie, _ := r.Cookie("session")
		if cookie != nil {
			sessionToken = cookie.Value
		}
	}
	var user User
	if sessionToken != "" {
		sessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", sessionToken))
		if err == nil && len(sessionTokenBytes) == 24 {
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionTokenBytes[8:])
			copy(sessionTokenHash[:8], sessionTokenBytes[:8])
			copy(sessionTokenHash[8:], checksum[:])
			user, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM session" +
					" JOIN users ON users.user_id = session.user_id" +
					" WHERE session.session_token_hash = {sessionTokenHash}",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				},
			}, func(row *sq.Row) User {
				user := User{
					UserID:                row.UUID("users.user_id"),
					Username:              row.String("users.username"),
					Email:                 row.String("users.email"),
					TimezoneOffsetSeconds: row.Int("users.timezone_offset_seconds"),
					DisableReason:         row.String("users.disable_reason"),
					SiteLimit:             row.Int64("coalesce(users.site_limit, -1)"),
					StorageLimit:          row.Int64("coalesce(users.storage_limit, -1)"),
				}
				b := row.Bytes(nil, "users.user_flags")
				if len(b) > 0 {
					err := json.Unmarshal(b, &user.UserFlags)
					if err != nil {
						panic(stacktrace.New(err))
					}
				}
				return user
			})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					contextData.Logger.Error(err.Error())
					nbrew.InternalServerError(w, r, contextData, err)
					return
				}
			}
			contextData.UserID = user.UserID
			contextData.Username = user.Username
			contextData.DisableReason = user.DisableReason
			contextData.UserFlags = user.UserFlags
		}
	}
	pathHead, pathTail, _ := strings.Cut(strings.Trim(urlPath, "/"), "/")
	contextData.PathTail = pathTail
	switch pathHead {
	case "static":
		if pathTail == "" {
			nbrew.NotFound(w, r, contextData)
			return
		}
		http.ServeFileFS(w, r, runtimeFS, urlPath)
		return
	case "login":
		// nbrew.login(w, r, contextData)
		return
	case "logout":
		if pathTail != "" {
			nbrew.NotFound(w, r, contextData)
			return
		}
		// nbrew.logout(w, r, contextData) // TODO
		return
	case "resetpassword":
		if pathTail != "" {
			nbrew.NotFound(w, r, contextData)
			return
		}
		// nbrew.resetpassword(w, r, contextData) // TODO
		return
	case "invite":
		if pathTail != "" {
			nbrew.NotFound(w, r, contextData)
			return
		}
		// nbrew.invite(w, r, contextData) // TODO
		return
	}
	if contextData.UserID.IsZero() {
		nbrew.NotAuthenticated(w, r, contextData)
		return
	}
	switch pathHead {
	case "":
		nbrew.NotFound(w, r, contextData)
		return
	case "notes":
		// nbrew.notes(w, r, contextData)
		return
	case "photos":
		// nbrew.photos(w, r, contextData) // TODO
		nbrew.NotFound(w, r, contextData)
		return
	case "blogs":
		nbrew.NotFound(w, r, contextData)
		return
	default:
		nbrew.NotFound(w, r, contextData)
		return
	}
}
