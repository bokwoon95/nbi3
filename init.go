package nbi3

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

//go:embed embed static
var embedFS embed.FS

// dev_mode.go overwrites these variables if the "dev" build tag is provided.
var (
	// runtimeFS is the FS containing the runtime files needed by notebrew for
	// operation. It switches between embedFS or the repo files depending on
	// whether devMode is enabled.
	runtimeFS fs.FS = embedFS

	// devMode is true if developer mode is enabled.
	devMode = false
)

// Globally-accessible templates.
var (
	// base templates are included in every template.
	baseTemplatePaths = []string{"embed/icons.html", "embed/base.html"}
	// templateMap is a global map of templates keyed by name.
	templateMap = map[string]*template.Template{}
	// funcMap contains all functions that templates use.
	funcMap = map[string]any{
		"join":                  path.Join,
		"dir":                   path.Dir,
		"base":                  path.Base,
		"ext":                   path.Ext,
		"hasPrefix":             strings.HasPrefix,
		"hasSuffix":             strings.HasSuffix,
		"trimPrefix":            strings.TrimPrefix,
		"trimSuffix":            strings.TrimSuffix,
		"contains":              strings.Contains,
		"joinStrings":           strings.Join,
		"toLower":               strings.ToLower,
		"toUpper":               strings.ToUpper,
		"humanReadableFileSize": HumanReadableFileSize,
		"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
		"float64ToInt64":        func(n float64) int64 { return int64(n) },
		"incr":                  func(n int) int { return n + 1 },
		"formatTime": func(t time.Time, layout string, offset int) string {
			return t.In(time.FixedZone("", offset)).Format(layout)
		},
		"formatTimezone": func(offset int) string {
			sign := "+"
			seconds := offset
			if offset < 0 {
				sign = "-"
				seconds = -offset
			}
			hours := seconds / 3600
			minutes := (seconds % 3600) / 60
			return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
		},
		"head": func(s string) string {
			head, _, _ := strings.Cut(s, "/")
			return head
		},
		"tail": func(s string) string {
			_, tail, _ := strings.Cut(s, "/")
			return tail
		},
		"jsonArray": func(s []string) (string, error) {
			b, err := json.Marshal(s)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	}
)

func init() {
	matches, err := fs.Glob(embedFS, "embed/*.html")
	if err != nil {
		panic(err)
	}
	for _, match := range matches {
		tmpl := template.New(path.Base(match))
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(embedFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(embedFS, match))
		templateMap[path.Base(match)] = tmpl
	}
}

// Content and hash of static/notebrew.min.css.
var (
	notebrewCSS     string
	notebrewCSSHash string
)

func init() {
	b, err := fs.ReadFile(embedFS, "static/notebrew.min.css")
	if err != nil {
		panic(err)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(b)
	notebrewCSS = string(b)
	notebrewCSSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
}

// Content and hash of static/notebrew.min.js.
var (
	notebrewJS     string
	notebrewJSHash string
)

func init() {
	b, err := fs.ReadFile(embedFS, "static/notebrew.min.js")
	if err != nil {
		panic(err)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(b)
	notebrewJS = string(b)
	notebrewJSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
}

// commonPasswords is a set of the top 10,000 most common passwords from
// top_10000_passwords.txt in the embed/ directory.
var commonPasswords = make(map[string]struct{})

func init() {
	file, err := embedFS.Open("embed/top_10000_passwords.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		commonPasswords[string(line)] = struct{}{}
	}
}

// countryCodes is the ISO code to country mapping from country_codes.json
// in the embed/ directory.
var countryCodes map[string]string

func init() {
	file, err := embedFS.Open("embed/country_codes.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	err = json.NewDecoder(file).Decode(&countryCodes)
	if err != nil {
		panic(err)
	}
}

// HumanReadableFileSize returns a human readable file size of an int64 size in
// bytes.
func HumanReadableFileSize(size int64) string {
	// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	if size < 0 {
		return ""
	}
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "kMGTPE"[exp])
}
