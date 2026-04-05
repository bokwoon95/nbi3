package nbi3

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bokwoon95/nbi3/godaddy"
	"github.com/bokwoon95/nbi3/namecheap"
	"github.com/bokwoon95/nbi3/stacktrace"
	"github.com/bokwoon95/sqddl/ddl"
	"github.com/caddyserver/certmagic"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/libdns/porkbun"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

// If a buffer's capacity exceeds this value, don't put it back in the pool
// because it's too expensive to keep it around in memory.
//
// From https://victoriametrics.com/blog/tsdb-performance-techniques-sync-pool/
//
// "The maximum capacity of a cached pool is limited to 2^18 bytes as we’ve
// found that the RAM cost of storing buffers larger than this limit is not
// worth the savings of not recreating those buffers."
const maxPoolableBufferCapacity = 1 << 18

var bufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

// Notebrew represents a notebrew instance.
type Notebrew struct {
	// DB is the DB associated with the notebrew instance.
	DB *sql.DB

	// Dialect is Dialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	Dialect string

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, ErrorCode should return an empty string.
	ErrorCode func(error) string

	// ObjectStorage is used for storage of binary objects.
	ObjectStorage ObjectStorage

	// CMSDomain is the domain that the notebrew is using to serve the CMS.
	// Examples: localhost, notebrew.com
	CMSDomain string

	// CMSDomainHTTPS indicates whether the CMS domain is currently being
	// served over HTTPS.
	CMSDomainHTTPS bool

	// ContentDomain is the domain that the notebrew instance is using to serve
	// the static generated content. Examples: localhost, nbrew.net.
	ContentDomain string

	// ContentDomainHTTPS indicates whether the content domain is currently
	// being served over HTTPS.
	ContentDomainHTTPS bool

	// CDNDomain is the domain of the CDN that notebrew is using to host its
	// images. Examples: cdn.nbrew.net, nbrewcdn.net.
	CDNDomain string

	// LossyImgCmd is the command (must reside in $PATH) used to preprocess
	// images in a lossy way for the web before they are saved to the FS.
	// Images in the notes folder are never preprocessed and are uploaded
	// as-is. This serves as an a escape hatch for users who wish to upload
	// their images without any lossy image preprocessing, as they can upload
	// images to the notes folder first before moving it elsewhere.
	//
	// LossyImgCmd should take in arguments in the form of `<LossyImgCmd>
	// $INPUT_PATH $OUTPUT_PATH`, where $INPUT_PATH is the input path to the
	// raw image and $OUTPUT_PATH is output path where LossyImgCmd should save
	// the preprocessed image.
	LossyImgCmd string

	// VideoCmd is the command (must reside in $PATH) used to preprocess videos
	// in a lossless way for the web before they are saved to the FS.
	//
	// VideoCmd should take in arguments in the form of `<VideoCmd> $INPUT_PATH
	// $OUTPUT_PATH`, where $INPUT_PATH is the input path to the raw video and
	// $OUTPUT_PATH is output path where VideoCmd should save the preprocessed
	// video.
	VideoCmd string

	// (Required) Port is port that notebrew is listening on.
	Port int

	// InboundIP4 is the IPv4 address of the current machine, if notebrew is currently
	// serving either port 80 (HTTP) or 443 (HTTPS).
	InboundIP4 netip.Addr

	// InboundIP6 is the IPv6 address of the current machine, if notebrew is currently
	// serving either port 80 (HTTP) or 443 (HTTPS).
	InboundIP6 netip.Addr

	OutboundIP4 netip.Addr

	OutboundIP6 netip.Addr

	// Domains is the list of domains that need to point at notebrew for it to
	// work. Does not include user-created domains.
	Domains []string

	// ManagingDomains is the list of domains that the current instance of
	// notebrew is managing SSL certificates for.
	ManagingDomains []string

	// Captcha configuration.
	CaptchaConfig struct {
		// Captcha widget's script src. e.g. https://js.hcaptcha.com/1/api.js,
		// https://challenges.cloudflare.com/turnstile/v0/api.js
		WidgetScriptSrc template.URL

		// Captcha widget's container div class. e.g. h-captcha, cf-turnstile
		WidgetClass string

		// Captcha verification URL to make POST requests to. e.g.
		// https://api.hcaptcha.com/siteverify,
		// https://challenges.cloudflare.com/turnstile/v0/siteverify
		VerificationURL string

		// Captcha response token name. e.g. h-captcha-response,
		// cf-turnstile-response
		ResponseTokenName string

		// Captcha site key.
		SiteKey string

		// Captcha secret key.
		SecretKey string

		// CSP contains the Content-Security-Policy directive names and values
		// required for the captcha widget to work.
		CSP map[string]string
	}

	// Mailer is used to send out transactional emails e.g. password reset
	// emails.
	Mailer *Mailer

	// The default value for the SMTP MAIL FROM instruction.
	MailFrom string

	// The default value for the SMTP Reply-To header.
	ReplyTo string

	// Proxy configuration.
	ProxyConfig struct {
		// RealIPHeaders contains trusted IP addresses to HTTP headers that
		// they are known to populate the real client IP with. e.g. X-Real-IP,
		// True-Client-IP.
		RealIPHeaders map[netip.Addr]string

		// Contains the set of trusted proxy IP addresses. This is used when
		// resolving the real client IP from the X-Forwarded-For HTTP header
		// chain from right (most trusted) to left (most accurate).
		ProxyIPs map[netip.Addr]struct{}
	}

	// DNS provider (required for using wildcard certificates with
	// LetsEncrypt).
	DNSProvider interface {
		libdns.RecordAppender
		libdns.RecordDeleter
		libdns.RecordGetter
		libdns.RecordSetter
	}

	// CertStorage is the magic (certmagic) that automatically provisions SSL
	// certificates for notebrew.
	CertStorage certmagic.Storage

	// CertLogger is the logger used for a certmagic.Config.
	CertLogger *zap.Logger

	// ContentSecurityPolicy is the Content-Security-Policy HTTP header set for
	// every HTML response served on the CMS domain.
	ContentSecurityPolicy string

	// Logger is used for reporting errors that cannot be handled and are
	// thrown away.
	Logger *slog.Logger

	// MaxMindDBReader is the maxmind database reader used to reolve IP
	// addresses to their countries using a maxmind GeoIP database.
	MaxMindDBReader *maxminddb.Reader

	// Monitoring configuration.
	MonitoringConfig struct {
		// Email address to notify for errors.
		Email string
	}

	// BackgroundContext is the background context of the notebrew instance.
	BackgroundContext context.Context

	// backgroundCancel cancels the background context.
	backgroundCancel func()

	// BackgroundWaitGroup tracks the number of background jobs spawned by the
	// notebrew instance. Each background job should take in the background
	// context, and should should initiate shutdown when the background context
	// is canceled.
	BackgroundWaitGroup sync.WaitGroup

	Modules []Module
}

// New returns a new instance of Notebrew. Each field within it still needs to
// be manually configured.
func New(configDir, dataDir string, csp map[string]string) (*Notebrew, error) {
	backgroundContext, backgroundCancel := context.WithCancel(context.Background())
	nbrew := &Notebrew{
		BackgroundContext: backgroundContext,
		backgroundCancel:  backgroundCancel,
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: true,
		})),
	}

	// CMS domain.
	b, err := os.ReadFile(filepath.Join(configDir, "cmsdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "cmsdomain.txt"), err)
	}
	nbrew.CMSDomain = string(bytes.TrimSpace(b))
	if nbrew.CMSDomain == "0.0.0.0" {
		// OutboundIP4 and OutboundIP6.
		var dialer net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() error {
			conn, err := dialer.DialContext(groupctx, "udp", "8.8.8.8:80" /* Google IPv4 DNS */)
			if err != nil {
				return fmt.Errorf("udp 8.8.8.8:80: %w", err)
			}
			defer conn.Close()
			udpAddr := conn.LocalAddr().(*net.UDPAddr)
			ip, _ := netip.AddrFromSlice(udpAddr.IP)
			if ip.Is4() {
				nbrew.OutboundIP4 = ip
			}
			return nil
		})
		group.Go(func() error {
			conn, err := dialer.DialContext(groupctx, "udp6", "[2001:4860:4860::8888]:80" /* Google IPv6 DNS */)
			if err != nil {
				// Best-effort attempt to get an IPv6 address; we won't always
				// have an IPv6 address e.g. when computer is using a phone's
				// data hotspot.
				return nil
			}
			defer conn.Close()
			udpAddr := conn.LocalAddr().(*net.UDPAddr)
			ip, _ := netip.AddrFromSlice(udpAddr.IP)
			if ip.Is6() {
				nbrew.OutboundIP6 = ip
			}
			return nil
		})
		err := group.Wait()
		if err != nil {
			return nil, err
		}
		if !nbrew.OutboundIP4.IsValid() && !nbrew.OutboundIP6.IsValid() {
			return nil, fmt.Errorf("unable to determine the outbound IP address of the current machine")
		}
	}

	// Content domain.
	b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
	}
	nbrew.ContentDomain = string(bytes.TrimSpace(b))

	// CDN domain.
	b, err = os.ReadFile(filepath.Join(configDir, "cdndomain.txt"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "cdndomain.txt"), err)
		}
	} else {
		nbrew.CDNDomain = string(bytes.TrimSpace(b))
	}

	// MaxMind DB reader.
	b, err = os.ReadFile(filepath.Join(configDir, "maxminddb.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "maxminddb.txt"), err)
	}
	maxMindDBFilePath := string(bytes.TrimSpace(b))
	if maxMindDBFilePath != "" {
		_, err = os.Stat(maxMindDBFilePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%s: %s does not exist", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath)
			}
			return nil, fmt.Errorf("%s: %s: %w", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath, err)
		}
		maxmindDBReader, err := maxminddb.Open(maxMindDBFilePath)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath, err)
		}
		nbrew.MaxMindDBReader = maxmindDBReader
	}

	// Port.
	b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
	}
	port := string(bytes.TrimSpace(b))

	// Fill in the port and CMS domain if missing.
	if port != "" {
		nbrew.Port, err = strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a valid integer", filepath.Join(configDir, "port.txt"), port)
		}
		if nbrew.Port <= 0 {
			return nil, fmt.Errorf("%s: %d is not a valid port", filepath.Join(configDir, "port.txt"), nbrew.Port)
		}
		if nbrew.CMSDomain == "" {
			switch nbrew.Port {
			case 443:
				return nil, fmt.Errorf("%s: cannot use port 443 without specifying the cmsdomain", filepath.Join(configDir, "port.txt"))
			case 80:
				break // Use IP address as domain when we find it later.
			default:
				nbrew.CMSDomain = "localhost:" + port
			}
		}
	} else {
		if nbrew.CMSDomain != "" {
			if nbrew.CMSDomain == "0.0.0.0" {
				nbrew.Port = 6444
			} else {
				nbrew.Port = 443
			}
		} else {
			nbrew.Port = 6444
			nbrew.CMSDomain = "localhost"
		}
	}

	if nbrew.Port == 443 || nbrew.Port == 80 {
		// InboundIP4 and InboundIP6.
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		group, groupctx := errgroup.WithContext(context.Background())
		group.Go(func() error {
			request, err := http.NewRequest("GET", "https://ipv4.icanhazip.com", nil)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			response, err := client.Do(request.WithContext(groupctx))
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			defer response.Body.Close()
			var b strings.Builder
			_, err = io.Copy(&b, response.Body)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			err = response.Body.Close()
			if err != nil {
				return err
			}
			s := strings.TrimSpace(b.String())
			if s == "" {
				return nil
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: did not get a valid IP address (%s)", s)
			}
			if ip.Is4() {
				nbrew.InboundIP4 = ip
			}
			return nil
		})
		group.Go(func() error {
			request, err := http.NewRequest("GET", "https://ipv6.icanhazip.com", nil)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			response, err := client.Do(request.WithContext(groupctx))
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			defer response.Body.Close()
			var b strings.Builder
			_, err = io.Copy(&b, response.Body)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			err = response.Body.Close()
			if err != nil {
				return err
			}
			s := strings.TrimSpace(b.String())
			if s == "" {
				return nil
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: did not get a valid IP address (%s)", s)
			}
			if ip.Is6() {
				nbrew.InboundIP6 = ip
			}
			return nil
		})
		err := group.Wait()
		if err != nil {
			return nil, err
		}
		if !nbrew.InboundIP4.IsValid() && !nbrew.InboundIP6.IsValid() {
			return nil, fmt.Errorf("unable to determine the inbound IP address of the current machine")
		}
		if nbrew.CMSDomain == "" {
			if nbrew.InboundIP4.IsValid() {
				nbrew.CMSDomain = nbrew.InboundIP4.String()
			} else {
				nbrew.CMSDomain = "[" + nbrew.InboundIP6.String() + "]"
			}
		}
	}
	if nbrew.ContentDomain == "" {
		nbrew.ContentDomain = nbrew.CMSDomain
	}

	// DNS.
	b, err = os.ReadFile(filepath.Join(configDir, "dns.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
	}
	b = bytes.TrimSpace(b)
	var dnsConfig DNSConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&dnsConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
		}
	}
	switch dnsConfig.Provider {
	case "":
		break
	case "namecheap":
		if dnsConfig.Username == "" {
			return nil, fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.APIKey == "" {
			return nil, fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if !nbrew.InboundIP4.IsValid() && (nbrew.Port == 443 || nbrew.Port == 80) {
			return nil, fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", nbrew.InboundIP6.String())
		}
		nbrew.DNSProvider = &namecheap.Provider{
			APIKey:      dnsConfig.APIKey,
			User:        dnsConfig.Username,
			APIEndpoint: "https://api.namecheap.com/xml.response",
			ClientIP:    nbrew.InboundIP4.String(),
		}
	case "cloudflare":
		if dnsConfig.APIToken == "" {
			return nil, fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &cloudflare.Provider{
			APIToken: dnsConfig.APIToken,
		}
	case "porkbun":
		if dnsConfig.APIKey == "" {
			return nil, fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.SecretKey == "" {
			return nil, fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &porkbun.Provider{
			APIKey:       dnsConfig.APIKey,
			APISecretKey: dnsConfig.SecretKey,
		}
	case "godaddy":
		if dnsConfig.APIToken == "" {
			return nil, fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &godaddy.Provider{
			APIToken: dnsConfig.APIToken,
		}
	default:
		return nil, fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configDir, "dns.json"), dnsConfig.Provider)
	}

	// If CMSDomain is not an IP address, add it to the Domains list.
	_, err = netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.CMSDomain, "["), "]"))
	if err != nil {
		nbrew.Domains = append(nbrew.Domains, nbrew.CMSDomain, "www."+nbrew.CMSDomain)
		nbrew.CMSDomainHTTPS = !strings.HasPrefix(nbrew.CMSDomain, "localhost:") && nbrew.Port != 80
	}
	// If ContentDomain is not an IP address, add it to the Domains list.
	_, err = netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.ContentDomain, "["), "]"))
	if err != nil {
		if nbrew.ContentDomain == nbrew.CMSDomain {
			nbrew.Domains = append(nbrew.Domains, "cdn."+nbrew.ContentDomain, "storage."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = nbrew.CMSDomainHTTPS
		} else {
			nbrew.Domains = append(nbrew.Domains, nbrew.ContentDomain, "www."+nbrew.ContentDomain, "cdn."+nbrew.ContentDomain, "storage."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = !strings.HasPrefix(nbrew.ContentDomain, "localhost:")
		}
	}

	// Database.
	b, err = os.ReadFile(filepath.Join(configDir, "database.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
	}
	b = bytes.TrimSpace(b)
	var databaseConfig DatabaseConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&databaseConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
		}
	}
	var dataSourceName string
	switch databaseConfig.Dialect {
	case "", "sqlite":
		if databaseConfig.SQLiteFilePath == "" {
			databaseConfig.SQLiteFilePath = filepath.Join(dataDir, "notebrew-database.db")
		}
		databaseConfig.SQLiteFilePath, err = filepath.Abs(databaseConfig.SQLiteFilePath)
		if err != nil {
			return nil, fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "database.json"), err)
		}
		dataSourceName = databaseConfig.SQLiteFilePath + "?" + sqliteQueryString(databaseConfig.Params)
		nbrew.Dialect = "sqlite"
		nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
		if err != nil {
			return nil, fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
		}
		nbrew.ErrorCode = sqliteErrorCode
	case "postgres":
		values := make(url.Values)
		for key, value := range databaseConfig.Params {
			switch key {
			case "sslmode":
				values.Set(key, value)
			}
		}
		if _, ok := databaseConfig.Params["sslmode"]; !ok {
			values.Set("sslmode", "disable")
		}
		if databaseConfig.Port == "" {
			databaseConfig.Port = "5432"
		}
		uri := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword(databaseConfig.User, databaseConfig.Password),
			Host:     databaseConfig.Host + ":" + databaseConfig.Port,
			Path:     databaseConfig.DBName,
			RawQuery: values.Encode(),
		}
		dataSourceName = uri.String()
		nbrew.Dialect = "postgres"
		nbrew.DB, err = sql.Open("pgx", dataSourceName)
		if err != nil {
			return nil, fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
		}
		nbrew.ErrorCode = func(err error) string {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				return pgErr.Code
			}
			return ""
		}
	case "mysql":
		values := make(url.Values)
		for key, value := range databaseConfig.Params {
			switch key {
			case "charset", "collation", "loc", "maxAllowedPacket",
				"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
				"tls", "writeTimeout", "connectionAttributes":
				values.Set(key, value)
			}
		}
		values.Set("multiStatements", "true")
		values.Set("parseTime", "true")
		if databaseConfig.Port == "" {
			databaseConfig.Port = "3306"
		}
		config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", databaseConfig.Host, databaseConfig.Port, url.PathEscape(databaseConfig.DBName), values.Encode()))
		if err != nil {
			return nil, err
		}
		// Set user and passwd manually to accomodate special characters.
		// https://github.com/go-sql-driver/mysql/issues/1323
		config.User = databaseConfig.User
		config.Passwd = databaseConfig.Password
		driver, err := mysql.NewConnector(config)
		if err != nil {
			return nil, err
		}
		dataSourceName = config.FormatDSN()
		nbrew.Dialect = "mysql"
		nbrew.DB = sql.OpenDB(driver)
		nbrew.ErrorCode = func(err error) string {
			var mysqlErr *mysql.MySQLError
			if errors.As(err, &mysqlErr) {
				return strconv.FormatUint(uint64(mysqlErr.Number), 10)
			}
			return ""
		}
	default:
		return nil, fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), databaseConfig.Dialect)
	}
	err = nbrew.DB.Ping()
	if err != nil {
		return nil, fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "database.json"), nbrew.Dialect, dataSourceName, err)
	}
	if databaseConfig.MaxOpenConns > 0 {
		nbrew.DB.SetMaxOpenConns(databaseConfig.MaxOpenConns)
	}
	if databaseConfig.MaxIdleConns > 0 {
		nbrew.DB.SetMaxIdleConns(databaseConfig.MaxIdleConns)
	}
	if databaseConfig.ConnMaxLifetime != "" {
		duration, err := time.ParseDuration(databaseConfig.ConnMaxLifetime)
		if err != nil {
			return nil, fmt.Errorf("%s: connMaxLifetime: %s: %w", filepath.Join(configDir, "database.json"), databaseConfig.ConnMaxLifetime, err)
		}
		nbrew.DB.SetConnMaxLifetime(duration)
	}
	if databaseConfig.ConnMaxIdleTime != "" {
		duration, err := time.ParseDuration(databaseConfig.ConnMaxIdleTime)
		if err != nil {
			return nil, fmt.Errorf("%s: connMaxIdleTime: %s: %w", filepath.Join(configDir, "database.json"), databaseConfig.ConnMaxIdleTime, err)
		}
		nbrew.DB.SetConnMaxIdleTime(duration)
	}
	databaseCatalog := &ddl.Catalog{
		Dialect: nbrew.Dialect,
	}
	err = unmarshalCatalog(databaseSchemaBytes, databaseCatalog)
	if err != nil {
		return nil, err
	}
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             nbrew.DB,
		Dialect:        nbrew.Dialect,
		DestCatalog:    databaseCatalog,
		AcceptWarnings: true,
		Stderr:         io.Discard,
	}
	err = automigrateCmd.Run()
	if err != nil {
		return nil, err
	}

	// Object Storage.
	b, err = os.ReadFile(filepath.Join(configDir, "objectstorage.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "objectstorage.json"), err)
	}
	b = bytes.TrimSpace(b)
	var objectstorageConfig ObjectstorageConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err = decoder.Decode(&objectstorageConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "objectstorage.json"), err)
		}
	}
	switch objectstorageConfig.Provider {
	case "", "directory":
		if objectstorageConfig.DirectoryPath == "" {
			objectstorageConfig.DirectoryPath = filepath.Join(dataDir, "notebrew-objectstorage")
		} else {
			objectstorageConfig.DirectoryPath = filepath.Clean(objectstorageConfig.DirectoryPath)
		}
		err := os.MkdirAll(objectstorageConfig.DirectoryPath, 0755)
		if err != nil {
			return nil, err
		}
		objectStorage, err := NewDirObjectStorage(objectstorageConfig.DirectoryPath, os.TempDir())
		if err != nil {
			return nil, err
		}
		nbrew.ObjectStorage = objectStorage
	case "s3":
		if objectstorageConfig.Endpoint == "" {
			return nil, fmt.Errorf("%s: missing endpoint field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.Region == "" {
			return nil, fmt.Errorf("%s: missing region field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.Bucket == "" {
			return nil, fmt.Errorf("%s: missing bucket field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.AccessKeyID == "" {
			return nil, fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.SecretAccessKey == "" {
			return nil, fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configDir, "objectstorage.json"))
		}
		contentTypeMap := map[string]string{
			".jpeg": "image/jpeg",
			".jpg":  "image/jpeg",
			".png":  "image/png",
			".webp": "image/webp",
			".gif":  "image/gif",
			".mp4":  "video/mp4",
			".mov":  "video/mp4",
			".webm": "video/webm",
			".tgz":  "application/octet-stream",
		}
		objectStorage, err := NewS3Storage(context.Background(), S3StorageConfig{
			Endpoint:        objectstorageConfig.Endpoint,
			Region:          objectstorageConfig.Region,
			Bucket:          objectstorageConfig.Bucket,
			AccessKeyID:     objectstorageConfig.AccessKeyID,
			SecretAccessKey: objectstorageConfig.SecretAccessKey,
			ContentTypeMap:  contentTypeMap,
			Logger:          nbrew.Logger,
		})
		if err != nil {
			return nil, err
		}
		nbrew.ObjectStorage = objectStorage
	default:
		return nil, fmt.Errorf("%s: unsupported provider %q (possible values: directory, s3)", filepath.Join(configDir, "objectstorage.json"), objectstorageConfig.Provider)
	}

	// Certmagic.
	b, err = os.ReadFile(filepath.Join(configDir, "certmagic.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.json"), err)
	}
	b = bytes.TrimSpace(b)
	var certmagicConfig CertmagicConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&certmagicConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.json"), err)
		}
	}
	switch certmagicConfig.Provider {
	case "database": // TODO: Once CertDatabaseStorage is implemented, make it the default instead.
		nbrew.CertStorage = &CertDatabaseStorage{
			DB:        nbrew.DB,
			Dialect:   nbrew.Dialect,
			ErrorCode: nbrew.ErrorCode,
		}
	case "", "directory":
		if certmagicConfig.DirectoryPath == "" {
			certmagicConfig.DirectoryPath = filepath.Join(configDir, "certmagic")
		}
		err = os.MkdirAll(certmagicConfig.DirectoryPath, 0755)
		if err != nil {
			return nil, err
		}
		nbrew.CertStorage = &certmagic.FileStorage{
			Path: certmagicConfig.DirectoryPath,
		}
	}
	if certmagicConfig.TerseLogger {
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
		terseLogger := zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			os.Stderr,
			zap.ErrorLevel,
		))
		nbrew.CertLogger = terseLogger
		certmagic.Default.Logger = terseLogger
		certmagic.DefaultACME.Logger = terseLogger
	} else {
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
		verboseLogger := zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			os.Stderr,
			zap.InfoLevel,
		))
		nbrew.CertLogger = verboseLogger
		certmagic.Default.Logger = verboseLogger
		certmagic.DefaultACME.Logger = verboseLogger
	}

	if nbrew.Port == 443 || nbrew.Port == 80 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		group, groupctx := errgroup.WithContext(ctx)
		matched := make([]bool, len(nbrew.Domains))
		for i, domain := range nbrew.Domains {
			group.Go(func() error {
				_, err := netip.ParseAddr(domain)
				if err == nil {
					return nil
				}
				ips, err := net.DefaultResolver.LookupIPAddr(groupctx, domain)
				if err != nil {
					fmt.Println(err)
					return nil
				}
				for _, ip := range ips {
					ip, ok := netip.AddrFromSlice(ip.IP)
					if !ok {
						continue
					}
					if ip.Is4() && ip == nbrew.InboundIP4 || ip.Is6() && ip == nbrew.InboundIP6 {
						matched[i] = true
						break
					}
				}
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			return nil, err
		}
		switch nbrew.Port {
		case 80:
			for i, domain := range nbrew.Domains {
				if matched[i] {
					nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
				}
			}
		case 443:
			addedCMSDomainWildcard := false
			addedContentDomainWildcard := false
			for i, domain := range nbrew.Domains {
				if matched[i] {
					if certmagic.MatchWildcard(domain, "*."+nbrew.CMSDomain) && nbrew.DNSProvider != nil {
						if !addedCMSDomainWildcard {
							addedCMSDomainWildcard = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, "*."+nbrew.CMSDomain)
						}
					} else if certmagic.MatchWildcard(domain, "*."+nbrew.ContentDomain) && nbrew.DNSProvider != nil {
						if !addedContentDomainWildcard {
							addedContentDomainWildcard = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, "*."+nbrew.ContentDomain)
						}
					} else {
						nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
					}
				}
			}
		}
	}

	// Captcha.
	b, err = os.ReadFile(filepath.Join(configDir, "captcha.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var captchaConfig CaptchaConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&captchaConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
		}
		nbrew.CaptchaConfig.WidgetScriptSrc = template.URL(captchaConfig.WidgetScriptSrc)
		nbrew.CaptchaConfig.WidgetClass = captchaConfig.WidgetClass
		nbrew.CaptchaConfig.VerificationURL = captchaConfig.VerificationURL
		nbrew.CaptchaConfig.ResponseTokenName = captchaConfig.ResponseTokenName
		nbrew.CaptchaConfig.SiteKey = captchaConfig.SiteKey
		nbrew.CaptchaConfig.SecretKey = captchaConfig.SecretKey
		nbrew.CaptchaConfig.CSP = captchaConfig.CSP
	}

	// SMTP.
	b, err = os.ReadFile(filepath.Join(configDir, "smtp.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var smtpConfig SMTPConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&smtpConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
		}
		if smtpConfig.Host != "" && smtpConfig.Port != "" && smtpConfig.Username != "" && smtpConfig.Password != "" {
			mailerConfig := MailerConfig{
				Username: smtpConfig.Username,
				Password: smtpConfig.Password,
				Host:     smtpConfig.Host,
				Port:     smtpConfig.Port,
				Logger:   nbrew.Logger,
			}
			nbrew.MailFrom = smtpConfig.MailFrom
			nbrew.ReplyTo = smtpConfig.ReplyTo
			if smtpConfig.LimitInterval == "" {
				mailerConfig.LimitInterval = 3 * time.Minute
			} else {
				limitInterval, err := time.ParseDuration(smtpConfig.LimitInterval)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
				}
				mailerConfig.LimitInterval = limitInterval
			}
			if smtpConfig.LimitBurst <= 0 {
				mailerConfig.LimitBurst = 20
			} else {
				mailerConfig.LimitBurst = smtpConfig.LimitBurst
			}
			mailer, err := NewMailer(mailerConfig)
			if err != nil {
				return nil, err
			}
			nbrew.Mailer = mailer
		}
	}

	// Proxy.
	b, err = os.ReadFile(filepath.Join(configDir, "proxy.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var proxyConfig ProxyConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
		}
		nbrew.ProxyConfig.RealIPHeaders = make(map[netip.Addr]string)
		for ip, header := range proxyConfig.RealIPHeaders {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("%s: realIPHeaders: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.RealIPHeaders[addr] = header
		}
		nbrew.ProxyConfig.ProxyIPs = make(map[netip.Addr]struct{})
		for _, ip := range proxyConfig.ProxyIPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("%s: proxyIPs: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.ProxyIPs[addr] = struct{}{}
		}
	}

	// Monitoring.
	b, err = os.ReadFile(filepath.Join(configDir, "monitoring.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "monitoring.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var monitoringConfig MonitoringConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&monitoringConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "monitoring.json"), err)
		}
		nbrew.MonitoringConfig.Email = monitoringConfig.Email
	}

	// Content Security Policy.
	var buf strings.Builder
	// default-src
	buf.WriteString("default-src 'none';")
	// script-src
	buf.WriteString(" script-src 'self' 'unsafe-hashes' " + notebrewJSHash)
	if value := csp["script-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["script-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// connect-src
	buf.WriteString(" connect-src 'self'")
	if value := csp["connect-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["connect-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// img-src
	buf.WriteString(" img-src 'self' data:")
	if value := csp["img-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if nbrew.CDNDomain != "" {
		buf.WriteString(" " + nbrew.CDNDomain)
	}
	buf.WriteString(";")
	// media-src
	buf.WriteString(" media-src 'self'")
	if value := csp["media-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if nbrew.CDNDomain != "" {
		buf.WriteString(" " + nbrew.CDNDomain)
	}
	buf.WriteString(";")
	// style-src
	buf.WriteString(" style-src 'self' 'unsafe-inline'")
	if value := csp["style-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["style-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// base-uri
	buf.WriteString(" base-uri 'self';")
	// form-action
	buf.WriteString(" form-action 'self'")
	if value := csp["form-action"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// manifest-src
	buf.WriteString(" manifest-src 'self';")
	// frame-src
	buf.WriteString(" frame-src 'self'")
	if value := csp["frame-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["frame-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// font-src
	buf.WriteString(" font-src 'self';")
	nbrew.ContentSecurityPolicy = buf.String()

	return nbrew, nil
}

// Close shuts down the notebrew instance as well as any background jobs it may
// have spawned.
func (nbrew *Notebrew) Close() error {
	nbrew.backgroundCancel()
	defer nbrew.BackgroundWaitGroup.Wait()
	var firstErr error
	if nbrew.Dialect == "sqlite" {
		_, err := nbrew.DB.Exec("PRAGMA optimize")
		if err != nil {
			firstErr = err
		}
	}
	if nbrew.Mailer != nil {
		err := nbrew.Mailer.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if nbrew.DB != nil {
		err := nbrew.DB.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if nbrew.MaxMindDBReader != nil {
		err := nbrew.MaxMindDBReader.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type ContextData struct {
	// == Application-level data == //
	CDNDomain   string       `json:"cdnDomain"`
	DevMode     bool         `json:"-"`
	NotebrewCSS template.CSS `json:"-"`
	NotebrewJS  template.JS  `json:"-"`
	// == Request-level data == //
	URLPath       string          `json:"urlPath"`
	PathTail      string          `json:"-"`
	UserID        ID              `json:"userID"`
	Username      string          `json:"username"`
	DisableReason string          `json:"disableReason"`
	UserFlags     map[string]bool `json:"userFlags"`
	Logger        *slog.Logger    `json:"-"`
	Referer       string          `json:"-"`
}

func (v ContextData) GoString() string {
	type ContextDataClone ContextData
	clone := ContextDataClone(v)
	if clone.NotebrewCSS != "" {
		clone.NotebrewCSS = template.CSS(fmt.Sprintf("<redacted len=%d>", len(clone.NotebrewCSS)))
	}
	if clone.NotebrewJS != "" {
		clone.NotebrewJS = template.JS(fmt.Sprintf("<redacted len=%d>", len(clone.NotebrewJS)))
	}
	return fmt.Sprintf("%#v", clone)
}

// User represents a user in the users table.
type User struct {
	// UserID uniquely identifies a user. It cannot be changed.
	UserID ID `json:"userID"`

	// Username uniquely identifies a user. It can be changed.
	Username string `json:"username"`

	// Email uniquely identifies a user. It can be changed.
	Email string `json:"email"`

	// TimezoneOffsetSeconds represents a user's preferred timezone offset in
	// seconds.
	TimezoneOffsetSeconds int `json:"timezoneOffsetSeconds"`

	// Is not empty, DisableReason is the reason why the user's account is
	// marked as disabled.
	DisableReason string `json:"disableReason"`

	// SiteLimit is the limit on the number of sites the user can create.
	SiteLimit int64 `json:"siteLimit"`

	// StorageLimit is the limit on the amount of storage the user can use.
	StorageLimit int64 `json:"storageLimit"`

	// UserFlags are various properties on a user that may be enabled or
	// disabled e.g. UploadImages.
	UserFlags map[string]bool `json:"userFlags"`
}

type ErrorTemplateData struct {
	ContextData ContextData
	Title       string
	Headline    string
	Byline      string
	Details     string
	Callers     []string
}

// BadRequest indicates that something was wrong with the request data.
func (nbrew *Notebrew) BadRequest(w http.ResponseWriter, r *http.Request, contextData ContextData, serverErr error) {
	var message string
	var maxBytesErr *http.MaxBytesError
	if errors.As(serverErr, &maxBytesErr) {
		message = "payload is too big (max " + HumanReadableFileSize(maxBytesErr.Limit) + ")"
	} else {
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			switch serverErr {
			case io.EOF:
				message = "missing JSON body"
			case io.ErrUnexpectedEOF:
				message = "malformed JSON"
			default:
				message = serverErr.Error()
			}
		} else {
			message = serverErr.Error()
		}
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "BadRequest",
			"message": message,
		})
		if err != nil {
			contextData.Logger.Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, &ErrorTemplateData{
		ContextData: contextData,
		Title:       "400 bad request",
		Headline:    "400 bad request",
		Byline:      message,
	})
	if err != nil {
		contextData.Logger.Error(err.Error())
		http.Error(w, "BadRequest: "+message, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusBadRequest)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotAuthenticated indicates that the user is not logged in.
func (nbrew *Notebrew) NotAuthenticated(w http.ResponseWriter, r *http.Request, contextData ContextData) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthenticated",
		})
		if err != nil {
			contextData.Logger.Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var query string
	if r.Method == "GET" {
		if r.URL.RawQuery != "" {
			query = "?redirect=" + url.QueryEscape(r.URL.Path+"?"+r.URL.RawQuery)
		} else {
			query = "?redirect=" + url.QueryEscape(r.URL.Path)
		}
	}
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, &ErrorTemplateData{
		ContextData: contextData,
		Title:       "401 unauthorized",
		Headline:    "401 unauthorized",
		Byline:      fmt.Sprintf("You are not authenticated, please <a href='/cms/login/%s' class='link'>log in</a>.", query),
	})
	if err != nil {
		contextData.Logger.Error(err.Error())
		http.Error(w, "NotAuthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotAuthorized indicates that the user is logged in, but is not authorized to
// view the current page or perform the current action.
func (nbrew *Notebrew) NotAuthorized(w http.ResponseWriter, r *http.Request, contextData ContextData) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthorized",
		})
		if err != nil {
			contextData.Logger.Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var byline string
	if r.Method == "GET" || r.Method == "HEAD" {
		byline = "You do not have permission to view this page (try logging in to a different account)."
	} else {
		byline = "You do not have permission to perform that action (try logging in to a different account)."
	}
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, &ErrorTemplateData{
		ContextData: contextData,
		Title:       "403 forbidden",
		Headline:    "403 forbidden",
		Byline:      byline,
	})
	if err != nil {
		contextData.Logger.Error(err.Error())
		http.Error(w, "NotAuthorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotFound indicates that a URL does not exist.
func (nbrew *Notebrew) NotFound(w http.ResponseWriter, r *http.Request, contextData ContextData) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotFound",
		})
		if err != nil {
			contextData.Logger.Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, &ErrorTemplateData{
		ContextData: contextData,
		Title:       "404 not found",
		Headline:    "404 not found",
		Byline:      "The page you are looking for does not exist.",
	})
	if err != nil {
		contextData.Logger.Error(err.Error())
		http.Error(w, "NotFound", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusNotFound)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// MethodNotAllowed indicates that the request method is not allowed.
func (nbrew *Notebrew) MethodNotAllowed(w http.ResponseWriter, r *http.Request, contextData ContextData) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":  "MethodNotAllowed",
			"method": r.Method,
		})
		if err != nil {
			contextData.Logger.Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, &ErrorTemplateData{
		ContextData: contextData,
		Title:       "405 method not allowed",
		Headline:    "405 method not allowed: " + r.Method,
	})
	if err != nil {
		contextData.Logger.Error(err.Error())
		http.Error(w, "NotFound", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusMethodNotAllowed)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// UnsupportedContentType indicates that the request did not send a supported
// Content-Type.
func (nbrew *Notebrew) UnsupportedContentType(w http.ResponseWriter, r *http.Request, contextData ContextData) {
	contentType := r.Header.Get("Content-Type")
	var message string
	if contentType == "" {
		message = "missing Content-Type"
	} else {
		message = "unsupported Content-Type: " + contentType
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"ContextData": contextData,
			"error":       "UnsupportedMediaType",
			"message":     message,
		})
		if err != nil {
			contextData.Logger.Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, &ErrorTemplateData{
		ContextData: contextData,
		Title:       "415 unsupported media type",
		Headline:    message,
	})
	if err != nil {
		contextData.Logger.Error(err.Error())
		http.Error(w, "UnsupportedMediaType "+message, http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnsupportedMediaType)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// InternalServerError is a catch-all handler for catching server errors and
// displaying it to the user.
//
// This includes the error message as well as the stack trace and notebrew
// version, in hopes that a user will be able to give developers the detailed
// error and trace in order to diagnose the problem faster.
func (nbrew *Notebrew) InternalServerError(w http.ResponseWriter, r *http.Request, contextData ContextData, serverErr error) {
	if serverErr == nil {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	var errmsg string
	var callers []string
	var stackTraceErr *stacktrace.Error
	if errors.As(serverErr, &stackTraceErr) {
		errmsg = stackTraceErr.Err.Error()
		callers = stackTraceErr.Callers
	} else {
		errmsg = serverErr.Error()
		var pc [30]uintptr
		n := runtime.Callers(2, pc[:]) // skip runtime.Callers + InternalServerError
		callers = make([]string, 0, n)
		frames := runtime.CallersFrames(pc[:n])
		for frame, more := frames.Next(); more; frame, more = frames.Next() {
			callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
		}
	}
	isDeadlineExceeded := errors.Is(serverErr, context.DeadlineExceeded)
	isCanceled := errors.Is(serverErr, context.Canceled)
	if nbrew.MonitoringConfig.Email != "" && nbrew.Mailer != nil && !isDeadlineExceeded && !isCanceled {
		nbrew.BackgroundWaitGroup.Add(1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fmt.Println(stacktrace.New(fmt.Errorf("panic: %v", v)))
				}
			}()
			defer nbrew.BackgroundWaitGroup.Done()
			var b strings.Builder
			b.WriteString(nbrew.CMSDomain + ": internal server error")
			b.WriteString("\r\n")
			b.WriteString("\r\n" + errmsg)
			b.WriteString("\r\n")
			b.WriteString("\r\nstack trace:")
			for _, caller := range callers {
				b.WriteString("\r\n" + caller)
			}
			b.WriteString("\r\n")
			mail := Mail{
				MailFrom: nbrew.MailFrom,
				RcptTo:   nbrew.MonitoringConfig.Email,
				Headers: []string{
					"Subject", "notebrew: " + nbrew.CMSDomain + ": internal server error: " + errmsg,
					"Content-Type", "text/plain; charset=utf-8",
				},
				Body: strings.NewReader(b.String()),
			}
			select {
			case <-nbrew.BackgroundContext.Done():
			case nbrew.Mailer.C <- mail:
			}
		}()
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "InternalServerError",
			"message": errmsg,
			"callers": callers,
		})
		if err != nil {
			contextData.Logger.Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	data := ErrorTemplateData{
		ContextData: contextData,
		Details:     errmsg,
		Callers:     callers,
	}
	if isDeadlineExceeded {
		data.Title = "deadline exceeded"
		data.Headline = "The server took too long to process your request."
	} else {
		data.Title = "500 internal server error"
		data.Headline = "500 internal server error"
		data.Byline = "There's a bug with notebrew."
	}
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, data)
	if err != nil {
		contextData.Logger.Error(err.Error())
		http.Error(w, "ServerError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusInternalServerError)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}
