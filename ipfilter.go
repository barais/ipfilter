package ipfilter

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

var (
	DBPublicURL = "http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz"
	DBTempPath  = filepath.Join(os.TempDir(), "ipfilter-GeoLite2-Country.mmdb.gz")
)

//Options for IPFilter. Allowed takes precendence over Blocked.
//IPs can be IPv4 or IPv6 and can optionally contain subnet
//masks (/24). Note however, determining if a given IP is
//included in a subnet requires a linear scan so is less performant
//than looking up single IPs.
//
//This could be improved with some algorithmic magic.
type Options struct {
	AllowedSchedule []*IPInterval
	//explicity allowed IPs
	AllowedIPs []string
	//explicity blocked IPs
	BlockedIPs []string
	//explicity allowed country ISO codes
	AllowedCountries []string
	//explicity blocked country ISO codes
	BlockedCountries []string
	//in-memory GeoLite2-Country.mmdb file,
	//if not provided falls back to IPDBPath
	IPDB []byte
	//path to GeoLite2-Country.mmdb[.gz] file,
	//if not provided defaults to ipfilter.DBTempPath
	IPDBPath string
	//disable automatic fetch of GeoLite2-Country.mmdb file
	//by default, when ipfilter.IPDBPath is not found,
	//ipfilter.IPDBFetchURL will be retrieved and stored at
	//ipfilter.IPDBPath, then loaded into memory (~19MB)
	IPDBNoFetch bool
	//URL of GeoLite2-Country.mmdb[.gz] file,
	//if not provided defaults to ipfilter.DBPublicURL
	IPDBFetchURL string
	//block by default (defaults to allow)
	BlockByDefault bool

	Logger interface {
		Printf(format string, v ...interface{})
	}
}

type IPInterval struct {
	Lower      *time.Time
	Upper      *time.Time
	AllowedIPs string
}

func (l *IPInterval) UnmarshalJSON(j []byte) error {
	var rawStrings map[string]string

	err := json.Unmarshal(j, &rawStrings)
	if err != nil {
		return err
	}

	for k, v := range rawStrings {
		if strings.ToLower(k) == "lower" {
			t, err := time.Parse(time.RFC822, v)
			if err != nil {
				return err
			}
			l.Lower = &t

		}
		if strings.ToLower(k) == "upper" {
			t, err := time.Parse(time.RFC822, v)
			if err != nil {
				return err
			}
			l.Upper = &t

		}
		if strings.ToLower(k) == "allowedips" {
			l.AllowedIPs = v
		}
	}

	return nil
}

type Interval struct {
	Lower *time.Time
	Upper *time.Time
}

type AllowIPInterval struct {
	Lower *time.Time
	Upper *time.Time
	Allow bool
}

/*
 *  Constuctor for Interval
 */
func NewIPInterval(low *time.Time, up *time.Time, ip string) *IPInterval {
	f := &IPInterval{
		Lower:      low,
		Upper:      up,
		AllowedIPs: ip,
	}
	return f
}

/*
 *  Constuctor for Interval
 */
func NewInterval(low *time.Time, up *time.Time, ip string) *Interval {
	f := &Interval{
		Lower: low,
		Upper: up,
	}
	return f
}

/*
 *  Constuctor for Interval
 */
func NewAllowIPInterval(low *time.Time, up *time.Time, allow bool) *AllowIPInterval {
	f := &AllowIPInterval{
		Lower: low,
		Upper: up,
		Allow: allow,
	}
	return f
}

type IPFilter struct {
	opts Options
	//mut protects the below
	//rw since writes are rare
	mut            sync.RWMutex
	defaultAllowed bool
	db             *maxminddb.Reader
	ips            map[string]*AllowIPInterval
	codes          map[string]bool
	subnets        []*subnet
}

type subnet struct {
	str      string
	ipnet    *net.IPNet
	allowed  bool
	interval *Interval
}

//NewNoDB constructs IPFilter instance without downloading DB.
func NewNoDB(opts Options) *IPFilter {
	if opts.IPDBFetchURL == "" {
		opts.IPDBFetchURL = DBPublicURL
	}
	if opts.IPDBPath == "" {
		opts.IPDBPath = DBTempPath
	}
	if opts.Logger == nil {
		flags := log.LstdFlags
		opts.Logger = log.New(os.Stdout, "", flags)
	}
	f := &IPFilter{
		opts:           opts,
		ips:            map[string]*AllowIPInterval{},
		codes:          map[string]bool{},
		defaultAllowed: !opts.BlockByDefault,
	}
	for _, ip := range opts.BlockedIPs {
		f.BlockIP(ip)
	}
	for _, ip := range opts.AllowedIPs {
		f.AllowIP(ip)
	}
	for _, ipinterval := range opts.AllowedSchedule {
		f.AllowIPInterval(ipinterval)
	}

	for _, code := range opts.BlockedCountries {
		f.BlockCountry(code)
	}
	for _, code := range opts.AllowedCountries {
		f.AllowCountry(code)
	}
	return f
}

//NewLazy performs database initialization in a goroutine.
//During this initialization, any DB (country code) lookups
//will be skipped. Errors will be logged instead of returned.
func NewLazy(opts Options) *IPFilter {
	f := NewNoDB(opts)
	go func() {
		if err := f.initDB(); err != nil {
			f.opts.Logger.Printf("[ipfilter] failed to intilise db: %s", err)
		}
	}()
	return f
}

//New blocks during database initialization and checks
//validity IP strings. returns an error on failure.
func New(opts Options) (*IPFilter, error) {
	f := NewNoDB(opts)
	if err := f.initDB(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *IPFilter) initDB() error {
	//in-memory
	if len(f.opts.IPDB) > 0 {
		return f.bytesDB(f.opts.IPDB)
	}
	//use local copy
	if fileinfo, err := os.Stat(f.opts.IPDBPath); err == nil {
		if fileinfo.Size() > 0 {
			file, err := os.Open(f.opts.IPDBPath)
			if err != nil {
				return err
			}
			defer file.Close()
			if err = f.readerDB(f.opts.IPDBFetchURL, file); err != nil {
				f.opts.Logger.Printf("[ipfilter] error reading db file %v", err)
				if errDel := os.Remove(f.opts.IPDBPath); errDel != nil {
					f.opts.Logger.Printf("[ipfilter] error removing bad file %v", f.opts.IPDBPath)
				}
			}
			return err
		} else {
			f.opts.Logger.Printf("[ipfilter] IP DB is 0 byte size")
		}
	}
	//ensure fetch is allowed
	if f.opts.IPDBNoFetch {
		return errors.New("IP DB not found and fetch is disabled")
	}
	//fetch and cache missing file
	file, err := os.Create(f.opts.IPDBPath)
	if err != nil {
		return err
	}
	defer file.Close()
	f.opts.Logger.Printf("[ipfilter] downloading %s...", f.opts.IPDBFetchURL)
	resp, err := http.Get(f.opts.IPDBFetchURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	//store on disk as db loads
	r := io.TeeReader(resp.Body, file)
	err = f.readerDB(DBPublicURL, r)
	f.opts.Logger.Printf("[ipfilter] cached: %s", f.opts.IPDBPath)
	return err
}

func (f *IPFilter) readerDB(filename string, r io.Reader) error {
	if strings.HasSuffix(filename, ".gz") {
		g, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer g.Close()
		r = g
	}
	buff := bytes.Buffer{}
	if _, err := io.Copy(&buff, r); err != nil {
		return err
	}
	return f.bytesDB(buff.Bytes())
}

func (f *IPFilter) bytesDB(b []byte) error {
	db, err := maxminddb.FromBytes(b)
	if err != nil {
		return err
	}
	f.mut.Lock()
	f.db = db
	f.mut.Unlock()
	return nil
}

func (f *IPFilter) AllowIP(ip string) bool {
	return f.ToggleIP(ip, nil, true)
}

func (f *IPFilter) AllowIPInterval(ip *IPInterval) bool {
	return f.ToggleIP(ip.AllowedIPs, &Interval{Lower: ip.Lower, Upper: ip.Upper}, true)
}

func (f *IPFilter) BlockIP(ip string) bool {
	return f.ToggleIP(ip, nil, false)
}

func (f *IPFilter) ToggleIP(str string, p_interval *Interval, allowed bool) bool {
	//check if has subnet
	if ip, net, err := net.ParseCIDR(str); err == nil {
		// containing only one ip?
		if n, total := net.Mask.Size(); n == total {
			f.mut.Lock()
			if p_interval == nil {
				f.ips[ip.String()] = &AllowIPInterval{Lower: nil, Upper: nil, Allow: allowed}
			} else {
				f.ips[ip.String()] = &AllowIPInterval{Lower: p_interval.Lower, Upper: p_interval.Upper, Allow: allowed}
			}
			f.mut.Unlock()
			return true
		}
		//check for existing
		f.mut.Lock()
		found := false
		for _, subnet := range f.subnets {
			if subnet.str == str {
				found = true
				subnet.allowed = allowed
				subnet.interval = p_interval
				break
			}
		}
		if !found {
			f.subnets = append(f.subnets, &subnet{
				str:      str,
				ipnet:    net,
				allowed:  allowed,
				interval: p_interval,
			})
		}
		f.mut.Unlock()
		return true
	}
	//check if plain ip
	if ip := net.ParseIP(str); ip != nil {
		f.mut.Lock()
		if p_interval != nil {
			f.ips[ip.String()] = &AllowIPInterval{Allow: allowed, Lower: p_interval.Lower, Upper: p_interval.Upper}
		} else {
			f.ips[ip.String()] = &AllowIPInterval{Allow: allowed, Lower: nil, Upper: nil}

		}
		f.mut.Unlock()
		return true
	}
	return false
}

func (f *IPFilter) AllowCountry(code string) {
	f.ToggleCountry(code, true)
}

func (f *IPFilter) BlockCountry(code string) {
	f.ToggleCountry(code, false)
}

//ToggleCountry alters a specific country setting
func (f *IPFilter) ToggleCountry(code string, allowed bool) {

	f.mut.Lock()
	f.codes[code] = allowed
	f.mut.Unlock()
}

//ToggleDefault alters the default setting
func (f *IPFilter) ToggleDefault(allowed bool) {
	f.mut.Lock()
	f.defaultAllowed = allowed
	f.mut.Unlock()
}

//Allowed returns if a given IP can pass through the filter
func (f *IPFilter) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

//Allowed returns if a given net.IP can pass through the filter
func (f *IPFilter) NetAllowed(ip net.IP) bool {
	//invalid ip
	if ip == nil {
		return false
	}
	//read lock entire function
	//except for db access
	f.mut.RLock()
	defer f.mut.RUnlock()
	//check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		if allowed.Lower == nil {
			return allowed.Allow
		} else {
			return time.Now().Before(*allowed.Upper) && time.Now().After(*allowed.Lower) && allowed.Allow
		}
	}
	//scan subnets for any allow/block
	blocked := false
	for _, subnet := range f.subnets {
		if subnet.ipnet.Contains(ip) {
			if allowed == nil && subnet.allowed {
				return true
			} else {
				if subnet.allowed && allowed.Upper != nil && time.Now().Before(*allowed.Upper) && time.Now().After(*allowed.Lower) {
					return true
				}
				blocked = true
			}
		}
	}
	if blocked {
		return false
	}
	//check country codes
	f.mut.RUnlock()
	code := f.NetIPToCountry(ip)
	f.mut.RLock()
	if code != "" {
		if allowed, ok := f.codes[code]; ok {
			return allowed
		}
	}
	//use default setting
	return f.defaultAllowed
}

//Blocked returns if a given IP can NOT pass through the filter
func (f *IPFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

//Blocked returns if a given net.IP can NOT pass through the filter
func (f *IPFilter) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

//Wrap the provided handler with simple IP blocking middleware
//using this IP filter and its configuration
func (f *IPFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{IPFilter: f, next: next}
}

//IP string to ISO country code.
//Returns an empty string when cannot determine country.
func (f *IPFilter) IPToCountry(ipstr string) string {
	if ip := net.ParseIP(ipstr); ip != nil {
		return f.NetIPToCountry(ip)
	}
	return ""
}

//net.IP to ISO country code.
//Returns an empty string when cannot determine country.
func (f *IPFilter) NetIPToCountry(ip net.IP) string {
	f.mut.RLock()
	db := f.db
	f.mut.RUnlock()
	return NetIPToCountry(db, ip)
}

//Wrap is equivalent to NewLazy(opts) then Wrap(next)
func Wrap(next http.Handler, opts Options) http.Handler {
	return NewLazy(opts).Wrap(next)
}

//IPToCountry is a simple IP-country code lookup.
//Returns an empty string when cannot determine country.
func IPToCountry(db *maxminddb.Reader, ipstr string) string {
	if ip := net.ParseIP(ipstr); ip != nil {
		return NetIPToCountry(db, ip)
	}
	return ""
}

//NetIPToCountry is a simple IP-country code lookup.
//Returns an empty string when cannot determine country.
func NetIPToCountry(db *maxminddb.Reader, ip net.IP) string {
	r := struct {
		//TODO(jpillora): lookup more fields and expose more options
		// IsAnonymous       bool `maxminddb:"is_anonymous"`
		// IsAnonymousVPN    bool `maxminddb:"is_anonymous_vpn"`
		// IsHostingProvider bool `maxminddb:"is_hosting_provider"`
		// IsPublicProxy     bool `maxminddb:"is_public_proxy"`
		// IsTorExitNode     bool `maxminddb:"is_tor_exit_node"`
		Country struct {
			Country string `maxminddb:"iso_code"`
			// Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}{}
	if db != nil {
		db.Lookup(ip, &r)
	}
	//DEBUG log.Printf("%s -> '%s'", ip, r.Country.Country)
	return r.Country.Country
}

type ipFilterMiddleware struct {
	*IPFilter
	next http.Handler
}

func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//use remote addr as it cant be spoofed
	//TODO also check X-Fowarded-For and friends
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	//show simple forbidden text
	if !m.IPFilter.Allowed(ip) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}

func inTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}

func Demo() {
	fmt.Println(time.Now().Format(time.RFC850))
	start, _ := time.Parse(time.RFC822, "01 Jan 15 10:00 UTC")
	end, _ := time.Parse(time.RFC822, "01 Jan 16 10:00 UTC")

	in, _ := time.Parse(time.RFC822, "01 Jan 15 20:00 UTC")
	out, _ := time.Parse(time.RFC822, "01 Jan 17 10:00 UTC")

	if inTimeSpan(start, end, in) {
		fmt.Println(in, "is between", start, "and", end, ".")
	}

	if !inTimeSpan(start, end, out) {
		fmt.Println(out, "is not between", start, "and", end, ".")
	}
}
