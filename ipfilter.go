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
	"strconv"
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

func NewOption(allowedScheduleO []*IPInterval) *Options {
	f := &Options{
		BlockByDefault:  true,
		AllowedSchedule: allowedScheduleO,
	}
	return f
}

func getAllIPs(x string) []string {
	var res []string

	i := strings.Index(x, "-")
	if i > -1 {
		chars := x[:i]
		arefun := x[i+1:]
		j := strings.LastIndex(chars, ".")
		k := strings.LastIndex(arefun, ".")
		common1 := chars[:j+1]
		common2 := arefun[:k+1]
		if common1 == common2 {
			begin := chars[j+1:]
			last := arefun[k+1:]
			ibegin, _ := strconv.Atoi(begin)
			ilast, _ := strconv.Atoi(last)
			for ii := ibegin; ii <= ilast; ii++ {
				res = append(res, common1+strconv.Itoa(ii))
			}
		} else {
			fmt.Println("bad" + common1 + "\n" + common2)
			res = append(res, chars)
		}

	} else {
		//fmt.Println("Index not found")
		res = append(res, x)
	}
	return res
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
	Lower []*time.Time
	Upper []*time.Time
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
func NewAllowIPInterval(low []*time.Time, up []*time.Time, allow bool) *AllowIPInterval {
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
	var ips []string
	ips = getAllIPs(ip.AllowedIPs)
	var res bool
	res = true
	if len(ips) == 1 {
		return f.ToggleIP(ips[0], &Interval{Lower: ip.Lower, Upper: ip.Upper}, true)
	} else {
		for ipindex := 0; ipindex < len(ips); ipindex++ {
			res = res && f.ToggleIP(ips[ipindex], &Interval{Lower: ip.Lower, Upper: ip.Upper}, true)
		}
	}
	return res
}

func (f *IPFilter) BlockIP(ip string) bool {
	return f.ToggleIP(ip, nil, false)
}

func (f *IPFilter) ToggleIP(str string, p_interval *Interval, allowed bool) bool {
	//check if has subnet
	jstar := strings.Index(str, "*")
	if jstar > -1 {
		//log.Println("ok for star")
		f.mut.Lock()
		if p_interval == nil {
			f.ips["*"] = &AllowIPInterval{Lower: nil, Upper: nil, Allow: allowed}
		} else {
			if f.ips["*"] != nil {
				f.ips["*"].Upper = append(f.ips["*"].Upper, p_interval.Upper)
				f.ips["*"].Lower = append(f.ips["*"].Lower, p_interval.Lower)
			} else {
				var low []*time.Time
				low = append(low, p_interval.Lower)
				var up []*time.Time
				up = append(up, p_interval.Upper)
				f.ips["*"] = &AllowIPInterval{Lower: low, Upper: up, Allow: allowed}
			}
		}
		f.mut.Unlock()
		return true
	}

	if ip, net, err := net.ParseCIDR(str); err == nil {
		// containing only one ip?
		if n, total := net.Mask.Size(); n == total {
			f.mut.Lock()
			if p_interval == nil {
				f.ips[ip.String()] = &AllowIPInterval{Lower: nil, Upper: nil, Allow: allowed}
			} else {
				if f.ips[ip.String()] != nil {
					f.ips[ip.String()].Upper = append(f.ips[ip.String()].Upper, p_interval.Upper)
					f.ips[ip.String()].Lower = append(f.ips[ip.String()].Lower, p_interval.Lower)
				} else {
					var low []*time.Time
					low = append(low, p_interval.Lower)
					var up []*time.Time
					up = append(up, p_interval.Upper)
					f.ips[ip.String()] = &AllowIPInterval{Lower: low, Upper: up, Allow: allowed}
				}
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
			if f.ips[ip.String()] != nil {
				f.ips[ip.String()].Upper = append(f.ips[ip.String()].Upper, p_interval.Upper)
				f.ips[ip.String()].Lower = append(f.ips[ip.String()].Lower, p_interval.Lower)
			} else {
				var low []*time.Time
				low = append(low, p_interval.Lower)
				var up []*time.Time
				up = append(up, p_interval.Upper)
				f.ips[ip.String()] = &AllowIPInterval{Lower: low, Upper: up, Allow: allowed}
			}

			//f.ips[ip.String()] = &AllowIPInterval{Allow: allowed, Lower: p_interval.Lower, Upper: p_interval.Upper}
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
	//	fmt.Printf("len=%d\n", len(f.ips))
	fmt.Printf(ip.String() + "\n")
	//check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		if allowed.Lower == nil {
			return allowed.Allow
		} else {
			isinvalidtimewindow := false
			for i := 0; i < len(allowed.Upper); i++ {
				isinvalidtimewindow = isinvalidtimewindow || (time.Now().Before(*allowed.Upper[i]) && time.Now().After(*allowed.Lower[i]))
			}

			//			fmt.Println("" + (*allowed.Lower).String())
			//			fmt.Println("" + (*allowed.Upper).String())
			//fmt.Println(allowed.Allow)
			return isinvalidtimewindow && allowed.Allow
		}
	}
	//scan subnets for any allow/block
	blocked := false
	for _, subnet := range f.subnets {
		if subnet.ipnet.Contains(ip) {
			if allowed == nil && subnet.allowed {
				return true
			} else {
				isinvalidtimewindow := false
				if allowed.Upper != nil {
					for i := 0; i < len(allowed.Upper); i++ {
						isinvalidtimewindow = isinvalidtimewindow || (time.Now().Before(*allowed.Upper[i]) && time.Now().After(*allowed.Lower[i]))
					}
				}

				if subnet.allowed && allowed.Upper != nil && isinvalidtimewindow {
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

	allowed, ok = f.ips["*"]
	if ok {
		if allowed.Lower == nil {
			return allowed.Allow
		} else {
			isinvalidtimewindow := false
			for i := 0; i < len(allowed.Upper); i++ {
				isinvalidtimewindow = isinvalidtimewindow || (time.Now().Before(*allowed.Upper[i]) && time.Now().After(*allowed.Lower[i]))
			}
			return isinvalidtimewindow && allowed.Allow
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
	var ip string
	ip = getIPAdress(r)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)

	}
	//fmt.Println(ip)

	//show simple forbidden text
	if !m.IPFilter.Allowed(ip) {
		//http.Redirect()
		w.WriteHeader(403)
		fmt.Fprint(w, "<!DOCTYPE html>"+
			"<html lang=\"en\">"+
			"<head>"+
			"<!-- Simple HttpErrorPages | MIT License | https://github.com/AndiDittrich/HttpErrorPages -->"+
			"<meta charset=\"utf-8\" /><meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"+
			"<title>Application closed</title>"+
			"<style type=\"text/css\">/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;line-height:1.15;-ms-text-si"+
			"ze-adjust:100%;-webkit-text-size-adjust:100%}body{margin:0}article,aside,footer,header,nav,section{display:block}h1{font-size:2em;margin:.67em 0}figcaption,fig"+
			"ure,main{display:block}figure{margin:1em 40px}hr{box-sizing:content-box;height:0;overflow:visible}pre{font-family:monospace,monospace;font-size:1em}a{backgroun"+
			"d-color:transparent;-webkit-text-decoration-skip:objects}a:active,a:hover{outline-width:0}abbr[title]{border-bottom:none;text-decoration:underline;text-decorat"+
			"ion:underline dotted}b,strong{font-weight:inherit}b,strong{font-weight:bolder}code,kbd,samp{font-family:monospace,monospace;font-size:1em}dfn{font-style:italic"+
			"}mark{background-color:#ff0;color:#000}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{"+
			"top:-.5em}audio,video{display:inline-block}audio:not([controls]){display:none;height:0}img{border-style:none}svg:not(:root){overflow:hidden}button,input,optgro"+
			"up,select,textarea{font-family:sans-serif;font-size:100%;line-height:1.15;margin:0}button,input{overflow:visible}button,select{text-transform:none}[type=reset]"+
			",[type=submit],button,html [type=button]{-webkit-appearance:button}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inn"+
			"er,button::-moz-focus-inner{border-style:none;padding:0}[type=button]:-moz-focusring,[type=reset]:-moz-focusring,[type=submit]:-moz-focusring,button:-moz-focus"+
			"ring{outline:1px dotted ButtonText}fieldset{border:1px solid silver;margin:0 2px;padding:.35em .625em .75em}legend{box-sizing:border-box;color:inherit;display:"+
			"table;max-width:100%;padding:0;white-space:normal}progress{display:inline-block;vertical-align:baseline}textarea{overflow:auto}[type=checkbox],[type=radio]{box"+
			"-sizing:border-box;padding:0}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:tex"+
			"tfield;outline-offset:-2px}[type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-b"+
			"utton{-webkit-appearance:button;font:inherit}details,menu{display:block}summary{display:list-item}canvas{display:inline-block}template{display:none}[hidden]{di"+
			"splay:none}/*! Simple HttpErrorPages | MIT X11 License | https://github.com/AndiDittrich/HttpErrorPages */body,html{width:100%;height:100%;background-color:#21"+
			"232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;-webkit-box-shadow:inset 0 0 100px rgba(0,0,0,.8);box-sha"+
			"dow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:\"Open Sans\",Arial,sans-serif}h1{font-family:inherit;font-weight:500;line-height:1.1;color:inherit;"+
			"font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}a{text-decoration:none;color:#fff;font-size:inherit;border-bottom:dotted 1px #70"+
			"7070}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}footer{position:fixed;width:100%;height:4"+
			"0px;left:0;bottom:0;color:#a0a0a0;font-size:14px}</style>"+
			"</head>"+
			"<body>"+
			"<div class=\"cover\"><h1>L'application de rendu de TPs n'est pas ouverte pour le moment à cette URL <BR> <small>mauvais horaire ou mauvaise IP</small></h1><p class=\"lead\">N'hésitez pa"+
			"s à contacter votre correspondant de TP si cette situation n'est pas normale</p></div>"+
			"</body>"+
			"</html>", http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}

func inTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}

//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

var privateRanges = []ipRange{
	ipRange{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	ipRange{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	ipRange{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	ipRange{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	ipRange{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	ipRange{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func getIPAdress(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	return ""
}
