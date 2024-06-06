package logging

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	flowidFilter "github.com/zalando/skipper/filters/flowid"
)

const (
	dateFormat      = "02/Jan/2006:15:04:05 -0700"
	commonLogFormat = `%s(%s) - %d(%d) %s %s %s://%s%s %d %s`
	// format:
	// remote_host - - [date] "method uri protocol" status response_size "referer" "user_agent"
	combinedLogFormat = commonLogFormat + ` "%s" "%s"`
	// We add the duration in ms, a requested host and a flow id and audit log
	accessLogFormat = combinedLogFormat + " %s\n"
)

type accessLogFormatter struct {
	format string
}

// Access log entry.
type AccessEntry struct {

	// The client request.
	Request *http.Request

	// The status code of the response.
	StatusCode int

	// The size of the response in bytes.
	ResponseSize int64

	// The time spent processing request.
	Duration time.Duration

	// The time that the request was received.
	RequestTime time.Time

	// The id of the authenticated user
	AuthUser string
}

// TODO: create individual instances from the access log and
// delegate the ownership from the package level to the user
// code.
var (
	accessLog  *logrus.Logger
	stripQuery bool
)

// strip port from addresses with hostname, ipv4 or ipv6
func stripPort(address string) string {
	if h, _, err := net.SplitHostPort(address); err == nil {
		return h
	}

	return address
}

// The remote host of the client. When the 'X-Forwarded-For'
// header is set, then its value is used as is.
func remoteHost(r *http.Request) string {
	ff := r.Header.Get("X-Forwarded-For")
	if ff != "" {
		return ff
	}
	return stripPort(r.RemoteAddr)
}

func omitWhitespace(h string) string {
	if h != "" {
		return h
	}
	return "-"
}

func (f *accessLogFormatter) Format(e *logrus.Entry) ([]byte, error) {
	keys := []string{
		"ip", "asn", "status", "res-size", "method", "proto", "scheme", "host", "uri", "res-time", "req-id",
		"referer", "user-agent",
		"ja3"}

	values := make([]interface{}, len(keys))
	for i, key := range keys {
		if s, ok := e.Data[key].(string); ok {
			values[i] = omitWhitespace(s)
		} else {
			values[i] = e.Data[key]
		}
	}

	return []byte(fmt.Sprintf(f.format, values...)), nil
}

func stripQueryString(u string) string {
	if i := strings.IndexRune(u, '?'); i < 0 {
		return u
	} else {
		return u[:i]
	}
}

// Logs an access event in Apache combined log format (with a minor customization with the duration).
// Additional allows to provide extra data that may be also logged, depending on the specific log format.
func LogAccess(entry *AccessEntry, additional map[string]interface{}) {
	if accessLog == nil || entry == nil {
		return
	}

	ts := entry.RequestTime.Format(dateFormat)
	ip := ""
	method := ""
	scheme := ""
	uri := ""
	proto := ""
	referer := ""
	userAgent := ""
	reqHost := ""
	reqSize := int64(0)
	reqId := ""
	status := entry.StatusCode
	resSize := entry.ResponseSize
	resTime := int64(entry.Duration / time.Millisecond)
	ja3 := ""
	geo := ""
	asn := ""

	if entry.Request != nil {
		ip = remoteHost(entry.Request)
		method = entry.Request.Method
		proto = entry.Request.Proto
		referer = entry.Request.Referer()
		userAgent = entry.Request.UserAgent()
		reqHost = entry.Request.Host
		reqId = entry.Request.Header.Get(flowidFilter.HeaderName)
		reqSize = entry.Request.ContentLength

		scheme = "http"
		if entry.Request.TLS != nil {
			scheme = "https"
			ja3 = entry.Request.TLS.JA3Hash
		}

		geo = entry.Request.Header.Get("X-Country-Code")
		asn = entry.Request.Header.Get("X-ASN")

		uri = entry.Request.RequestURI
		if stripQuery {
			uri = stripQueryString(uri)
		}
	}

	logData := logrus.Fields{
		"timestamp":  ts,
		"ip":         ip,
		"geo":        geo,
		"asn":        asn,
		"method":     method,
		"proto":      proto,
		"scheme":     scheme,
		"host":       reqHost,
		"uri":        uri,
		"status":     status,
		"res-size":   resSize,
		"res-time":   resTime,
		"req-size":   reqSize,
		"req-id":     reqId,
		"user-agent": userAgent,
		"referer":    referer,
		"ja3":        ja3,
	}

	for k, v := range additional {
		logData[k] = v
	}

	accessLog.WithFields(logData).Infoln()
}
