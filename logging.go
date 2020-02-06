package memberlist

import (
	"fmt"
	"io"
	"log"
	"net"
)

// LogAddress ...
func LogAddress(addr net.Addr) string {
	if addr == nil {
		return "from=<unknown address>"
	}

	return fmt.Sprintf("from=%s", addr.String())
}

// LogConn ...
func LogConn(conn net.Conn) string {
	if conn == nil {
		return LogAddress(nil)
	}

	return LogAddress(conn.RemoteAddr())
}

// LogLevels ...
const (
	LogLevelDebug = iota
	LogLevelInfo
	LogLevelWarning
	LogLevelError
)

// LevelLogger is custom logger that supports levelled logging
// it logs the output to given io.Writer or log.Logger
type LevelLogger struct {
	logger *log.Logger
	level  int
}

// NewStreamLogger creates a LevelLogger that writes to given io.Writer
func NewStreamLogger(w io.Writer, lvl int) *LevelLogger {
	l := &LevelLogger{
		logger: log.New(w, "", log.LstdFlags),
	}
	l.SetLogLevel(lvl)
	return l
}

// NewLevelLogger creates a LevelLogger that wraps given log.Logger
func NewLevelLogger(l *log.Logger, lvl int) *LevelLogger {
	ll := &LevelLogger{logger: l}
	ll.SetLogLevel(lvl)
	return ll
}

// SetLogLevel updates the log level
func (l *LevelLogger) SetLogLevel(lvl int) {
	switch lvl {
	case LogLevelDebug, LogLevelInfo, LogLevelWarning, LogLevelError:
		l.level = lvl
	}
}

// Debugf is called for debug level events
func (l *LevelLogger) Debugf(format string, args ...interface{}) {
	if l.level <= LogLevelDebug {
		l.logger.Output(2, "[DEBUG] "+fmt.Sprintf(format, args...))
	}
}

// Infof is called for info level events
func (l *LevelLogger) Infof(format string, args ...interface{}) {
	if l.level <= LogLevelInfo {
		l.logger.Output(2, "[INFO] "+fmt.Sprintf(format, args...))
	}
}

// Warnf is called for warning level events
func (l *LevelLogger) Warnf(format string, args ...interface{}) {
	if l.level <= LogLevelWarning {
		l.logger.Output(2, "[WARN] "+fmt.Sprintf(format, args...))
	}
}

// Errorf is called for error level events
func (l *LevelLogger) Errorf(format string, args ...interface{}) {
	if l.level <= LogLevelError {
		l.logger.Output(2, "[ERR] "+fmt.Sprintf(format, args...))
	}
}
