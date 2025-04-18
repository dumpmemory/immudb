/*
Copyright 2025 Codenotary Inc. All rights reserved.

SPDX-License-Identifier: BUSL-1.1
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://mariadb.com/bsl11/

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package logger

import (
	"io"
	"log"
)

// SimpleLogger ...
type SimpleLogger struct {
	Out      io.Writer
	Logger   *log.Logger
	LogLevel LogLevel
}

// NewSimpleLogger ...
func NewSimpleLogger(name string, out io.Writer) Logger {
	return &SimpleLogger{
		Out:      out,
		Logger:   log.New(out, name+" ", log.LstdFlags),
		LogLevel: LogLevelFromEnvironment(),
	}
}

// NewSimpleLoggerWithLevel ...
func NewSimpleLoggerWithLevel(name string, out io.Writer, level LogLevel) Logger {
	return &SimpleLogger{
		Logger:   log.New(out, name+" ", log.LstdFlags),
		LogLevel: level,
	}
}

// Errorf ...
func (l *SimpleLogger) Errorf(f string, v ...interface{}) {
	if l.LogLevel <= LogError {
		l.Logger.Printf("ERROR: "+f, v...)
	}
}

// Warningf ...
func (l *SimpleLogger) Warningf(f string, v ...interface{}) {
	if l.LogLevel <= LogWarn {
		l.Logger.Printf("WARNING: "+f, v...)
	}
}

// Infof ...
func (l *SimpleLogger) Infof(f string, v ...interface{}) {
	if l.LogLevel <= LogInfo {
		l.Logger.Printf("INFO: "+f, v...)
	}
}

// Debugf ...
func (l *SimpleLogger) Debugf(f string, v ...interface{}) {
	if l.LogLevel <= LogDebug {
		l.Logger.Printf("DEBUG: "+f, v...)
	}
}

// Close the logger ...
func (l *SimpleLogger) Close() error {
	if wc, ok := l.Out.(io.Closer); ok {
		return wc.Close()
	}
	return nil
}
