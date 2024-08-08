package logging

import (
	"fmt"
	"log"
	"os"

	"dns_tools/config"
)

var Runlog_prefix = ""

// 0: OFF, 1: ERR, 2: WARN, 3: INFO, 4: DEBUG, 5: VERBOSE, 6: ALL
func Println(lvl int, prefix interface{}, v ...any) {
	if lvl <= config.Cfg.Verbosity {
		u := []any{}
		switch lvl {
		case 1:
			u = append(u, "ERR    ")
		case 2:
			u = append(u, "WARN   ")
		case 3:
			u = append(u, "INFO   ")
		case 4:
			u = append(u, "DEBUG  ")
		case 5:
			u = append(u, "VERBOSE")
		case 6:
			u = append(u, "ALL    ")
		default:
			u = append(u, "       ")
		}
		if prefix != nil && prefix != "" {
			u = append(u, "["+fmt.Sprintf("%v", prefix)+"]")
		}
		u = append(u, v...)
		v = u
		log.Println(v...)
	}
}

func Write_to_runlog(msg string) {
	logfile, err := os.OpenFile("run.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer logfile.Close()
	if Runlog_prefix != "" {
		msg = "[" + Runlog_prefix + "] " + msg
	}
	logfile.WriteString(msg + "\n")
}
