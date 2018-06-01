package main

import (
    "fmt"
    "net"
    "strings"
    "runtime"
    "sync"
    "log"
    "regexp"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

var (
    DBW *sql.DB
    ip_addr_pattern = regexp.MustCompile(`\[((\d+)\.(\d+)\.(\d+)\.(\d+))\]`)
    severity_ptrn = regexp.MustCompile(`\[\w+\d\.\w+\]`)

    username = "username"
    password = "password"
    socket = "mysql.sock"
    database = "Syslog"
    tablename = "TableName"

    SQLQuery = "INSERT INTO "+tablename+" (DeviceReportedTime, Facility, Severity, FromHost, Message) VALUES (STR_TO_DATE(?,'%Y-%m-%d %H:%i:%s'),?,?,?,?)"
    // SQLQuery = "INSERT INTO "+tablename+" (DeviceReportedTime, Facility, Severity, FromHost, Message) VALUES (?,?,?,?,?)"
    StmtMain *sql.Stmt
    wg       sync.WaitGroup
    errDbw  error
    errStmt error
    message SyslogMessage;

)
// <13>May 30 07:22:21 10.zxc.1.12 [2020.05.30-10: 22:57] [10.cxz.92.18] [local7.info] ft_mgr::ft_speed_update: Temperature is not decreasing. Increasing the fan speed.

type SyslogMessage struct {
        host string
        date string
        severity string
        facility string
        message string
}

func CheckError(err error) {
    if err  != nil {
        log.Fatalln(err)
        // fmt.Println("Error: " , err)
    }
}

func connect_db(username, password, socket, database string) (db *sql.DB) {
    db,err := sql.Open("mysql", username+":"+password+"@unix("+socket+")/"+database)
    if err != nil {
      panic(err)
    }
    return db
}

func get_datetime_str(input string) string {
    remain := input[strings.Index(input,"["): len(input)];
    origin_date := strings.SplitN(remain[1:strings.Index(remain,"]")],"-",2);
    origin_date[1] = strings.Replace(origin_date[1]," ","",1);
    origin_month := origin_date[0][5:7];
    origin_day:= origin_date[0][8:10];
    return origin_date[0][0:4]+"-"+origin_month+"-" + origin_day + " "+ origin_date[1];
}

func get_origin_ip(input string) string {
    origin_ip := ip_addr_pattern.FindString(input);
    return origin_ip[1:len(origin_ip)-1];
}

func get_log_msg(input string) string {
   svrt := severity_ptrn.FindString(input);
   return input[strings.Index(input,svrt)+len(svrt):];
}

func get_facility_severity_msg(input string) (string, string) {
    svrt := severity_ptrn.FindString(input);
    severity := strings.Split(svrt,".");
    return severity[1][:len(severity[1])-1], severity[0][1:];
}

func insert_db(message SyslogMessage, DBW *sql.DB) {
    defer wg.Done()
    // DeviceReportedTime, Facility, Severity, FromHost, Message
    _, err := StmtMain.Exec(message.date, message.facility, message.severity, message.host, message.message)
    CheckError(err)
}

func parser(msg string, message SyslogMessage, DBW *sql.DB) {
    message.host = get_origin_ip(msg);
    message.date = get_datetime_str(msg);
    message.severity, message.facility = get_facility_severity_msg(msg);
    message.message = get_log_msg(msg);
    StmtMain, errStmt = DBW.Prepare(SQLQuery);
    CheckError(errStmt);
    // defer StmtMain.Close();
    wg.Add(1);
    go insert_db(message, DBW);
}

func main () {
    ServerAddr,err := net.ResolveUDPAddr("udp",":10001")
    CheckError(err)
    ServerConn, err := net.ListenUDP("udp", ServerAddr)
    CheckError(err)
    defer ServerConn.Close()
    fmt.Println("Server started at :10001 UDP");

    concurrencyLevel := runtime.NumCPU() * 8;
    DBW := connect_db(username, password, socket, database);
    DBW.SetMaxIdleConns(concurrencyLevel);
    defer DBW.Close();

    buf := make([]byte, 1024);
    for {
        n,_,err := ServerConn.ReadFromUDP(buf)
        // fmt.Println("Received ",string(buf[0:n]), " from ",addr)
        parser(string(buf[0:n]), message, DBW)

        if err != nil {
            // fmt.Println("Error: ",err)
            log.Fatalln(err)
        }
    }
    wg.Wait();
}


// DROP TABLE IF EXISTS `BRASMessage`;
// /*!40101 SET @saved_cs_client     = @@character_set_client */;
// /*!40101 SET character_set_client = utf8 */;
// CREATE TABLE `BRASMessage` (
//   `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
//   `DeviceReportedTime` datetime DEFAULT NULL,
//   `Facility` varchar(10) DEFAULT NULL,
//   `Severity` varchar(10)  DEFAULT NULL,
//   `FromHost` varchar(60) DEFAULT NULL,
//   `Message` text,
//   PRIMARY KEY (`ID`)
// ) ENGINE=MyISAM AUTO_INCREMENT=2595171222 DEFAULT CHARSET=latin1;
// /*!40101 SET character_set_client = @saved_cs_client */;
