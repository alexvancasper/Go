package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "flag"
    "strings"
    "regexp"
    "database/sql"
    _ "mysql"
    "net/http"
    "net/url"
    "bytes"
    "encoding/json"
    "toml"
    "time"
    "os/exec"
)
// 0   1 2   3       4            5            6
// Apr   6 14:27:05 10.111.5.69 [0001]: %LOGGTEST-6-INFO: OSPF-1 test

// 0    1      2       3          4            5            6
// Apr 16 14:27:05 10.111.5.69 [0001]: %LOGGTEST-6-INFO: OSPF-1 test
// %OMI-COM-5-NOTICE:  -               reportAlarm Sending alarm: dn=ManagedElement=1,Equipment=1,Slot=2,Port=20; majorType=193; minorType=3188851713; additionalText=Link down; severity=0; specificProblem=Link down; seqNo=764; eventTime=1523269552000000000; sta

var (
    username string 
    password string 
    socket string 
    database string 
    MYURL string 
    CHANNEL_NAME string 
    Bot_name string
    fifo_name string
    alarm_file string
    check_port bool
    external_script bool
    conf Config
    parcel []LogMessage

    deny_message *regexp.Regexp
    and_deny_message *regexp.Regexp
    event_regexp *regexp.Regexp
    ip_addr_pattern = regexp.MustCompile(`((\d+)\.(\d+)\.(\d+)\.(\d+))`)
    dots_pattern = regexp.MustCompile(`\.`)
    first3octets_pattern = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)\.`)

    to_from_full_ptrn = regexp.MustCompile(`(?i)(to|from) full`)
    kill_neighbor_ptrn = regexp.MustCompile(`(?i)(Kill Neighbor|1 Way|Inactivity Timer)`)
    bgp_ptrn = regexp.MustCompile(`(?i)BGP-6-INFO`)
    up_down_ptrn = regexp.MustCompile(`(?i)(up|down)`)
    neighbor_ptrn = regexp.MustCompile(`(?i)^(.*?)Neighbor(.*)$`)
    slot_ptrn = regexp.MustCompile(`(?i)slot=\d{1,2}`)
    port_ptrn = regexp.MustCompile(`(?i)port=\d{1,2}`)
    addtxt_ptrn = regexp.MustCompile(`(?i)additionalText=.*`) 
    severity_ptrn = regexp.MustCompile(`(?i)severity=\d{1,2}`)
    major_type = regexp.MustCompile(`(?i)majorType=\d{1,4}`)
    minor_type = regexp.MustCompile(`(?i)minorType=\d{1,13}`)
    report_send_alarm_ptrn = regexp.MustCompile(`(?i)reportAlarm Sending alarm`)
    dash_ptrn = regexp.MustCompile(`-\s{3,}\w`)  

    ManagedElement = "ManagedElement=1"
    Equipment = "Equipment=1"
    delimeter = ";"
    severity_cleared = "severity=0"
    MAX_MSG = 4090
)

type DNSEntry struct {
    context_name string
    interface_name string
}

type Config struct {
  Bot bot
  Filter filter
  Database DB
  Buffer buffer
  Common common
  External external
  Devices map[string]device
}

type bot struct {
  Url string
  Channel_name string
  Bot_name string
}

type filter struct {
  Deny_msg string
  And_Denymsg string
  Send_port string
}

type DB struct {
  Dbuser string
  Dbpass string
  Dbsock string
  Dbname string
}

type buffer struct {
  Filepath string
}

type common struct{
  Alarmfile string
}

type device struct {
  Name string
}

type external struct {
  Enable string
  Event_regexp string
  Path_script string
  Script_args string
  Output_file string
}

type LogMessage struct {
  Host string
  Date string
  Time string
  Message string
}

type Parcel struct {
  msg []LogMessage
}

func check(e error) {
    if e != nil {
        log.Fatal(e)
        // fmt.Printf("Error: %s\n", e)
    }
}

func WriteFile(msg string){
  f, err := os.OpenFile(alarm_file, os.O_APPEND|os.O_WRONLY, 0600)
  check(err)
  defer f.Close() 
  if _, err = f.WriteString(msg+"\n"); err != nil {
    check(err)
  }
  f.Sync()
}

func WriteExternalFile(msg []byte, output string){
  var (
    f *os.File
    err error
  )

  if _, err = os.Stat(output); os.IsNotExist(err) {
    f, err = os.Create(output)
    check(err)
    f.Close();
  }
  
  f, err = os.OpenFile(output, os.O_APPEND|os.O_WRONLY, 0600)
  check(err)
  defer f.Close() 
  if _, err = f.Write(msg); err != nil {
    check(err)
  }
  f.Sync()
}

func remove_str_element(source []string, i int) []string {
    source_size := len(source)
    var (
          output []string
        )
    output = make([]string,source_size-1,source_size-1)
    if (i>source_size) || (i<0) {
        return source
    }

    if i==0 {
        output = source[1:]
        return output
    }
    if i==source_size {
        output = source[:len(source)-1]
        return output
    }

    if (i>0) && (i<source_size) {
       output = append(source[0:i], source[i+1:len(source)]...) 
       return output
    }
    return source
}

func find_hostname(ip_addr string) string {
    hostname := conf.Devices[ip_addr].Name
    if len(hostname)==0  {
        return ip_addr
    } else {
        return hostname
    }
}

func connect_db(username, password, socket, database string) (db *sql.DB) {
    db,err := sql.Open("mysql", username+":"+password+"@unix("+socket+")/"+database)
    if err != nil {
      panic(err)
    }

    return db
}

func fetch_data(hostname, int_addr string) DNSEntry {
    address := first3octets_pattern.FindString(int_addr)
    ipaddr := dots_pattern.ReplaceAllString(int_addr,"")

    db := connect_db(username, password, socket, database)
    var entry DNSEntry
    err := db.QueryRow("SELECT context_name, interface_name FROM interfaces WHERE start_ipaddr<=? and end_ipaddr>=? and interface_address like ? and hostname=? order by dt desc limit 0,1", ipaddr, ipaddr, "%"+address+"%", hostname).Scan(&entry.context_name, &entry.interface_name)

    if err != nil {
        fmt.Println(err.Error())
    }
    db.Close()
    return entry
    // returned [('CONTEXT_NAME', 'INTERFACE_NAME')]
}

func replace_log_ip_addr(log, hostname string) string {
    ip_address := ip_addr_pattern.FindString(log)
    if len(ip_address)>0 {
      q_result := fetch_data(hostname, ip_address)
      if len(q_result.interface_name)>0 && len(q_result.context_name)>0 {
          new_log := fmt.Sprintf("<b>Neighbor on INTERFACE: %s CONTEXT: %s</b>",  q_result.interface_name, q_result.context_name)
          if len(to_from_full_ptrn.FindString(log))>0 {
            return neighbor_ptrn.ReplaceAllString(log, "${1}"+new_log+"$2")
          }
          if len(kill_neighbor_ptrn.FindString(log))>0 {
            return neighbor_ptrn.ReplaceAllString(log, "${1}"+new_log+"$2")            
          }
          if len(bgp_ptrn.FindString(log))>0 && len(up_down_ptrn.FindString(log))>0 {
            return bgp_ptrn.ReplaceAllString(log, "BGP-6-INFO: "+new_log)            
          }
      }
    }
    return log
}

func send_telegram(message_data string) int {
   if len(message_data)>0 {
      v := url.Values{}
      v.Set("chat_id", CHANNEL_NAME)
      v.Set("text", message_data)
      v.Set("bot_name", Bot_name)
      s := v.Encode()
      req, err := http.NewRequest("POST", MYURL, strings.NewReader(s))
      if err != nil {
         // fmt.Printf("error: %v\n",err)
         return -1
      }
      req.Header.Add("Content-Type","application/x-www-form-urlencoded")
      c := &http.Client{}
      resp, err := c.Do(req)
      if err != nil {
         // fmt.Printf("Do() errorL %v\n", err)
         return -1
      }
      defer resp.Body.Close()
      return 0
   }
   return -1
}

func send_slack(message_data string) int {
   if len(message_data)>0 {
      v := url.Values{}
      v.Set("channel", "pscore")
      v.Set("text", message_data)
      v.Set("bot_name", "BLACK2ERBOT")
      v.Set("srvc", "slack")
      s := v.Encode()
      req, err := http.NewRequest("POST", "https://ltecode.com/bot_sl.php", strings.NewReader(s))
      if err != nil {
         // fmt.Printf("error: %v\n",err)
         return -1
      }
      req.Header.Add("Content-Type","application/x-www-form-urlencoded")
      c := &http.Client{}
      time.Sleep(time.Second)
      resp, err := c.Do(req)
      if err != nil {
         // fmt.Printf("Do() errorL %v\n", err)
         return -1
      }
      defer resp.Body.Close()
      return 0
   }
   return -1
}

func send_skype(message_data string) int {
   if len(message_data)>0 {
      SKYPE_URL :="https://ltecode.com/skype.php"
      // v := url.Values{}
      // v.Set("chat_id", CHANNEL_NAME)
      // v.Set("text", message_data)
      // v.Set("bot_name", Bot_name)
      // s := v.Encode()

      values := map[string]string{"text": message_data}
      jsonValue, _ := json.Marshal(values)

      req, err := http.NewRequest("POST", SKYPE_URL, bytes.NewBuffer(jsonValue))
      if err != nil {
         // fmt.Printf("error: %v\n",err)
         return -1
      }
      req.Header.Add("Content-Type","application/json")
      c := &http.Client{}
      resp, err := c.Do(req)
      if err != nil {
         // fmt.Printf("Do() errorL %v\n", err)
         return -1
      }
      defer resp.Body.Close()
      return 0
   }
   return -1
}

func ParseConfig(conf Config) {
    // fmt.Printf("%#v\n",conf)
    fmt.Printf("DB user: %s\n", conf.Database.Dbuser)
    // fmt.Printf("DB pass: %s\n", conf.Database.Dbpass)
    fmt.Printf("DB pass: %s\n", strings.Repeat("*", len(conf.Database.Dbpass)))
    fmt.Printf("DB sock: %s\n", conf.Database.Dbsock)
    fmt.Printf("DB name: %s\n", conf.Database.Dbname)
    fmt.Printf("Bot URL: %s\n", conf.Bot.Url)
    fmt.Printf("Bot channel name: %s\n", conf.Bot.Channel_name)
    fmt.Printf("Bot name: %s\n", conf.Bot.Bot_name)
    fmt.Printf("Deny words %d: %s\n", len(strings.Split(conf.Filter.Deny_msg, "|")), conf.Filter.Deny_msg)
    fmt.Printf("AND Deny words %d: %s\n", len(strings.Split(conf.Filter.And_Denymsg, "|")), conf.Filter.And_Denymsg)
    fmt.Printf("FIFO buffer: %s\n", conf.Buffer.Filepath)
    fmt.Printf("Alarm file: %s\n", conf.Common.Alarmfile)
    fmt.Printf("External script enable: %s\n", conf.External.Enable)
    fmt.Printf("External script path: %s\n", conf.External.Path_script)
    fmt.Printf("External script args: %s\n", conf.External.Script_args)
    fmt.Printf("External script regexp: %s\n", conf.External.Event_regexp)
    fmt.Printf("External script output: %s\n", conf.External.Output_file)
    fmt.Printf("Send each port info: %s\n", conf.Filter.Send_port)
    fmt.Printf("Loaded devices: %d\n", len(conf.Devices))
    username = conf.Database.Dbuser
    password = conf.Database.Dbpass
    socket = conf.Database.Dbsock
    database = conf.Database.Dbname
    MYURL = conf.Bot.Url
    CHANNEL_NAME = conf.Bot.Channel_name
    Bot_name = conf.Bot.Bot_name
    deny_message = regexp.MustCompile("(?i)"+conf.Filter.Deny_msg)
    and_deny_message = regexp.MustCompile("(?i)"+conf.Filter.And_Denymsg)
    fifo_name = conf.Buffer.Filepath
    alarm_file = conf.Common.Alarmfile
    if conf.Filter.Send_port == "no"{
      check_port = false
    } else {
      check_port = true
    }

    if conf.External.Enable == "no" {
      external_script = false
    } else {
      external_script = true
      event_regexp = regexp.MustCompile("(?i)"+conf.External.Event_regexp)
    }
}

func event_handler(input string) {
  if event_regexp.MatchString(input) {
    cmd := exec.Command(conf.External.Path_script, conf.External.Script_args, "echo stdout; echo 1>&2 stderr")
    fmt.Printf("\nRunning command and waiting for it to finish...")
    stdoutStderr, err := cmd.CombinedOutput()
    fmt.Printf("\nCommand finished with error: %v", err)
    WriteExternalFile(stdoutStderr, conf.External.Output_file)
    fmt.Printf("\nResult was written to the output file: %s", conf.External.Output_file)
  }
}

func parser(x string, slotport bool) (string, bool) {
  report := make([]string, 3);
  dash_value := dash_ptrn.FindString(x);
  if len(dash_value)<=0 {
    return "nodash", false
  }
  addtxt := addtxt_ptrn.FindString(x);
  pos1:=strings.Index(x,ManagedElement)+len(ManagedElement)+1;
  pos2:=strings.LastIndex(x,delimeter);
  if pos2<0 {
    pos2 = len(x);
  }
  x = x[pos1:pos2];
  i := strings.Count(x,delimeter)+1;
  split := strings.SplitN(x,delimeter,i);
  if len(split[0])>len(Equipment){
    equip_idx := strings.Index(split[0], Equipment);
    if equip_idx>=0 {
        report[0]=split[0][equip_idx +len(Equipment)+1:];  
    }else{
      report[0]=split[0]
      }
    slot := slot_ptrn.FindString(report[0]);
    port := port_ptrn.FindString(report[0]);
    if len(slot)>0 && len(port)>0 && !slotport {
             return "check_port_off", false
    }
  }
  if len(addtxt)>0 {
     if strings.Index(addtxt,delimeter)>=0 {
       report[1]=addtxt[15:strings.Index(addtxt,delimeter)]
     }else {
       report[1]=addtxt[15:]
     }
  }
  svrt := severity_ptrn.FindString(x)
  if svrt == severity_cleared {
     report[2] = "<b>Status: Cleared</b>"
  }
  sms :="";
  for j:=0;j<len(report);j++{
   sms += report[j]+"\n";
  }
  return sms, true
}


func ParseMsg(result []string, channel chan string) {
    var sms string = ""
    var send bool = true
    // var msg LogMessage

    sms =  "<b>HOST:"+find_hostname(result[3])+"</b>\n"
    // msg.Host = find_hostname(result[3])
    sms += "DATE:"+result[0]+" "+result[1]+" "+result[2]+"\n"
    // msg.Date = result[0]+" "+result[1]
    // msg.Time = result[2]
    if external_script {
       go event_handler(result[4])
    }
    report, ok := parser(result[4], check_port)
    if report == "check_port_off" && !ok {
      return
    }
    // if !ok {
    //   fmt.Println(report);
    // }
    if ok {
      sms += "LOG:"+report+"\n"
      channel <- sms;
      // msg.Message = report
      // parcel, json_err := json.Marshall(msg)
      // check(json_err)
      // json_channel <- parcel 
      send = false
    };
    if send {
      sms += "LOG:"+replace_log_ip_addr(result[4], find_hostname(result[3]))+"\n\n"
      channel <- sms;
      // msg.Message = report
      // parcel, json_err := json.Marshall(msg)
      // check(json_err)
      // json_channel <- parcel 
    }

    minortype := minor_type.FindString(result[4])
    majortype := major_type.FindString(result[4])
    if len(minortype)>0 && len(majortype)>0 {
      WriteFile(result[4])
    }

}

func waiting_sms(channel chan string) {
   var sms string;
   var parts, k int;
   ticker := time.NewTicker(1 * time.Second);
   go func() {
      for {
        select {
            case <-ticker.C:
                if len(sms)>1{
                    if len(sms)>=MAX_MSG {
                        parts = int(len(sms)/MAX_MSG);
                        k=0;
                        for i:=0;i<len(sms);i+=MAX_MSG {
                          if k==parts{
                            k=i; 
                            break;
                          }
                          // fmt.Println(sms[0+i:MAX_MSG+i])
                          send_telegram(sms[0+i:MAX_MSG+i]);
                          // send_skype(sms[0+i:MAX_MSG+i]);
                          // send_slack(sms[0+i:MAX_MSG+i]);
                          k++;
                        }
                        // fmt.Println(sms[k:]);
                        send_telegram(sms[k:]);
                        // send_skype(sms[k:]);
                        // send_slack(sms[k:]);
                    }
                    if len(sms)<MAX_MSG {
                      // fmt.Println(sms);
                      send_telegram(sms);
                      // send_skype(sms);
                      // send_slack(sms);
                    }
                    sms = "";
                }
            case msg := <-channel:
                sms+= msg
        }
      }
   }()
}

// func waiting_json_message(channel chan []byte) {
//    var sms string;
//    var parts, k int;
//    ticker := time.NewTicker(1 * time.Second);
//    go func() {
//       for {
//         select {
//             case <-ticker.C:
//                 if len(sms)>1{
//                     if len(sms)>=MAX_MSG {
//                         parts = int(len(sms)/MAX_MSG);
//                         k=0;
//                         for i:=0;i<len(sms);i+=MAX_MSG {
//                           if k==parts{
//                             k=i; 
//                             break;
//                           }
//                           send_skype(sms[0+i:MAX_MSG+i]);
//                           k++;
//                         }
//                         send_skype(sms[k:]);
//                     }
//                     if len(sms)<MAX_MSG {
//                       send_skype(sms);
//                     }
//                     sms = "";
//                 }
//             case msg := <-channel:
//                 sms+= msg
//         }
//       }
//    }()
// }

func main() {
    if len(os.Args)==1 {
      fmt.Println(os.Args)
      fmt.Fprintf(os.Stderr, "usage %s [config_file]\n", os.Args[0])
      flag.PrintDefaults()
      os.Exit(2)
    }
    
    if _, err := toml.DecodeFile(os.Args[1], &conf); err != nil {
      log.Fatal(err)
      // fmt.Fprintf(os.Stderr, "The config file is broken or happens something else  :) \n")
      // flag.PrintDefaults()
      os.Exit(2)
    } 
    ParseConfig(conf)
    
    channel := make(chan string);
    go waiting_sms(channel);

    // json_channel := make(chan []byte);
    // go waiting_json_message(channel);
    
    var result []string
    file, err := os.Open(fifo_name)
    if err != nil {
        log.Fatal(err)
    }
    for {
      scanner := bufio.NewScanner(file)
      for scanner.Scan() {
          result = strings.SplitN(scanner.Text(), " ", 6)
          if len(result)<4 {continue}
          if result[1] == "" {
            result = remove_str_element(result, 1)
          }
          if len(result)>5 {
            result[4]=result[4]+" "+result[5]
            remove_str_element(result, 5)
          }
          if deny_message.MatchString(result[4])  { continue }
          if report_send_alarm_ptrn.MatchString(result[4]) && and_deny_message.MatchString(result[4]) { continue }
          go ParseMsg(result, channel)
      }
      if err := scanner.Err(); err != nil {
        log.Fatal(err)
      }
    }
    file.Close()
}
