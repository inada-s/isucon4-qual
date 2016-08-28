package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/fasthttp-contrib/sessions"
	_ "github.com/fasthttp-contrib/sessions/providers/memory"
	"github.com/valyala/fasthttp"
)

var (
	cpuProfileFile   = "/tmp/cpu.pprof"
	memProfileFile   = "/tmp/mem.pprof"
	blockProfileFile = "/tmp/block.pprof"

	sess *sessions.Manager

	db *sql.DB

	UserLockThreshold int
	IPBanThreshold    int

	ErrBannedIP      = errors.New("Banned IP")
	ErrLockedUser    = errors.New("Locked user")
	ErrUserNotFound  = errors.New("Not found user")
	ErrWrongPassword = errors.New("Wrong password")

	LoginLogMtx              sync.Mutex
	LoginLogs                []LoginLog
	LoginFailedCountByIP     map[string]int
	LoginFailedCountByUserID map[int]int
	LastLoginLog             map[int]LoginLog
	PrevLoginLog             map[int]LoginLog

	UsersMtx sync.Mutex
	Users    map[string]User
	UsersID  map[int]User
)

func addLoginLog(ll LoginLog) {
	LoginLogMtx.Lock()
	ll.ID = len(LoginLogs) + 1
	if ll.Succeeded == 0 {
		LoginFailedCountByIP[ll.IP] += 1
		LoginFailedCountByUserID[ll.UserID] += 1
	} else {
		LoginFailedCountByIP[ll.IP] = 0
		LoginFailedCountByUserID[ll.UserID] = 0

		prev, ok := LastLoginLog[ll.UserID]
		if ok {
			PrevLoginLog[ll.UserID] = prev
		}
		LastLoginLog[ll.UserID] = ll
	}
	LoginLogs = append(LoginLogs, ll)
	LoginLogMtx.Unlock()
}

type User struct {
	ID           int
	Login        string
	PasswordHash string
	Salt         string

	LastLogin *LastLogin
}

type LastLogin struct {
	Login     string
	IP        string
	CreatedAt time.Time
}

type LoginLog struct {
	ID        int
	CreatedAt time.Time
	UserID    int
	Name      string
	IP        string
	Succeeded int
}

func initLoginLog() {
	dummyLog, err := os.Open("dummy_log.tsv")
	if err != nil {
		log.Fatal(err)
	}
	r := csv.NewReader(dummyLog)
	r.Comma = '\t'
	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range records {
		var ll LoginLog
		/*
			line[0]     CreatedAt
			line[1]     UserID
			line[2]     Login (UserName)
			line[3]     IPAddr
			line[4]     Succeeded
		*/
		ll.CreatedAt, err = time.Parse("2006-01-02 15:04:05 -0700", strings.Trim(line[0], "' "))
		if err != nil {
			log.Fatal(err)
		}
		uid, err := strconv.ParseInt(strings.Trim(line[1], " "), 10, 32)
		if err != nil {
			log.Fatal(err)
		}
		ll.UserID = int(uid)
		ll.Name = strings.Trim(line[2], "' ")
		ll.IP = strings.Trim(line[3], "' ")
		if strings.Contains(line[4], "1") {
			ll.Succeeded = 1
		}
		addLoginLog(ll)
	}
}

func initUsers() {
	dummyUsers, err := os.Open("dummy_users.tsv")
	if err != nil {
		log.Fatal(err)
	}
	r := csv.NewReader(dummyUsers)
	r.Comma = '\t'
	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	UsersMtx.Lock()
	defer UsersMtx.Unlock()
	for _, line := range records {
		var u User
		/*
			line[0]     ID
			line[1]     Login
			line[2]     Pass
			line[3]     Salt
			line[4]     Hash
		*/
		uid, err := strconv.ParseInt(strings.Trim(line[0], " "), 10, 32)
		if err != nil {
			log.Fatal(err)
		}
		u.ID = int(uid)
		u.Login = strings.Trim(line[1], "' ")
		u.Salt = strings.Trim(line[3], "' ")
		u.PasswordHash = strings.Trim(line[4], "' ")
		Users[u.Login] = u
		UsersID[u.ID] = u
	}
	log.Println(Users["isucon2"])
}

func init() {
	sess = sessions.New("memory", "isucon_go_session", time.Duration(60)*time.Minute)
	LoginFailedCountByIP = map[string]int{}
	LoginFailedCountByUserID = map[int]int{}
	LastLoginLog = map[int]LoginLog{}
	PrevLoginLog = map[int]LoginLog{}
	Users = map[string]User{}
	UsersID = map[int]User{}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Local",
		getEnv("ISU4_DB_USER", "root"),
		getEnv("ISU4_DB_PASSWORD", ""),
		getEnv("ISU4_DB_HOST", "localhost"),
		getEnv("ISU4_DB_PORT", "3306"),
		getEnv("ISU4_DB_NAME", "isu4_qualifier"),
	)

	var err error

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}

	UserLockThreshold, err = strconv.Atoi(getEnv("ISU4_USER_LOCK_THRESHOLD", "3"))
	if err != nil {
		panic(err)
	}

	IPBanThreshold, err = strconv.Atoi(getEnv("ISU4_IP_BAN_THRESHOLD", "10"))
	if err != nil {
		panic(err)
	}
	initLoginLog()
	initUsers()
}

func getIndex(ctx *fasthttp.RequestCtx) {
	s := sess.Start(ctx)
	flash := ""

	value := s.Get("notice")
	if value != nil {
		s.Delete("notice")
		flash = value.(string)
	}
	ctx.SetContentType("text/html")
	ctx.WriteString(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/"><img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス"></a>
      </h1>
      <div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>`)
	if flash != "" {
		ctx.WriteString(`<div id="notice-message" class="alert alert-danger" role="alert">`)
		ctx.WriteString(flash)
		ctx.WriteString(`</div>`)
	}

	ctx.WriteString(`
<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>
</div>`)
}

func postLogin(ctx *fasthttp.RequestCtx) {
	s := sess.Start(ctx)
	user, err := attemptLogin(ctx)

	notice := ""
	if err != nil || user == nil {
		switch err {
		case ErrBannedIP:
			notice = "You're banned."
		case ErrLockedUser:
			notice = "This account is locked."
		default:
			notice = "Wrong username or password"
		}

		s.Set("notice", notice)
		ctx.Redirect("/", http.StatusFound)
		return
	}

	s.Set("user_id", strconv.Itoa(user.ID))
	ctx.Redirect("/mypage", http.StatusFound)
}

func getMyPage(ctx *fasthttp.RequestCtx) {
	s := sess.Start(ctx)
	currentUser := getCurrentUser(s.Get("user_id"))

	if currentUser == nil {
		s.Set("notice", "You must be logged in")
		ctx.Redirect("/", http.StatusFound)
		return
	}

	ll := currentUser.getLastLogin()
	ctx.SetContentType("text/html")
	ctx.WriteString(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/"><img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス"></a>
      </h1>
<div class="alert alert-success" role="alert">
  ログインに成功しました。<br>
  未読のお知らせが０件、残っています。
</div>

<dl class="dl-horizontal">
  <dt>前回ログイン</dt>
  <dd id="last-logined-at">`)
	ctx.WriteString(ll.CreatedAt.Format("2006-01-02 15:04:05"))
	ctx.WriteString(`</dd>
  <dt>最終ログインIPアドレス</dt>
  <dd id="last-logined-ip">`)
	ctx.WriteString(ll.IP)
	ctx.WriteString(`</dd>
</dl>

<div class="panel panel-default">
  <div class="panel-heading">
    お客様ご契約ID：`)
	ctx.WriteString(ll.Login)
	ctx.WriteString(` 様の代表口座
  </div>
  <div class="panel-body">
    <div class="row">
      <div class="col-sm-4">
        普通預金<br>
        <small>東京支店　1111111111</small><br>
      </div>
      <div class="col-sm-4">
        <p id="zandaka" class="text-right">
          ―――円
        </p>
      </div>

      <div class="col-sm-4">
        <p>
          <a class="btn btn-success btn-block">入出金明細を表示</a>
          <a class="btn btn-default btn-block">振込・振替はこちらから</a>
        </p>
      </div>

      <div class="col-sm-12">
        <a class="btn btn-link btn-block">定期預金・住宅ローンのお申込みはこちら</a>
      </div>
    </div>
  </div>
</div>
</div>
  </body>
</html>
`)
}

func getReport(ctx *fasthttp.RequestCtx) {
	resp, err := json.Marshal(struct {
		BannedIPS   []string `json:"banned_ips"`
		LockedUsers []string `json:"locked_users"`
	}{bannedIPs(), lockedUsers()})
	if err != nil {
		log.Fatal(err)
	}
	ctx.SetContentType("application/json")
	ctx.Write(resp)
}

func main() {
	runtime.GOMAXPROCS(4)
	runtime.MemProfileRate = 1024
	http.HandleFunc("/startprof", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Create(cpuProfileFile)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		runtime.SetBlockProfileRate(1) // どれくらい遅くなるか確認する
		w.Write([]byte("profile started\n"))
	})

	http.HandleFunc("/endprof", func(w http.ResponseWriter, r *http.Request) {
		pprof.StopCPUProfile()
		runtime.SetBlockProfileRate(0)
		w.Write([]byte("profile ended\n"))

		mf, err := os.Create(memProfileFile)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		pprof.WriteHeapProfile(mf)

		bf, err := os.Create(blockProfileFile)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		pprof.Lookup("block").WriteTo(bf, 0)
	})

	go func() {
		log.Println("Listen 6060")
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	h := func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
			getIndex(ctx)
		case "/login":
			postLogin(ctx)
		case "/mypage":
			getMyPage(ctx)
		case "/report":
			getReport(ctx)
		default:
			ctx.Error("not found", fasthttp.StatusNotFound)
		}
	}

	if err := fasthttp.ListenAndServe(":8080", h); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}

func getEnv(key string, def string) string {
	v := os.Getenv(key)
	if len(v) == 0 {
		return def
	}

	return v
}

func calcPassHash(password, hash string) string {
	h := sha256.New()
	io.WriteString(h, password)
	io.WriteString(h, ":")
	io.WriteString(h, hash)

	return fmt.Sprintf("%x", h.Sum(nil))
}

func (u *User) getLastLogin() *LastLogin {
	prev, ok := PrevLoginLog[u.ID]
	if ok {
		u.LastLogin = &LastLogin{}
		u.LastLogin.Login = prev.Name
		u.LastLogin.IP = prev.IP
		u.LastLogin.CreatedAt = prev.CreatedAt
		return u.LastLogin
	}

	last, ok := LastLoginLog[u.ID]
	if ok {
		u.LastLogin = &LastLogin{}
		u.LastLogin.Login = last.Name
		u.LastLogin.IP = last.IP
		u.LastLogin.CreatedAt = last.CreatedAt
		return u.LastLogin
	}
	return nil
}

func createLoginLog(succeeded bool, remoteAddr, login string, user *User) error {
	succ := 0
	if succeeded {
		succ = 1
	}

	var userId sql.NullInt64
	if user != nil {
		userId.Int64 = int64(user.ID)
		userId.Valid = true
	}

	var ll LoginLog
	ll.CreatedAt = time.Now()
	ll.UserID = user.ID
	ll.Name = user.Login
	ll.IP = remoteAddr
	ll.Succeeded = succ
	addLoginLog(ll)

	_, err := db.Exec(
		"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
			"VALUES (?,?,?,?,?)",
		time.Now(), userId, login, remoteAddr, succ,
	)

	return err
}

func isLockedUser(user *User) (bool, error) {
	if user == nil {
		return false, nil
	}

	LoginLogMtx.Lock()
	cnt, ok := LoginFailedCountByUserID[user.ID]
	LoginLogMtx.Unlock()
	if !ok {
		cnt = 0
	}
	return UserLockThreshold <= cnt, nil
}

func isBannedIP(ip string) (bool, error) {
	LoginLogMtx.Lock()
	cnt, ok := LoginFailedCountByIP[ip]
	LoginLogMtx.Unlock()
	if !ok {
		cnt = 0
	}
	return IPBanThreshold <= cnt, nil
}

func attemptLogin(ctx *fasthttp.RequestCtx) (*User, error) {
	succeeded := false
	user := &User{}

	args := ctx.PostArgs()
	loginName := string(args.Peek("login"))
	password := string(args.Peek("password"))

	remoteAddr := ctx.RemoteAddr().String()
	if xForwardedFor := ctx.Request.Header.Peek("X-Forwarded-For"); len(xForwardedFor) > 0 {
		remoteAddr = string(xForwardedFor)
	}

	defer func() {
		createLoginLog(succeeded, remoteAddr, loginName, user)
	}()

	UsersMtx.Lock()
	u, ok := Users[loginName]
	UsersMtx.Unlock()

	if !ok {
		user = nil
	} else {
		*user = u
	}

	if banned, _ := isBannedIP(remoteAddr); banned {
		return nil, ErrBannedIP
	}

	if locked, _ := isLockedUser(user); locked {
		return nil, ErrLockedUser
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.PasswordHash != calcPassHash(password, user.Salt) {
		return nil, ErrWrongPassword
	}

	succeeded = true
	return user, nil
}

func getCurrentUser(userId interface{}) *User {
	uid, err := strconv.Atoi(fmt.Sprint(userId))
	if err != nil {
		log.Println(err)
		return nil
	}
	UsersMtx.Lock()
	user, ok := UsersID[uid]
	UsersMtx.Unlock()

	if !ok {
		return nil
	}
	return &user
}
