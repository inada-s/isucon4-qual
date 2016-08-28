package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
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

	"github.com/go-martini/martini"
	_ "github.com/go-sql-driver/mysql"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessions"
)

var (
	cpuProfileFile   = "/tmp/cpu.pprof"
	memProfileFile   = "/tmp/mem.pprof"
	blockProfileFile = "/tmp/block.pprof"

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
	Users map[string]User
	UsersID map[int]User
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
			i+1         ID
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

	m := martini.Classic()

	store := sessions.NewCookieStore([]byte("secret-isucon"))
	m.Use(sessions.Sessions("isucon_go_session", store))

	m.Use(martini.Static("./public"))
	m.Use(render.Renderer(render.Options{
		Layout: "layout",
	}))

	m.Get("/", func(r render.Render, session sessions.Session) {
		r.HTML(200, "index", map[string]string{"Flash": getFlash(session, "notice")})
	})

	m.Post("/login", func(req *http.Request, r render.Render, session sessions.Session) {
		user, err := attemptLogin(req)

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

			session.Set("notice", notice)
			r.Redirect("/")
			return
		}

		session.Set("user_id", strconv.Itoa(user.ID))
		r.Redirect("/mypage")
	})

	m.Get("/mypage", func(r render.Render, session sessions.Session) {
		currentUser := getCurrentUser(session.Get("user_id"))

		if currentUser == nil {
			session.Set("notice", "You must be logged in")
			r.Redirect("/")
			return
		}

		currentUser.getLastLogin()
		r.HTML(200, "mypage", currentUser)
	})

	m.Get("/report", func(r render.Render) {
		r.JSON(200, map[string][]string{
			"banned_ips":   bannedIPs(),
			"locked_users": lockedUsers(),
		})
	})

	http.ListenAndServe(":8080", m)
}

func getEnv(key string, def string) string {
	v := os.Getenv(key)
	if len(v) == 0 {
		return def
	}

	return v
}

func getFlash(session sessions.Session, key string) string {
	value := session.Get(key)

	if value == nil {
		return ""
	} else {
		session.Delete(key)
		return value.(string)
	}
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

	/*
		// ログインログからこのユーザの前回の(１回前の)成功ログインを返す.
		// ただし初回ログインのときはそのログインを返す.
		rows, err := db.Query(
			"SELECT login, ip, created_at FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2",
			u.ID,
		)

		if err != nil {
			return nil
		}

		defer rows.Close()
		for rows.Next() {
			u.LastLogin = &LastLogin{}
			err = rows.Scan(&u.LastLogin.Login, &u.LastLogin.IP, &u.LastLogin.CreatedAt)
			if err != nil {
				u.LastLogin = nil
				return nil
			}
		}

		return u.LastLogin
	*/
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

	/*
		var ni sql.NullInt64
		// ログインログからこのユーザのログイン失敗回数を返す.
		// ただしログインに成功するとログイン失敗回数は0となる.
		row := db.QueryRow(
			"SELECT COUNT(1) AS failures FROM login_log WHERE "+
				"user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND "+
				"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
			user.ID, user.ID,
		)
		err := row.Scan(&ni)

		switch {
		case err == sql.ErrNoRows:
			return false, nil
		case err != nil:
			return false, err
		}

		return UserLockThreshold <= int(ni.Int64), nil
	*/
}

func isBannedIP(ip string) (bool, error) {

	LoginLogMtx.Lock()
	cnt, ok := LoginFailedCountByIP[ip]
	LoginLogMtx.Unlock()
	if !ok {
		cnt = 0
	}
	return IPBanThreshold <= cnt, nil

	/*
		var ni sql.NullInt64
		// ログインログからこのIPのログイン失敗回数を返す.
		// ただしログインに成功するとログイン失敗回数は0となる.
		row := db.QueryRow(
			"SELECT COUNT(1) AS failures FROM login_log WHERE "+"ip = ? AND id > IFNULL( (select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
			ip, ip,
		)
		err := row.Scan(&ni)

		switch {
		case err == sql.ErrNoRows:
			return false, nil
		case err != nil:
			return false, err
		}

		return IPBanThreshold <= int(ni.Int64), nil
	*/
}

func attemptLogin(req *http.Request) (*User, error) {
	succeeded := false
	user := &User{}

	loginName := req.PostFormValue("login")
	password := req.PostFormValue("password")

	remoteAddr := req.RemoteAddr
	if xForwardedFor := req.Header.Get("X-Forwarded-For"); len(xForwardedFor) > 0 {
		remoteAddr = xForwardedFor
	}

	defer func() {
		createLoginLog(succeeded, remoteAddr, loginName, user)
	}()

	/*
	row := db.QueryRow(
		"SELECT id, login, password_hash, salt FROM users WHERE login = ?",
		loginName,
	)
	err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	switch {
	case err == sql.ErrNoRows:
		user = nil
	case err != nil:
		return nil, err
	}
	*/

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
	/*
	user := &User{}
	row := db.QueryRow(
		"SELECT id, login, password_hash, salt FROM users WHERE id = ?",
		userId,
	)
	err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	if err != nil {
		return nil
	}
	*/

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

func bannedIPs() []string {
	ips := []string{}

	rows, err := db.Query(
		"SELECT ip FROM "+
			"(SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) "+
			"AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?",
		IPBanThreshold,
	)

	if err != nil {
		return ips
	}

	defer rows.Close()
	for rows.Next() {
		var ip string

		if err := rows.Scan(&ip); err != nil {
			return ips
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return ips
	}

	rowsB, err := db.Query(
		"SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip",
	)

	if err != nil {
		return ips
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var ip string
		var lastLoginId int

		if err := rows.Scan(&ip, &lastLoginId); err != nil {
			return ips
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id",
			ip, lastLoginId,
		).Scan(&count)

		if err != nil {
			return ips
		}

		if IPBanThreshold <= count {
			ips = append(ips, ip)
		}
	}
	if err := rowsB.Err(); err != nil {
		return ips
	}

	return ips
}

func lockedUsers() []string {
	userIds := []string{}

	rows, err := db.Query(
		"SELECT user_id, login FROM "+
			"(SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) "+
			"AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?",
		UserLockThreshold,
	)

	if err != nil {
		return userIds
	}

	defer rows.Close()
	for rows.Next() {
		var userId int
		var login string

		if err := rows.Scan(&userId, &login); err != nil {
			return userIds
		}
		userIds = append(userIds, login)
	}
	if err := rows.Err(); err != nil {
		return userIds
	}

	rowsB, err := db.Query(
		"SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id",
	)

	if err != nil {
		return userIds
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var userId int
		var login string
		var lastLoginId int

		if err := rowsB.Scan(&userId, &login, &lastLoginId); err != nil {
			return userIds
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id",
			userId, lastLoginId,
		).Scan(&count)

		if err != nil {
			return userIds
		}

		if UserLockThreshold <= count {
			userIds = append(userIds, login)
		}
	}
	if err := rowsB.Err(); err != nil {
		return userIds
	}

	return userIds
}
