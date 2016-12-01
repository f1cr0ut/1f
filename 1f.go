package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"github.com/fatih/color"
	"github.com/garyburd/go-oauth/oauth"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	PasswordString = "1[Nq2-6sK@JX3/8skaZX<R4s>aO}7|50" // must be 16, 24 or 32 bytes

	account  = flag.String("a", "", "account")
	list     = flag.String("l", "", "show list tweets")
	dotweet  = flag.String("t", "", "tweet message")
	verbose  = flag.Bool("v", false, "detail display")
	colorMode = flag.Bool("c", false, "coloring(default off)")
)

type Account struct {
	TimeZone struct {
		Name       string `json:"name"`
		UtcOffset  int    `json:"utc_offset"`
		TzinfoName string `json:"tzinfo_name"`
	} `json:"time_zone"`
	Protected                bool   `json:"protected"`
	ScreenName               string `json:"screen_name"`
	AlwaysUseHTTPS           bool   `json:"always_use_https"`
	UseCookiePersonalization bool   `json:"use_cookie_personalization"`
	SleepTime                struct {
		Enabled   bool        `json:"enabled"`
		EndTime   interface{} `json:"end_time"`
		StartTime interface{} `json:"start_time"`
	} `json:"sleep_time"`
	GeoEnabled                bool   `json:"geo_enabled"`
	Language                  string `json:"language"`
	DiscoverableByEmail       bool   `json:"discoverable_by_email"`
	DiscoverableByMobilePhone bool   `json:"discoverable_by_mobile_phone"`
	DisplaySensitiveMedia     bool   `json:"display_sensitive_media"`
	AllowContributorRequest   string `json:"allow_contributor_request"`
	AllowDmsFrom              string `json:"allow_dms_from"`
	AllowDmGroupsFrom         string `json:"allow_dm_groups_from"`
	SmartMute                 bool   `json:"smart_mute"`
	TrendLocation             []struct {
		Name        string `json:"name"`
		CountryCode string `json:"countryCode"`
		URL         string `json:"url"`
		Woeid       int    `json:"woeid"`
		PlaceType   struct {
			Name string `json:"name"`
			Code int    `json:"code"`
		} `json:"placeType"`
		Parentid int    `json:"parentid"`
		Country  string `json:"country"`
	} `json:"trend_location"`
}

type Tweet struct {
	Text       string `json:"text"`
	Identifier string `json:"id_str"`
	Source     string `json:"source"`
	CreatedAt  string `json:"created_at"`
	User       struct {
		Name            string `json:"name"`
		ScreenName      string `json:"screen_name"`
		FollowersCount  int    `json:"followers_count"`
		ProfileImageURL string `json:"profile_image_url"`
	} `json:"user"`
	Place *struct {
		ID       string `json:"id"`
		FullName string `json:"full_name"`
	} `json:"place"`
	Entities struct {
		HashTags []struct {
			Indices [2]int `json:"indices"`
			Text    string `json:"text"`
		}
		UserMentions []struct {
			Indices    [2]int `json:"indices"`
			ScreenName string `json:"screen_name"`
		} `json:"user_mentions"`
		Urls []struct {
			Indices [2]int `json:"indices"`
			URL     string `json:"url"`
		} `json:"urls"`
	} `json:"entities"`
}

type SearchMetadata struct {
	CompletedIn float64 `json:"completed_in"`
	MaxID       int64   `json:"max_id"`
	MaxIDStr    string  `json:"max_id_str"`
	NextResults string  `json:"next_results"`
	Query       string  `json:"query"`
	RefreshURL  string  `json:"refresh_url"`
	Count       int     `json:"count"`
	SinceID     int     `json:"since_id"`
	SinceIDStr  string  `json:"since_id_str"`
}

type RSS struct {
	Channel struct {
		Title       string
		Description string
		Link        string
		Item        []struct {
			Title       string
			Description string
			PubDate     string
			Link        []string
			GUID        string
			Author      string
		}
	}
}

var oauthClient = oauth.Client{
	TemporaryCredentialRequestURI: "https://api.twitter.com/oauth/request_token",
	ResourceOwnerAuthorizationURI: "https://api.twitter.com/oauth/authenticate",
	TokenRequestURI:               "https://api.twitter.com/oauth/access_token",
}

func clientAuth(requestToken *oauth.Credentials) (*oauth.Credentials, error) {
	var err error
	browser := "xdg-open"
	url := oauthClient.AuthorizationURL(requestToken, nil)

	args := []string{url}
	if runtime.GOOS == "windows" {
		browser = "rundll32.exe"
		args = []string{"url.dll,FileProtocolHandler", url}
	} else if runtime.GOOS == "darwin" {
		browser = "open"
		args = []string{url}
	} else if runtime.GOOS == "plan9" {
		browser = "plumb"
	}
	if *colorMode {
		color.Set(color.FgHiRed)
	}
	fmt.Println("Open this URL and enter PIN.")
	if *colorMode {
		color.Set(color.Reset)
	}
	fmt.Println(url)
	browser, err = exec.LookPath(browser)
	if err == nil {
		cmd := exec.Command(browser, args...)
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start command: %v", err)
		}
	}

	fmt.Print("PIN: ")
	stdin := bufio.NewScanner(os.Stdin)
	if !stdin.Scan() {
		return nil, fmt.Errorf("canceled")
	}
	accessToken, _, err := oauthClient.RequestToken(http.DefaultClient, requestToken, stdin.Text())
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %v", err)
	}
	return accessToken, nil
}

func getAccessToken(config map[string]string) (*oauth.Credentials, bool, error) {
	oauthClient.Credentials.Token = config["ClientToken"]
	oauthClient.Credentials.Secret = config["ClientSecret"]

	authorized := false
	var token *oauth.Credentials
	accessToken, foundToken := config["AccessToken"]
	accessSecret, foundSecret := config["AccessSecret"]
	if foundToken && foundSecret {
		token = &oauth.Credentials{Token: accessToken, Secret: accessSecret}
	} else {
		requestToken, err := oauthClient.RequestTemporaryCredentials(http.DefaultClient, "", nil)
		if err != nil {
			err = fmt.Errorf("failed to request temporary credentials: %v", err)
			return nil, false, err
		}
		token, err = clientAuth(requestToken)
		if err != nil {
			err = fmt.Errorf("failed to request temporary credentials: %v", err)
			return nil, false, err
		}

		config["AccessToken"] = token.Token
		config["AccessSecret"] = token.Secret
		authorized = true
	}
	return token, authorized, nil
}

func rawCall(token *oauth.Credentials, method string, uri string, opt map[string]string, res interface{}) error {
	param := make(url.Values)
	for k, v := range opt {
		param.Set(k, v)
	}
	oauthClient.SignParam(token, method, uri, param)
	var resp *http.Response
	var err error
	if method == "GET" {
		uri = uri + "?" + param.Encode()
		resp, err = http.Get(uri)
	} else {
		resp, err = http.PostForm(uri, url.Values(param))
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if res == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(&res)
}

var replacer = strings.NewReplacer(
	"\r", "",
	"\n", " ",
	"\t", " ",
)

func showTweets(tweets []Tweet, verbose bool) {
	if verbose {
		for i := len(tweets) - 1; i >= 0; i-- {
			name := tweets[i].User.Name
			user := tweets[i].User.ScreenName
			text := tweets[i].Text
			text = replacer.Replace(text)
			if *colorMode {
				color.Set(color.FgHiRed)
			}
			fmt.Println(user + ": " + name)
			if *colorMode {
				color.Set(color.Reset)
			}
			fmt.Println("  " + text)
			fmt.Println("  " + tweets[i].Identifier)
			fmt.Println("  " + tweets[i].CreatedAt)
			fmt.Println()
		}
	} else {
		for i := len(tweets) - 1; i >= 0; i-- {
			user := tweets[i].User.ScreenName
			text := tweets[i].Text
			if *colorMode {
				color.Set(color.FgHiRed)
			}
			fmt.Print(user)
			if *colorMode {
				color.Set(color.Reset)
			}
			fmt.Print(": ")
			fmt.Println(text)
		}
	}
}

func getConfig() (string, map[string]string, error) {
	dir := os.Getenv("HOME")
	if dir == "" && runtime.GOOS == "windows" {
		dir = os.Getenv("APPDATA")
		if dir == "" {
			dir = filepath.Join(os.Getenv("USERPROFILE"), "Application Data", "1f")
		}
		dir = filepath.Join(dir, "1f")
	} else {
		dir = filepath.Join(dir, ".config", "1f")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", nil, err
	}
	var file string
	if *account == "" {
		file = filepath.Join(dir, "settings.json")
	} else {
		file = filepath.Join(dir, "settings-"+*account+".json")
	}
	config := map[string]string{}

	b, err := ioutil.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return "", nil, err
	}
	if err != nil {
		config["ClientToken"] = "xJmZPMsbYBOe39OU33buDnnkw"
		config["ClientSecret"] = "FYsQdPqPNn0MHHI953LgBY2XLDY1Om0ufy7q7SPoSOXQchn9tP"
	} else {
		// decrypt
		key := []byte(PasswordString)
		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}
		decryptedText := make([]byte, len(b[aes.BlockSize:]))
		decryptStream := cipher.NewCTR(block, b[:aes.BlockSize])
		decryptStream.XORKeyStream(decryptedText, b[aes.BlockSize:])
		err = json.Unmarshal(decryptedText, &config)
		if err != nil {
			return "", nil, fmt.Errorf("could not unmarshal %v: %v", file, err)
		}
	}
	return file, config, nil
}

func loadConfigData() *oauth.Credentials {
	file, config, err := getConfig()
	if err != nil {
		log.Fatal("failed to get configuration:", err)
	}
	token, authorized, err := getAccessToken(config)
	if err != nil {
		log.Fatal("faild to get access token:", err)
	}
	if authorized {
		b, err := json.Marshal(config)
		if err != nil {
			log.Fatal("failed to store file:", err)
		}
		// create encrypt key
		key := []byte(PasswordString)
		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}
		// Create IV
		cipherText := make([]byte, aes.BlockSize+len(b))
		iv := cipherText[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			log.Fatal(err)
		}
		// encrypt
		encryptStream := cipher.NewCTR(block, iv)
		encryptStream.XORKeyStream(cipherText[aes.BlockSize:], b)
		err = ioutil.WriteFile(file, cipherText, 0700)
		if err != nil {
			log.Fatal("failed to store file:", err)
		}
	}
	return token
}

func main() {
	flag.Parse()
	fmt.Fprintf(os.Stderr, "password?\n")

	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
			log.Fatal(err)
	}
	if l := len(password); l != 16 && l != 24 && l != 32 {
		log.Fatal("invalid password length. it must be 16, 24 or 32 bytes")
	}
	PasswordString = string(password)

	token := loadConfigData()

	if len(*list) > 0 {
		part := strings.SplitN(*list, "/", 2)
		if len(part) == 1 {
			var account Account
			err := rawCall(token, "GET", "https://api.twitter.com/1.1/account/settings.json", nil, &account)
			if err != nil {
				log.Fatal("failed to get account:", err)
			}
			part = []string{account.ScreenName, part[0]}
		}
		var tweets []Tweet
		err := rawCall(token, "GET", "https://api.twitter.com/1.1/lists/statuses.json", map[string]string{"owner_screen_name": part[0], "slug": part[1]}, &tweets)
		if err != nil {
			log.Fatal("failed to get tweets:", err)
		}
		showTweets(tweets, *verbose)
	} else if *dotweet != "" {
		var tweet Tweet
		err := rawCall(token, "POST", "https://api.twitter.com/1.1/statuses/update.json", map[string]string{"status": *dotweet, "in_reply_to_status_id": ""}, &tweet)
		if err != nil {
			log.Fatal("failed to post tweet:", err)
		}
		fmt.Println("tweeted:", tweet.Identifier)
	} else if flag.NArg() == 0 {
		var tweets []Tweet
		err := rawCall(token, "GET", "https://api.twitter.com/1.1/statuses/home_timeline.json", map[string]string{}, &tweets)
		if err != nil {
			log.Fatal("failed to get tweets:", err)
		}
		showTweets(tweets, *verbose)
	}
}
