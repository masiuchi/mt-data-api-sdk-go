package dataapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"
)

type ErrorCode int
type Error struct {
	Message string
	Code    ErrorCode
}

const (
	AuthenticationError ErrorCode = iota + 1
)

func (e *Error) Error() string { return e.Message }

type Client struct {
	accessTokenData accessTokenData
	Opts            ClientOptions
}

type ClientOptionsStruct struct {
	OptBaseUrl    string
	OptApiVersion string
	OptClientId   string
	OptUsername   string
	OptPassword   string
}

type ClientOptions interface {
	BaseUrl() string
	ApiVersion() string
	ClientId() string
	Username() string
	Password() string
}

type RequestParameters map[string]interface{}

type Result struct {
	Error *ResultError
}

type ResultError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func (e *ResultError) Error() string { return e.Message }

type authenticationResult struct {
	Result
	SessionId     string      `json:"sessionId"`
	AccessToken   string      `json:"accessToken"`
	ExpiresInData interface{} `json:"expiresIn"`
	ExpiresIn     int         `json:"-"`
	Remember      bool        `json:"remember"`
}

type accessTokenData struct {
	authenticationResult
	startTime time.Time
}

func (d *accessTokenData) Normalize() {
	switch t := d.ExpiresInData.(type) {
	case string:
		d.ExpiresIn, _ = strconv.Atoi(t)
	case float64:
		d.ExpiresIn = int(t)
	}
}

func (o ClientOptionsStruct) BaseUrl() string {
	return o.OptBaseUrl
}

func (o ClientOptionsStruct) ApiVersion() string {
	return o.OptApiVersion
}

func (o ClientOptionsStruct) ClientId() string {
	return o.OptClientId
}

func (o ClientOptionsStruct) Username() string {
	return o.OptUsername
}

func (o ClientOptionsStruct) Password() string {
	return o.OptPassword
}

func NewClient(opts ClientOptions) Client {
	return Client{
		Opts: opts,
	}
}

func (a accessTokenData) isPrepared() bool {
	if a.AccessToken == "" {
		return false
	}

	if a.startTime.Add(time.Duration(a.ExpiresIn-10) * time.Second).Before(time.Now()) {
		return false
	}

	return true
}

func (c *Client) prepareAccessToken() error {
	if c.accessTokenData.isPrepared() {
		return nil
	}

	var data accessTokenData
	if c.accessTokenData.SessionId != "" {
		req, err := http.NewRequest("POST", c.Opts.BaseUrl()+"/v1/token", nil)
		if err != nil {
			return err
		}

		client := &http.Client{}
		req.Header.Add("X-MT-Authorization", "MTAuth sessionId="+c.accessTokenData.SessionId)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		data = accessTokenData{}
		err = json.Unmarshal(body, &data)
		if err != nil {
			return err
		}
		data.Normalize()

		if data.AccessToken == "" {
			c.accessTokenData = accessTokenData{}
			return c.prepareAccessToken()
		}
	} else {
		resp, err := http.PostForm(c.Opts.BaseUrl()+"/v1/authentication",
			url.Values{"clientId": {c.Opts.ClientId()}, "username": {c.Opts.Username()}, "password": {c.Opts.Password()}})
		if err != nil {
			return err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		data = accessTokenData{}
		err = json.Unmarshal(body, &data)
		if err != nil {
			return err
		}
		data.Normalize()

		if data.AccessToken == "" {
			c.accessTokenData = accessTokenData{}
			return &Error{
				Message: "Authentication error",
				Code:    AuthenticationError,
			}
		}
	}

	data.startTime = time.Now()
	c.accessTokenData = data

	return nil
}

func (c Client) requiresAccessToken() bool {
	return c.accessTokenData.AccessToken != "" || c.accessTokenData.SessionId != "" || c.Opts.Password() != ""
}

func marshal(v interface{}) ([]byte, error) {
	kind := reflect.TypeOf(v).Kind()
	if kind == reflect.Bool {
		return []byte("0"), nil
	} else if kind <= reflect.Float64 || kind == reflect.String {
		return []byte(fmt.Sprint(v)), nil
	} else {
		return json.Marshal(v)
	}
}

func isFileType(v interface{}) bool {
	return reflect.TypeOf(v) == reflect.TypeOf(&os.File{})
}

func (c *Client) SendRequest(method string, path string, params *RequestParameters, result interface{}) error {
	body, err := c.SendRequestAndGetJson(method, path, params, result)
	if body == nil {
		return err
	}

	err = json.Unmarshal(body, result)
	if err != nil {
		return err
	}

	errorField := reflect.ValueOf(&result).Elem().FieldByName("Error")
	var resultError *ResultError
	resultError = errorField.Interface().(*ResultError)

	if resultError != nil && resultError.Code == 401 {
		var nilError *ResultError
		errorField.Set(reflect.ValueOf(nilError))

		c.accessTokenData.AccessToken = ""

		requestUrl, err := c.getRequestUrl(method, path, params)
		if err != nil {
			return err
		}

		return c.SendRequest(method, requestUrl, params, result)
	}

	return err
}

func (c *Client) SendRequestAndGetJson(method string, path string, params *RequestParameters, result interface{}) ([]byte, error) {
	if c.requiresAccessToken() {
		err := c.prepareAccessToken()
		if err != nil {
			return nil, err
		}
	}

	var requestBody *bytes.Buffer
	var writer *multipart.Writer
	if params != nil {
		if method != "GET" {
			requestBody = &bytes.Buffer{}
			writer = multipart.NewWriter(requestBody)
			for k, v := range *params {
				if isFileType(v) {
					file := v.(*os.File)
					part, err := writer.CreateFormFile(k, filepath.Base(file.Name()))
					if err != nil {
						return nil, err
					}

					_, err = io.Copy(part, file)
					if err != nil {
						return nil, err
					}
				} else {
					data, err := marshal(v)
					if err != nil {
						return nil, err
					}
					err = writer.WriteField(k, string(data))
					if err != nil {
						return nil, err
					}
				}
			}
			writer.Close()
		}
	}

	requestUrl, err := c.getRequestUrl(method, path, params)
	if err != nil {
		return nil, err
	}

	req, err := (func() (*http.Request, error) {
		if requestBody == nil {
			return http.NewRequest(method, requestUrl, nil)
		}

		return http.NewRequest(method, requestUrl, requestBody)
	})()
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	if c.requiresAccessToken() {
		req.Header.Add("X-MT-Authorization", "MTAuth accessToken="+c.accessTokenData.AccessToken)
	}
	if writer != nil {
		req.Header.Set("Content-Type", writer.FormDataContentType())
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func (c *Client) getRequestUrl(method string, path string, params *RequestParameters) (string, error) {
	queryString, err := c.getQueryString(method, params)
	if err != nil {
		return "", err
	}
	return c.Opts.BaseUrl() + "/v" + c.Opts.ApiVersion() + path + queryString, nil
}

func (c *Client) getQueryString(method string, params *RequestParameters) (string, error) {
	if method != "GET" || params == nil || len(*params) == 0 {
		return "", nil
	}

	values := url.Values{}
	for k, v := range *params {
		data, err := marshal(v)
		if err != nil {
			return "", err
		}
		values.Add(k, string(data))
	}
	return "?" + values.Encode(), nil
}
