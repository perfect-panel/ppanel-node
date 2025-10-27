package panel

import (
	"fmt"
	"path"

	"encoding/json/jsontext"
	"encoding/json/v2"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users"`
}

type UserOnlineBody struct {
	Users []OnlineUser `json:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

func (c *ClientV1) GetUserList() ([]UserInfo, error) {
	const p = "/v1/server/user"
	r, err := c.Client.R().
		SetHeader("If-None-Match", c.userEtag).
		ForceContentType("application/json").
		SetDoNotParseResponse(true).
		Get(p)
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("服务端响应为空")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return nil, fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), string(body))
	}
	userlist := &UserListBody{}
	dec := jsontext.NewDecoder(r.RawResponse.Body)
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("解码用户列表失败: %w", err)
		}
		if tok.Kind() == '"' && tok.String() == "users" {
			break
		}
	}
	tok, err := dec.ReadToken()
	if err != nil {
		return nil, fmt.Errorf("解码用户列表失败: %w", err)
	}
	if tok.Kind() != '[' {
		return nil, fmt.Errorf(`解码用户列表失败: "users"非数组`)
	}
	for dec.PeekKind() != ']' {
		val, err := dec.ReadValue()
		if err != nil {
			return nil, fmt.Errorf("解码用户列表失败: 读取用户对象失败: %w", err)
		}
		var u UserInfo
		if err := json.Unmarshal(val, &u); err != nil {
			return nil, fmt.Errorf("解码用户列表失败: 读取用户对象失败: %w", err)
		}
		userlist.Users = append(userlist.Users, u)
	}
	c.userEtag = r.Header().Get("ETag")
	return userlist.Users, nil
}

func (c *ClientV1) GetUserAlive() (map[int]int, error) {
	c.AliveMap = &AliveMap{}
	c.AliveMap.Alive = make(map[int]int)
	/*const path = "/v1/server/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err != nil || r.StatusCode() >= 399 {
		c.AliveMap.Alive = make(map[int]int)
	}
	if r == nil || r.RawResponse == nil {
		fmt.Printf("received nil response or raw response")
		c.AliveMap.Alive = make(map[int]int)
	}
	defer r.RawResponse.Body.Close()
	if err := json.Unmarshal(r.Body(), c.AliveMap); err != nil {
		//fmt.Printf("unmarshal user alive list error: %s", err)
		c.AliveMap.Alive = make(map[int]int)
	}
	*/
	return c.AliveMap.Alive, nil
}

type ServerPushUserTrafficRequest struct {
	Traffic []UserTraffic `json:"traffic"`
}

type UserTraffic struct {
	UID      int   `json:"uid"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

func (c *ClientV1) ReportUserTraffic(userTraffic *[]UserTraffic) error {
	traffic := make([]UserTraffic, 0)
	for _, t := range *userTraffic {
		traffic = append(traffic, UserTraffic{
			UID:      t.UID,
			Upload:   t.Upload,
			Download: t.Download,
		})
	}
	p := "/v1/server/push"
	req := ServerPushUserTrafficRequest{
		Traffic: traffic,
	}
	r, err := c.Client.R().
		SetBody(req).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), string(body))
	}

	return nil
}

func (c *ClientV1) ReportNodeOnlineUsers(data *[]OnlineUser) error {
	const p = "/v1/server/online"
	users := UserOnlineBody{
		Users: *data,
	}
	r, err := c.Client.R().
		SetBody(users).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), string(body))
	}

	return nil
}
