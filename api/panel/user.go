package panel

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"path"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
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

func (c *NodeClient) GetUserList(ctx context.Context) ([]UserInfo, error) {
	if c.UseProtobuf {
		return c.getUserListProtobuf(ctx)
	}
	const p = "/v1/server/user"
	r, err := c.Client.R().
		SetContext(ctx).
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
	users, err := decodeUserList(r.RawResponse.Body)
	if err != nil {
		return nil, err
	}
	c.userEtag = r.Header().Get("ETag")
	return users, nil
}

func decodeUserList(body io.Reader) ([]UserInfo, error) {
	dec := jsontext.NewDecoder(body)
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("解码用户列表失败: %w", err)
		}
		if tok.Kind() == '"' && tok.String() == "users" {
			break
		}
	}
	if dec.PeekKind() != '[' {
		return nil, fmt.Errorf(`解码用户列表失败: "users"非数组`)
	}
	// Nil is reserved for HTTP 304; an empty array must revoke all users.
	users := make([]UserInfo, 0)
	if err := json.UnmarshalDecode(dec, &users); err != nil {
		return nil, fmt.Errorf("解码用户列表失败: %w", err)
	}
	return users, nil
}

func (c *NodeClient) getUserListProtobuf(ctx context.Context) ([]UserInfo, error) {
	const p = "/v1/server/user"
	r, err := c.Client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("Accept", protobufContentType).
		Get(p)
	if err != nil {
		return nil, fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	if err := checkHTTPResponse(r, path.Join(c.APIHost+p)); err != nil {
		return nil, err
	}
	if r.StatusCode() == 304 {
		return nil, nil
	}

	message := &serverv1.GetServerUserListResponse{}
	if err := proto.Unmarshal(r.Body(), message); err != nil {
		return nil, fmt.Errorf("解码 Protobuf 用户列表失败: %w", err)
	}
	if err := checkPanelEnvelope(int(message.Code), message.Message, path.Join(c.APIHost+p)); err != nil {
		return nil, err
	}
	if message.Data == nil {
		return nil, fmt.Errorf("用户列表为空")
	}
	users := make([]UserInfo, 0, len(message.Data.Users))
	for _, user := range message.Data.Users {
		if user == nil {
			continue
		}
		users = append(users, UserInfo{
			Id:          int(user.Id),
			Uuid:        user.Uuid,
			SpeedLimit:  int(user.SpeedLimit),
			DeviceLimit: int(user.DeviceLimit),
		})
	}
	c.userEtag = r.Header().Get("ETag")
	return users, nil
}

func (c *NodeClient) GetUserAlive() (map[int]int, error) {
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

func (c *NodeClient) ReportUserTraffic(ctx context.Context, userTraffic *[]UserTraffic) error {
	if c.UseProtobuf {
		return c.reportUserTrafficProtobuf(ctx, userTraffic)
	}
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
		SetContext(ctx).
		SetBody(req).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}

func (c *NodeClient) reportUserTrafficProtobuf(ctx context.Context, userTraffic *[]UserTraffic) error {
	const p = "/v1/server/push"
	traffic := make([]*serverv1.UserTraffic, 0, len(*userTraffic))
	for _, item := range *userTraffic {
		traffic = append(traffic, &serverv1.UserTraffic{
			UserId:   int64(item.UID),
			Upload:   item.Upload,
			Download: item.Download,
		})
	}
	request := c.Client.R().SetContext(ctx)
	if err := setProtobufRequestBody(request, &serverv1.PushUserTrafficRequest{Traffic: traffic}); err != nil {
		return err
	}
	r, err := request.Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}

func (c *NodeClient) ReportNodeOnlineUsers(ctx context.Context, data *[]OnlineUser) error {
	if c.UseProtobuf {
		return c.reportNodeOnlineUsersProtobuf(ctx, data)
	}
	const p = "/v1/server/online"
	users := UserOnlineBody{
		Users: *data,
	}
	r, err := c.Client.R().
		SetContext(ctx).
		SetBody(users).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}

func (c *NodeClient) reportNodeOnlineUsersProtobuf(ctx context.Context, data *[]OnlineUser) error {
	const p = "/v1/server/online"
	users := make([]*serverv1.OnlineUser, 0, len(*data))
	for _, item := range *data {
		users = append(users, &serverv1.OnlineUser{UserId: int64(item.UID), Ip: item.IP})
	}
	request := c.Client.R().SetContext(ctx)
	if err := setProtobufRequestBody(request, &serverv1.PushOnlineUsersRequest{Users: users}); err != nil {
		return err
	}
	r, err := request.Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), err)
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}
