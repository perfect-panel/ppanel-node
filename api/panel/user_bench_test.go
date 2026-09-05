package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func BenchmarkDecodeUserList(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("users_%d", count), func(b *testing.B) {
			users := make([]UserInfo, count)
			for i := range users {
				users[i] = UserInfo{Id: i + 1, Uuid: fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1), SpeedLimit: 100, DeviceLimit: 3}
			}
			payload, err := json.Marshal(struct {
				Code int          `json:"code"`
				Data UserListBody `json:"data"`
			}{Code: 200, Data: UserListBody{Users: users}})
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				result, err := decodeUserList(bytes.NewReader(payload))
				if err != nil || len(result) != count {
					b.Fatalf("decode = %d users, %v", len(result), err)
				}
			}
		})
	}
}
