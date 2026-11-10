package limiter

import (
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

type Manager struct {
	lock     sync.RWMutex
	limiters map[string]*Limiter
}

func NewManager() *Manager {
	return &Manager{
		limiters: make(map[string]*Limiter),
	}
}

type Limiter struct {
	NodeType      string
	SpeedLimit    int
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UserLimitInfo *sync.Map      // Key: TagUUID, value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: TagUUID, value: *ratelimit.Bucket
	admitDevice   DeviceAdmission
	admission     deviceAdmissionState // guarded by aliveMu
	clock         func() time.Time
	online        map[int]map[string]*onlineDevice
	aliveMu       sync.RWMutex
	aliveList     map[int]int // Key: Uid, value: alive_ip; owned by this limiter
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
}

func (m *Manager) Add(tag string, users []panel.UserInfo, aliveList map[int]int, nodeType string) *Limiter {
	info := &Limiter{
		NodeType:      nodeType,
		clock:         time.Now,
		online:        make(map[int]map[string]*onlineDevice),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
	}
	info.UpdateAliveList(aliveList)
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := &UserLimitInfo{}
		userLimit.UID = users[i].Id
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		info.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), userLimit)
	}
	info.UUIDtoUID = uuidmap
	m.lock.Lock()
	m.limiters[tag] = info
	m.lock.Unlock()
	return info
}

func (m *Manager) Get(tag string) (info *Limiter, err error) {
	m.lock.RLock()
	info, ok := m.limiters[tag]
	m.lock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func (m *Manager) Delete(tag string) {
	m.lock.Lock()
	delete(m.limiters, tag)
	m.lock.Unlock()
}

// UpdateAliveList replaces the online counts with an owned snapshot. Callers
// may reuse their map after this method returns without changing the limiter.
func (l *Limiter) UpdateAliveList(aliveList map[int]int) {
	snapshot := maps.Clone(aliveList)
	l.aliveMu.Lock()
	l.aliveList = snapshot
	l.aliveMu.Unlock()
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	retainedUIDs := make(map[int]struct{}, len(added))
	for _, user := range added {
		retainedUIDs[user.Id] = struct{}{}
	}
	l.aliveMu.Lock()
	defer l.aliveMu.Unlock()
	for i := range deleted {
		l.UserLimitInfo.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.SpeedLimiter.Delete(format.UserTag(tag, deleted[i].Uuid))
		delete(l.UUIDtoUID, deleted[i].Uuid)
		// Changed limits are applied as delete/add of the same user. Keep the
		// panel's online count so the new device limit takes effect immediately.
		if _, retained := retainedUIDs[deleted[i].Id]; !retained {
			delete(l.aliveList, deleted[i].Id)
			delete(l.online, deleted[i].Id)
		}
	}
	for i := range added {
		userLimit := &UserLimitInfo{
			UID: added[i].Id,
		}
		if added[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = added[i].SpeedLimit
			userLimit.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = added[i].DeviceLimit
		}
		userLimit.OverLimit = false
		l.UserLimitInfo.Store(format.UserTag(tag, added[i].Uuid), userLimit)
		l.UUIDtoUID[added[i].Uuid] = added[i].Id
	}
	// In-flight grants belong to this exact user incarnation, not just a UID
	// that could have been removed and re-added while the panel was responding.
	for key, claim := range l.admission.claims {
		if !l.claimUserCurrent(claim) {
			claim.cancel()
			delete(l.admission.claims, key)
		}
	}
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}
