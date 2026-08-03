//go:build kerberos
// +build kerberos

package gosasl

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/beltran/gssapi"
)

// GSSAPIMechanism corresponds to GSSAPI SASL mechanism
type GSSAPIMechanism struct {
	config           *MechanismConfig
	host             string
	user             string
	service          string
	negotiationStage int
	context          *GSSAPIContext
	qop              byte
	supportedQop     uint8
	serverMaxLength  int
	UserSelectQop    uint8
	MaxLength        int
}

// NewGSSAPIMechanism returns a new GSSAPIMechanism
func NewGSSAPIMechanism(service string) (mechanism *GSSAPIMechanism, err error) {
	context, err := newGSSAPIContext()
	if err != nil {
		return nil, err
	}
	mechanism = &GSSAPIMechanism{
		config:           newDefaultConfig("GSSAPI"),
		service:          service,
		negotiationStage: 0,
		context:          context,
		supportedQop:     QOP_TO_FLAG[AUTH] | QOP_TO_FLAG[AUTH_CONF] | QOP_TO_FLAG[AUTH_INT],
		MaxLength:        DEFAULT_MAX_LENGTH,
		UserSelectQop:    QOP_TO_FLAG[AUTH] | QOP_TO_FLAG[AUTH_INT] | QOP_TO_FLAG[AUTH_CONF],
	}
	return
}

func (m *GSSAPIMechanism) start() ([]byte, error) {
	return m.step(nil)
}

func (m *GSSAPIMechanism) step(challenge []byte) ([]byte, error) {
	var serviceHostQualified string
	var fullServiceName string
	// Allows to use a service principal designated for another host to still be used.
	// Useful for containerized environments.
	serviceHostQualified = os.Getenv("SERVICE_HOST_QUALIFIED")
	if len(serviceHostQualified) > 0 {
		fullServiceName = m.service + "/" + serviceHostQualified
	} else {
		fullServiceName = m.service + "/" + m.host
	}

	if m.negotiationStage == 0 {
		err := initClientContext(m.context, fullServiceName, nil)
		if err == gssapi.ErrContinueNeeded {
			err = nil
		}
		m.negotiationStage = 1
		return m.context.token, err

	} else if m.negotiationStage == 1 {
		err := initClientContext(m.context, fullServiceName, challenge)
		if err != nil && err != gssapi.ErrContinueNeeded {
			return nil, err
		}

		if m.context.contextId != nil {
			// InquireContext 在 native 侧返回两个需要显式 gss_release_name 的 Name。
			// 原实现只取 srcName 且三个返回值全部丢弃，srcName/targetName 会在每次
			// 成功 Kerberos 握手后永久滞留 native heap，Go GC 无法回收，表现为
			// RSS/WSS 随建连次数持续上涨。mechType 指向 GSS 库的静态 OID，Release
			// 对其是 no-op，但仍统一调用以兼容依赖后续实现。
			srcName, targetName, _, mechType, _, _, _, inquireErr := m.context.contextId.InquireContext()
			if srcName != nil {
				defer srcName.Release()
			}
			if targetName != nil {
				defer targetName.Release()
			}
			if mechType != nil {
				defer mechType.Release()
			}
			if inquireErr == nil && srcName != nil {
				m.user = srcName.String()
			}
		}
		if m.user != "" {
			// Check if the context is available. If the user has set the flags
			// it will fail, although at this point we could know that the negotiation won't succeed
			if !m.context.integAvail() && !m.context.confAvail() {
				log.Println("No security layer can be established, authentication is still possible")
			}
			m.negotiationStage = 2
		}
		return m.context.token, nil
	} else if m.negotiationStage == 2 {
		data, err := m.context.unwrap(challenge)
		if err != nil {
			return nil, err
		}
		if len(data) != 4 {
			return nil, fmt.Errorf("Decoded data should have length for at this stage")
		}
		qopBits := data[0]
		data[0] = 0
		m.serverMaxLength = int(binary.BigEndian.Uint32(data))

		m.qop, err = m.selectQop(qopBits)
		// The client doesn't support or want any of the security layers offered by the server
		if err != nil {
			m.MaxLength = 0
		}

		header := make([]byte, 4)
		maxLength := m.serverMaxLength
		if m.MaxLength < m.serverMaxLength {
			maxLength = m.MaxLength
		}

		headerInt := (uint(m.qop) << 24) | uint(maxLength)

		binary.BigEndian.PutUint32(header, uint32(headerInt))

		// FLAG_BYTE + 3 bytes of length + user or authority
		var name string
		if name = m.user; m.config.AuthorizationID != "" {
			name = m.config.AuthorizationID
		}
		out := append(header, []byte(name)...)
		wrappedOut, err := m.context.wrap(out, false)

		m.config.complete = true
		return wrappedOut, err
	}
	return nil, fmt.Errorf("Error, this code should be unreachable")
}

func (m *GSSAPIMechanism) selectQop(qopByte byte) (byte, error) {
	availableQops := m.UserSelectQop & m.supportedQop & qopByte
	for _, qop := range []byte{QOP_TO_FLAG[AUTH_CONF], QOP_TO_FLAG[AUTH_INT], QOP_TO_FLAG[AUTH]} {
		if qop&availableQops != 0 {
			return qop, nil
		}
	}
	return byte(0), fmt.Errorf("No qop satisfying all the conditions where found")
}

// replaceSPNHostWildcard substitutes the special string '_HOST' in the given
// SPN for the given (current) host.
func replaceSPNHostWildcard(spn, host string) string {
	res := krbSPNHost.FindStringSubmatchIndex(spn)
	if res == nil || res[2] == -1 {
		return spn
	}
	return spn[:res[2]] + host + spn[res[3]:]
}

func (m GSSAPIMechanism) encode(outgoing []byte) ([]byte, error) {
	if m.qop == QOP_TO_FLAG[AUTH] {
		return outgoing, nil
	} else {
		var conf_flag bool = false
		if m.qop == QOP_TO_FLAG[AUTH_CONF] {
			conf_flag = true
		}
		return m.context.wrap(deepCopy(outgoing), conf_flag)
	}
}

func (m GSSAPIMechanism) decode(incoming []byte) ([]byte, error) {
	if m.qop == QOP_TO_FLAG[AUTH] {
		return incoming, nil
	}
	return m.context.unwrap(deepCopy(incoming))
}

func deepCopy(original []byte) []byte {
	copied := make([]byte, len(original))
	for i, el := range original {
		copied[i] = el
	}
	return copied
}

func (m GSSAPIMechanism) dispose() {
	m.context.dispose()
}

func (m GSSAPIMechanism) getConfig() *MechanismConfig {
	return m.config
}

type GSSAPIContext struct {
	DebugLog       bool
	RunAsService   bool
	ServiceName    string
	ServiceAddress string

	gssapi.Options

	*gssapi.Lib `json:"-"`

	// Service credentials loaded from keytab
	credential     *gssapi.CredId
	token          []byte
	continueNeeded bool
	contextId      *gssapi.CtxId
	reqFlags       uint32
	availFlags     uint32
}

// GSSAPI 动态库 (libgssapi_krb5.so) 是进程级、无状态的纯函数库: 所有租户相关的
// 状态都封装在 per-connection 的 gss_cred_id_t / gss_ctx_id_t handle 中, 库本身
// 不持有任何用户身份。因此在整个进程内只 dlopen 一次并常驻, 是GSSAPI/MIT-krb5
// 的标准用法。
//
// 之前的实现把 dlopen/dlclose 放在每个连接的生命周期里(dispose 调用 Lib.Unload),
// 而 dlclose 是进程全局的引用计数操作: 多租户并发下, 某个连接关闭时若把全局引用
// 计数打到 0, libgssapi_krb5.so 会被 munmap, 而其它goroutine 保存在ftable 里
// 指向该代码段的函数指针 (Fp_gss_*) 立刻变为悬空指针, 下一次调用即触发 SIGSEGV
// (SEGV_MAPERR, signal arrived during cgo execution)。此外 MIT krb5 本身注册了
// atexit/TLS destructor、com_err 错误表并会内部 dlopen mechanism plugin, 根本
// 不支持被 dlclose。
//
// 单例化后: 函数指针在进程生命周期内恒定有效, 从结构上消除 use-after-unload;
// 各租户的隔离仍完全由各自独立的 credential / contextId handle 保证, 多个 handle
// 共享同一份只读函数表不会造成任何身份串号(等价于多线程共享同一个 libc)。
var (
	globalLib     *gssapi.Lib
	globalLibOnce sync.Once
	globalLibErr  error
)

// loadSharedLib 进程级懒加载唯一一份 GSSAPI 动态库并返回, 永不 Unload。
func loadSharedLib(debug bool, prefix string) (*gssapi.Lib, error) {
	globalLibOnce.Do(func() {
		max := gssapi.Err + 1
		if debug {
			max = gssapi.MaxSeverity
		}
		pp := make([]gssapi.Printer, 0, max)
		for i := gssapi.Severity(0); i < max; i++ {
			p := log.New(os.Stderr,
				fmt.Sprintf("%s: %s\t", prefix, i),
				log.LstdFlags)
			pp = append(pp, p)
		}
		globalLib, globalLibErr = gssapi.Load(&gssapi.Options{Printers: pp})
	})
	return globalLib, globalLibErr
}

func newGSSAPIContext() (*GSSAPIContext, error) {
	var c = &GSSAPIContext{
		reqFlags: uint32(gssapi.GSS_C_INTEG_FLAG) + uint32(gssapi.GSS_C_MUTUAL_FLAG) + uint32(gssapi.GSS_C_SEQUENCE_FLAG) + uint32(gssapi.GSS_C_CONF_FLAG),
	}
	prefix := "gosasl-client"
	if err := loadlib(c.DebugLog, prefix, c); err != nil {
		return nil, err
	}

	j, _ := json.MarshalIndent(c, "", "  ")
	c.Debug(fmt.Sprintf("Config: %s", string(j)))
	return c, nil
}

// InitClientContext initializes the context and gets the response(token)
// to send to the server
func initClientContext(c *GSSAPIContext, service string, inputToken []byte) error {
	c.ServiceName = service

	var _inputToken *gssapi.Buffer
	var err error
	if inputToken == nil {
		_inputToken = c.GSS_C_NO_BUFFER
	} else {
		_inputToken, err = c.MakeBufferBytes(inputToken)
		defer _inputToken.Release()
		if err != nil {
			return err
		}
	}

	preparedName := prepareServiceName(c)
	defer preparedName.Release()

	contextId, actualMechType, token, outputRetFlags, _, err := c.InitSecContext(
		nil,
		c.contextId,
		preparedName,
		c.GSS_MECH_KRB5,
		c.reqFlags,
		0,
		c.GSS_C_NO_CHANNEL_BINDINGS,
		_inputToken)
	// InitSecContext may return a partial context and an error token together
	// with an error. Take ownership before returning so Dispose can release the
	// context, and release all per-call outputs here.
	if actualMechType != nil {
		defer actualMechType.Release()
	}
	if token != nil {
		defer token.Release()
		c.token = token.Bytes()
	} else {
		c.token = nil
	}
	if contextId != nil {
		c.contextId = contextId
	}
	c.availFlags = outputRetFlags
	return err
}

// Wrap calls GSS_Wrap
func (c *GSSAPIContext) wrap(original []byte, conf_flag bool) (wrapped []byte, err error) {
	if original == nil {
		return
	}
	_original, err := c.MakeBufferBytes(original)
	defer _original.Release()

	if err != nil {
		return nil, err
	}
	_, wrappedBuffer, err := c.contextId.Wrap(conf_flag, gssapi.GSS_C_QOP_DEFAULT, _original)
	defer wrappedBuffer.Release()
	if err != nil {
		return nil, err
	}
	return wrappedBuffer.Bytes(), nil
}

// Unwrap calls GSS_Unwrap
func (c *GSSAPIContext) unwrap(original []byte) (unwrapped []byte, err error) {
	if original == nil {
		return
	}
	_original, err := c.MakeBufferBytes(original)
	defer _original.Release()

	if err != nil {
		return nil, err
	}
	unwrappedBuffer, _, _, err := c.contextId.Unwrap(_original)
	defer unwrappedBuffer.Release()
	if err != nil {
		return nil, err
	}
	return unwrappedBuffer.Bytes(), nil
}

// Dispose releases the acquired memory and destroys sensitive information
//
// 只释放 per-connection 的 native 资源: 先释放 security context
// (gss_delete_sec_context), 再释放凭据(若曾从 keytab 加载 gss_acquire_cred)。
// 释放后置空指针以保证多次调用幂等, 避免对已释放的 native 资源重复操作。
//
// 关键: 绝不在这里调用 c.Lib.Unload()。libgssapi_krb5.so 是进程级共享的单例
// (见 loadSharedLib的说明), dlclose 会 munmap 掉仍被其它并发连接使用的函数
// 代码段, 造成 use-after-unload 崩溃; 且 MIT krb5 本身不支持被 dlclose。这里
// 仅解除本context 对共享 Lib 的引用, 不触碰库的加载状态。
func (c *GSSAPIContext) dispose() error {
	var firstErr error

	if c.contextId != nil {
		// CtxId.Release() 是 DeleteSecContext() 的别名, 最终调用 gss_delete_sec_context。
		if err := c.contextId.Release(); err != nil {
			firstErr = err
		}
		c.contextId = nil
	}

	if c.credential != nil {
		if err := c.credential.Release(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.credential = nil
	}

	// 不Unload 共享库, 仅解除引用。
	c.Lib = nil

	c.token = nil
	return firstErr
}

// IntegAvail returns true in the integ_flag is available and therefore a security layer can be established
func (c *GSSAPIContext) integAvail() bool {
	return c.availFlags&uint32(gssapi.GSS_C_INTEG_FLAG) != 0
}

// ConfAvail returns true in the conf_flag is available and therefore a confidentiality layer can be established
func (c *GSSAPIContext) confAvail() bool {
	return c.availFlags&uint32(gssapi.GSS_C_CONF_FLAG) != 0
}

// loadlib 让每个 context 引用进程级唯一的共享 Lib(懒加载, 永不卸载),
// 而非各自 dlopen 一份。这样所有租户共享同一份只读函数表, 消除 dlclose 竞态。
func loadlib(debug bool, prefix string, c *GSSAPIContext) error {
	lib, err := loadSharedLib(debug, prefix)
	if err != nil {
		return err
	}
	c.Lib = lib
	return nil
}

func prepareServiceName(c *GSSAPIContext) *gssapi.Name {
	if c.ServiceName == "" {
		log.Fatal("Need a --service-name")
	}

	nameBuf, err := c.MakeBufferString(c.ServiceName)
	defer nameBuf.Release()
	if err != nil {
		log.Fatal(err)
	}

	name, err := nameBuf.Name(c.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		log.Fatal(err)
	}
	if name.String() != c.ServiceName {
		log.Fatalf("name: got %q, expected %q", name.String(), c.ServiceName)
	}

	return name
}
