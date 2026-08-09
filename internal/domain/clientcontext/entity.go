package clientcontext

type Platform string

const (
	PlatformWeb     Platform = "web"
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
	PlatformUnknown Platform = "unknown"
)

type ClientContext struct {
	IPAddress string
	UserAgent string
	Platform  Platform
	OS        string
}
