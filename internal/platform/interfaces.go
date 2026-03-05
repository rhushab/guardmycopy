package platform

type Clipboard interface {
	ReadText() (string, error)
	WriteText(value string) error
}

type ForegroundApp interface {
	ActiveApp() (name string, bundleID string, err error)
}

type Notifier interface {
	Notify(title, body string) error
}
