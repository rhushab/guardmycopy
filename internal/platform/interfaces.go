package platform

type Clipboard interface {
	ReadText() (string, error)
	WriteText(value string) error
}

type ForegroundApp interface {
	ActiveAppName() (string, error)
}

type Notifier interface {
	Notify(title, body string) error
}
