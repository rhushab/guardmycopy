#include <stddef.h>

typedef struct {
	char *data;
	size_t len;
	char *err;
} guardmycopyPasteboardTextResult;

typedef struct {
	int ok;
	char *err;
} guardmycopyPasteboardStatus;

typedef struct {
	long long value;
	char *err;
} guardmycopyPasteboardChangeCountResult;

guardmycopyPasteboardTextResult guardmycopyPasteboardReadText(void);
guardmycopyPasteboardStatus guardmycopyPasteboardWriteText(const void *data, size_t len);
guardmycopyPasteboardChangeCountResult guardmycopyPasteboardChangeCount(void);
