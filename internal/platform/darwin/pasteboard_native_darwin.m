#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#include <stdlib.h>
#include <string.h>

#include "pasteboard_native_darwin.h"

static char *guardmycopyCopyError(const char *message) {
	if (message == NULL) {
		return NULL;
	}
	return strdup(message);
}

static NSPasteboard *guardmycopyGeneralPasteboard(void) {
	return [NSPasteboard generalPasteboard];
}

guardmycopyPasteboardTextResult guardmycopyPasteboardReadText(void) {
	@autoreleasepool {
		guardmycopyPasteboardTextResult result = {0};
		NSPasteboard *pasteboard = guardmycopyGeneralPasteboard();
		if (pasteboard == nil) {
			result.err = guardmycopyCopyError("native pasteboard read failed: general pasteboard unavailable");
			return result;
		}

		NSData *data = [pasteboard dataForType:NSPasteboardTypeString];
		if (data != nil) {
			NSUInteger length = [data length];
			result.len = (size_t)length;
			if (length == 0) {
				return result;
			}

			result.data = malloc(length);
			if (result.data == NULL) {
				result.err = guardmycopyCopyError("native pasteboard read failed: out of memory");
				result.len = 0;
				return result;
			}

			memcpy(result.data, [data bytes], length);
			return result;
		}

		NSString *value = [pasteboard stringForType:NSPasteboardTypeString];
		if (value == nil) {
			return result;
		}

		NSData *utf8 = [value dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
		if (utf8 == nil) {
			result.err = guardmycopyCopyError("native pasteboard read failed: clipboard text is not valid UTF-8");
			return result;
		}

		NSUInteger length = [utf8 length];
		result.len = (size_t)length;
		if (length == 0) {
			return result;
		}

		result.data = malloc(length);
		if (result.data == NULL) {
			result.err = guardmycopyCopyError("native pasteboard read failed: out of memory");
			result.len = 0;
			return result;
		}

		memcpy(result.data, [utf8 bytes], length);
		return result;
	}
}

guardmycopyPasteboardStatus guardmycopyPasteboardWriteText(const void *data, size_t len) {
	@autoreleasepool {
		guardmycopyPasteboardStatus result = {0};
		NSPasteboard *pasteboard = guardmycopyGeneralPasteboard();
		if (pasteboard == nil) {
			result.err = guardmycopyCopyError("native pasteboard write failed: general pasteboard unavailable");
			return result;
		}

		NSData *textData = [NSData dataWithBytes:data length:len];
		[pasteboard clearContents];
		if (![pasteboard setData:textData forType:NSPasteboardTypeString]) {
			result.err = guardmycopyCopyError("native pasteboard write failed: AppKit rejected clipboard update");
			return result;
		}

		result.ok = 1;
		return result;
	}
}

guardmycopyPasteboardChangeCountResult guardmycopyPasteboardChangeCount(void) {
	@autoreleasepool {
		guardmycopyPasteboardChangeCountResult result = {0};
		NSPasteboard *pasteboard = guardmycopyGeneralPasteboard();
		if (pasteboard == nil) {
			result.err = guardmycopyCopyError("native pasteboard change count failed: general pasteboard unavailable");
			return result;
		}

		result.value = (long long)[pasteboard changeCount];
		return result;
	}
}
