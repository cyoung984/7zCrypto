#include "PEMCleanser.h"

// return value is number of bytes being waited on (which is always 0 here)
size_t PEMCleanser::Put2(const byte *begin, size_t length, int messageEnd, bool blocking)
{
	if (length == 0) 
		return AttachedTransformation()->Put2(begin, length, messageEnd, blocking);

	size_t skipped = 0;
	while (skipped < length) {
		byte b = begin[skipped];
		if (b == '-') ignoreUntilNewLine = true;
		else if (b == '\n') { 
			ignoreUntilNewLine = false; 
			skipped++;
		}
		if (!ignoreUntilNewLine) break;
		else skipped++;
	}
	return ignoreUntilNewLine || skipped == length ? 0 :
		AttachedTransformation()->Put2(begin + skipped,	length - skipped, 
		messageEnd, blocking);
}