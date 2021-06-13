// Mysis download_plugin v0.1

// Interface 1
class download_if 
{
	public:
		int (*DoUnk0)(int);
		int (*DoUnk1)(wchar_t * url);
		int (*DoUnk2)(wchar_t * device_path);
		int (*DoUnk3)(int, wchar_t *url);
		int (*DoUnk4)(int,wchar_t * url, wchar_t *, int, int, uint64_t, uint64_t);
		int (*DoUnk5)(int,wchar_t * url, wchar_t * device_path);
		int (*DoUnk6)(wchar_t * mimeType, wchar_t *userdata);
		int (*DoUnk7)(wchar_t * url, wchar_t *mimeType, void * userdata);
		int (*DoUnk8)(void *);
		int (*DoUnk9)(void *, int, int);
		int (*DoUnk10)(uint8_t);
		int (*DoUnk11)(int);
		int (*DoUnk12)(char *);
		int (*DoUnk13)(char *);
		int (*DoUnk14)(int, void *);
		int (*DoUnk15)(int, int, int, int, uint64_t, uint64_t, uint64_t);
		int (*DoUnk16)(int, wchar_t *, wchar_t *, uint64_t, char *, char *, char *);
		int (*DoUnk17)(int);
		int (*DoUnk18)(int,void *);
}; 
