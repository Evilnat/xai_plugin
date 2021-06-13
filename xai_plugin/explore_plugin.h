// Mysis explore_plugin.h v0.1
class explore_plugin_interface
{
	public:
		int (*DoUnk0)(int);
		int (*DoUnk1)();
		int (*DoUnk2)();
		int (*DoUnk3)();
		int (*DoUnk4)(); //
		int (*DoUnk5)(int *); // ptr = { <list>, count }
		int (*DoUnk6)(char *, void *, int);
		int (*DoUnk7)(int, int);
		int (*DoUnk8)(void *, int, int);
		int (*DoUnk9)(void *, int, int);
		int (*DoUnk10)(int*, char *);
		int (*DoUnk11)(char *, char *, int *);
		int (*DoUnk12)(void *);
		int (*DoUnk13)(int);
		int (*DoUnk14)(int);
		int (*DoUnk15)(int, int, int);
		int (*DoUnk16)(int, int, int);
		int (*DoUnk17)(int, int, int*, int*, int*);
		int (*DoUnk18)(int);
		int (*DoUnk19)(int);
		int (*DoUnk20)(int, uint64_t);
		int (*DoUnk21)(void *);
		int (*DoUnk22)(void *);
		int (*DoUnk23)(); //
		int (*DoUnk24)();
		int (*DoUnk25)(); // get target id check
		int (*DoUnk26)(char *, char *);
		int (*DoUnk27)(void *);
		int (*DoUnk28)(char *, void *);
		int (*DoUnk29)(char *, void *);
}; 