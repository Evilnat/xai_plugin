// Mysis impose_plugin.h v0.1
class impose_plugin_interface
{
public:
	int (*DoUnk0)(int sod, void *);	// screen of death
	int (*DoUnk1)();				// 
	int (*DoUnk2)();				// blankscreen
	int (*DoUnk3)(int);				// impose page
	int (*DoUnk4)(int);				// game exit?
	int (*DoUnk5)(char);			// controller setting game exit?
	int (*DoUnk6)();				// pageclose blankscreen
	int (*DoUnk7)(int, float, float);	// pad battery notice
	int (*DoUnk8)(float);			// pad battery notice float
	int (*DoUnk9)(int);				// 
	int (*DoUnk10)();				// confirm gameupdate dialog
	int (*DoUnk11)();				// wait for background task
	int (*DoUnk12)();				// error text plane
	int (*DoUnk13)(int);			// start_xmb
	int (*DoUnk14)();				// notification btn navi
	int (*DoUnk15)(int);			// game exit widget
	int (*DoUnk16)(int);			// vibrationEnable flag
	int (*DoUnk17)(int);			// psbutton notification ?
	int (*DoUnk18)();				// 
}; impose_plugin_interface * impose_interface;