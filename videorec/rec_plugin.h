// Mysis rec_plugin.h v0.1
class rec_plugin_interface
{
public:
	int (*DoUnk0)(); 
	int (*start)(); //RecStart
	int (*stop)(); //RecStop
	int (*close)(int isdiscard); 
	int (*geti)(int giprm);  // RecGetInfo
	int (*md)(void * mdarg, int); //RecSetInfo
	int (*etis)(int start_time_msec); //RecSetInfo
	int (*etie)(int end_time_msec); //RecSetInfo
}; rec_plugin_interface * rec_interface;