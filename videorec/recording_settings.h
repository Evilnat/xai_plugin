#include <sysutil/sysutil_rec.h>

#define MPEG4		0x0000
#define AVC_MP		0x1000
#define AVC_BL		0x2000
#define MJPEG		0x3000
#define M4HD		0x4000

#define SMALL		0x000
#define MIDDLE		0x100
#define LARGE		0x200
#define HD720		0x600
#define HD1080		0x700

#define _512K		0x00
#define _768K		0x10
#define _1024K		0x20
#define _1536K		0x30
#define _2048K		0x40
#define _5000K		0x60
#define _11000K		0x70
#define _20000K		0x80
#define _25000K		0x90
#define _30000K		0xA0

uint32_t * recOpt = 0;
bool recording = false;
sys_memory_container_t recContainer;

int video_setting = MJPEG + HD720 + _20000K;
int audio_setting = CELL_REC_PARAM_AUDIO_FMT_PCM_768K;
int mc_size = 7;
bool game_container = false;
char * rec_extension = "avi";

