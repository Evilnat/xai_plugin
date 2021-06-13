#ifndef _X3_H
#define _X3_H

// Mysis x3.h v0.1

#define NODISC 0xFFF0
#define BDGAME 5
#define BDMOVIE 9

// _x3_xBDVDGetInstance()
class xBDVD
{
	public:
		int (*_BDInitialize)();
		int (*_BDExit)();
		int (*DoUnk2)(void *);
		int (*DoUnk3)(int *);
		int (*Execute)(int, int*, int); 
		int (*DoUnk5)(int, int*, int*);
		int (*DoUnk6)(int*, int*, uint64_t, uint64_t*);
		int (*DoUnk7)(int*, uint64_t, int, uint64_t *);
		int (*DoUnk8)(int*);
		int (*DoUnk9)(int*);
		int (*DoUnk10)(int*);
		int (*DoUnk11)(int);
		int (*DoUnk12)(int);
		int (*DoUnk13)(int*);
		int (*DoUnk14)(int*);
		int (*DoUnk15)(int*);
		int (*DoUnk16)();
		int (*DoUnk17)(void*); // title id, parental level
		int (*DoUnk18)();
		int (*GetDiscType)(); // FFF0 = no disc, 5 = bd game, 9 = bd movie
		int (*DoUnk20)();
		int (*DoUnk21)(); // sys_mutex_unlock
		int (*DoUnk22)(); // sys_mutex_trylock
		int (*DoUnk23)();
		int (*DoUnk24)(int*);
		int (*DoUnk25)(int*);
		int (*SetModeSense)(int);
		int (*GetModeSense)(int*);
		int (*DoUnk28)(void*);
		int (*DoUnk29)();
		int (*DoUnk30)();
		int (*DoUnk31)();
		int (*DoUnk32)(int);
		int (*DoUnk33)(int*);
}; 

#endif /* _X3_H */