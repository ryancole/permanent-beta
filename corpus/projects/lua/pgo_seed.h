/* Forced into every Lua source by the o2-pgo flag set (recipe.psd1, PgoCl). PGO training must take the same paths
   on every run, or the profile, and so the profile-optimized build, changes from build to build. Lua randomizes
   two things the training workload touches:
   - the string-hash seed, from the clock and from addresses that ASLR moves (lstate.c);
   - table.sort's pivot for large arrays, from clock() and time() (ltablib.c).
   Without these, Lua 5.4.7's PGO build differed between two builds (838 correct on one, 834 on the next).
   Only PGO builds use this. */
#define luai_makeseed(L) 0x5eedu
#define l_randomizePivot() 0x5eedu
