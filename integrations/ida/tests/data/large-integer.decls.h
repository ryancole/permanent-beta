struct __crt_locale_pointers;
union _LARGE_INTEGER;

/* 7 */
typedef __crt_locale_pointers *_locale_t;

/* 8 */
#pragma pack(push, 8)
struct __crt_locale_pointers
{
  struct __crt_locale_data *locinfo;
  struct __crt_multibyte_data *mbcinfo;
};
#pragma pack(pop)

/* 13 */
typedef union _LARGE_INTEGER LARGE_INTEGER;

/* 12 */
typedef unsigned int DWORD;

/* 16 */
typedef int LONG;

/* 15 */
struct _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E
{
  DWORD LowPart;
  LONG HighPart;
};

/* 17 */
typedef __int64 LONGLONG;

/* 14 */
union _LARGE_INTEGER
{
  struct
  {
    DWORD LowPart;
    LONG HighPart;
  };
  struct
  {
    DWORD LowPart;
    LONG HighPart;
  } u;
  LONGLONG QuadPart;
};

