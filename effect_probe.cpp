// EnchantEffectProbe（観察専用）
// MobEffect（効果）の関数表9番と、HealthAttributeDelegate（体力の値が変わる処理）の4〜6番、
// HungerAttributeDelegate の3番に観察用の差し替えを入れ、呼ばれたときの引数をログに書くだけの調査MODです。
// 戻り値は一切書き換えません。最後に元の関数へ同じ引数のまま引き渡す（末尾呼び出し）ので、
// 戻り値の型(float/int/double/void)に関係なく、ゲーム側には元の値がそのまま返ります。
//
// 引数は整数レジスタ6個(a〜e)と、小数レジスタ3個(f0〜f2)を読みます（小数は double としてと、
// 下位32bitを float としての両方で記録）。
// 効果の9番だけは「純粋な計算」とみなして、ログ用に元の関数を追加で2回呼び、戻り値も記録します。
// 体力・満腹度の処理は状態を変える可能性があるため、追加呼び出しはしません（引数のみ記録）。
//
// ログ: /storage/emulated/0/Android/media/<ランチャー>/EnchantEffectProbe/log.txt

#include <android/log.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <strings.h>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "EnchantEffectProbe", __VA_ARGS__)

#if defined(__clang__)
#define TAILCALL [[clang::musttail]]
#else
#define TAILCALL
#endif

static const uintptr_t kLibSpan = 0x20000000;
static const int kLogFirst = 40;   // 最初のN回は全部記録
static const int kLogEvery = 500;  // 以降はN回に1回だけ記録

struct Section { uintptr_t addr; size_t size; };
static char gLogPath[700] = {0};

typedef double (*FnD)(void*, long, long, long, long, long, double, double, double);
typedef int (*FnI)(void*, long, long, long, long, long, double, double, double);

static void Log(const char* fmt, ...) {
  if (!gLogPath[0]) return;
  FILE* f = fopen(gLogPath, "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fputc('\n', f);
  fclose(f);
}

static float LowFloat(double x) {
  uint64_t u;
  memcpy(&u, &x, sizeof(u));
  uint32_t lo = (uint32_t)(u & 0xffffffffu);
  float r;
  memcpy(&r, &lo, sizeof(r));
  return r;
}

static bool ShouldLog(int n) { return n <= kLogFirst || n % kLogEvery == 0; }

#define ARGS void* self, long a, long b, long c, long d, long e, double f0, double f1, double f2
#define PASS self, a, b, c, d, e, f0, f1, f2

// 効果(MobEffect)の9番: 戻り値も記録する
#define DEFINE_EFFECT_HOOK(NAME)                                                              \
  static void* gOrig_##NAME = nullptr;                                                        \
  static std::atomic<int> gCalls_##NAME{0};                                                   \
  static double Hook_##NAME(ARGS) {                                                           \
    int n = ++gCalls_##NAME;                                                                  \
    if (ShouldLog(n)) {                                                                       \
      double rd = ((FnD)gOrig_##NAME)(PASS);                                                  \
      int ri = ((FnI)gOrig_##NAME)(PASS);                                                     \
      uint64_t o8 = *(uint64_t*)((uintptr_t)self + 8);                                        \
      uint64_t o16 = *(uint64_t*)((uintptr_t)self + 16);                                      \
      Log(#NAME " #%d self+8=0x%llx self+16=0x%llx a=%ld b=0x%lx c=0x%lx d=0x%lx e=0x%lx | "   \
          "f0=%g(f:%g) f1=%g(f:%g) f2=%g(f:%g) | ret asDouble=%g asFloat=%g asInt=%d",         \
          n, (unsigned long long)o8, (unsigned long long)o16, a, (unsigned long)b,            \
          (unsigned long)c, (unsigned long)d, (unsigned long)e, f0, (double)LowFloat(f0), f1, \
          (double)LowFloat(f1), f2, (double)LowFloat(f2), rd, (double)LowFloat(rd), ri);      \
    }                                                                                         \
    TAILCALL return ((FnD)gOrig_##NAME)(PASS);                                                \
  }

// 体力・満腹度の処理: 引数のみ記録（追加呼び出しなし）
#define DEFINE_ARGS_HOOK(NAME)                                                                \
  static void* gOrig_##NAME = nullptr;                                                        \
  static std::atomic<int> gCalls_##NAME{0};                                                   \
  static double Hook_##NAME(ARGS) {                                                           \
    int n = ++gCalls_##NAME;                                                                  \
    if (ShouldLog(n)) {                                                                       \
      Log(#NAME " #%d a=0x%lx b=0x%lx c=0x%lx d=0x%lx e=0x%lx | "                             \
          "f0=%g(f:%g) f1=%g(f:%g) f2=%g(f:%g)",                                              \
          n, (unsigned long)a, (unsigned long)b, (unsigned long)c, (unsigned long)d,          \
          (unsigned long)e, f0, (double)LowFloat(f0), f1, (double)LowFloat(f1), f2,           \
          (double)LowFloat(f2));                                                              \
    }                                                                                         \
    TAILCALL return ((FnD)gOrig_##NAME)(PASS);                                                \
  }

DEFINE_EFFECT_HOOK(MobEffect_s9)
DEFINE_EFFECT_HOOK(AttackDamage_s9)
DEFINE_ARGS_HOOK(HealthDelegate_s4)
DEFINE_ARGS_HOOK(HealthDelegate_s5)
DEFINE_ARGS_HOOK(HealthDelegate_s6)
DEFINE_ARGS_HOOK(HungerDelegate_s3)

static bool LoadSections(Section& rodata, Section& drr, uintptr_t& base) {
  const char* libname = "libminecraftpe.so";
  char libPath[512] = {0};
  base = 0;
  FILE* maps = fopen("/proc/self/maps", "r");
  if (!maps) return false;
  char line[1024];
  while (fgets(line, sizeof(line), maps)) {
    if (!strstr(line, libname)) continue;
    unsigned long long start = 0;
    char path[512] = {0};
    if (sscanf(line, "%llx-%*x %*s %*x %*s %*d %511s", &start, path) >= 1 && path[0] == '/') {
      base = (uintptr_t)start;
      strncpy(libPath, path, sizeof(libPath) - 1);
      break;
    }
  }
  fclose(maps);
  if (!base || !libPath[0]) return false;
  int fd = open(libPath, O_RDONLY);
  if (fd < 0) return false;
  struct stat st;
  if (fstat(fd, &st) < 0) { close(fd); return false; }
  void* map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) return false;
  bool ok = false;
  ElfW(Ehdr)* eh = (ElfW(Ehdr)*)map;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0) {
    ElfW(Shdr)* sh = (ElfW(Shdr)*)((uintptr_t)map + eh->e_shoff);
    const char* names = (const char*)((uintptr_t)map + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++) {
      const char* nm = names + sh[i].sh_name;
      if (!strcasecmp(nm, ".rodata")) { rodata.addr = base + sh[i].sh_addr; rodata.size = sh[i].sh_size; }
      else if (!strcasecmp(nm, ".data.rel.ro")) { drr.addr = base + sh[i].sh_addr; drr.size = sh[i].sh_size; }
    }
    ok = rodata.addr && drr.addr;
  }
  munmap(map, st.st_size);
  return ok;
}

static void** FindVtable(const Section& ro, const Section& drr, const char* typeStr) {
  size_t len = strlen(typeStr);
  char* zts = nullptr;
  size_t off = 0;
  while (off < ro.size) {
    char* m = (char*)memmem((void*)(ro.addr + off), ro.size - off, typeStr, len + 1);
    if (!m) break;
    if ((uintptr_t)m == ro.addr || *(m - 1) == '\0') { zts = m; break; }
    off = (uintptr_t)m - ro.addr + 1;
  }
  if (!zts) return nullptr;
  uintptr_t zti = 0;
  for (size_t i = 0; i + sizeof(uintptr_t) <= drr.size; i += sizeof(uintptr_t)) {
    if (*(uintptr_t*)(drr.addr + i) == (uintptr_t)zts) { zti = drr.addr + i - sizeof(uintptr_t); break; }
  }
  if (!zti) return nullptr;
  uintptr_t vtable = 0;
  for (size_t i = 0; i + sizeof(uintptr_t) <= drr.size; i += sizeof(uintptr_t)) {
    if (*(uintptr_t*)(drr.addr + i) == zti) {
      uintptr_t cand = drr.addr + i + sizeof(uintptr_t);
      if (i >= sizeof(uintptr_t) && *(uintptr_t*)(drr.addr + i - sizeof(uintptr_t)) == 0) { vtable = cand; break; }
      if (!vtable) vtable = cand;
    }
  }
  return (void**)vtable;
}

static bool PatchSlot(void** vt, int slot, void* fn) {
  uintptr_t addr = (uintptr_t)&vt[slot];
  size_t ps = (size_t)sysconf(_SC_PAGESIZE);
  uintptr_t page = addr & ~((uintptr_t)ps - 1);
  if (mprotect((void*)page, ps, PROT_READ | PROT_WRITE) != 0) return false;
  vt[slot] = fn;
  mprotect((void*)page, ps, PROT_READ);
  return true;
}

static bool InLib(void* p, uintptr_t base) {
  uintptr_t v = (uintptr_t)p;
  return v >= base && v < base + kLibSpan;
}

static void Install(const Section& ro, const Section& drr, uintptr_t base, const char* typeName,
                    int slot, void** origOut, void* hook) {
  void** vt = FindVtable(ro, drr, typeName);
  if (!vt) { Log("%s slot %d: vtable not found", typeName, slot); return; }
  void* cur = vt[slot];
  if (!InLib(cur, base)) { Log("%s slot %d: not in lib (raw=%p). skipped.", typeName, slot, cur); return; }
  *origOut = cur;
  bool ok = PatchSlot(vt, slot, hook);
  Log("%s slot %d: patched=%d (orig +0x%llx)", typeName, slot, ok ? 1 : 0,
      (unsigned long long)((uintptr_t)cur - base));
}

__attribute__((constructor)) static void Init() {
  Section ro{}, drr{};
  uintptr_t base = 0;
  if (!LoadSections(ro, drr, base)) { LOG("sections not found"); return; }

  char pkg[256] = {0};
  FILE* cmd = fopen("/proc/self/cmdline", "rb");
  if (cmd) { fread(pkg, 1, sizeof(pkg) - 1, cmd); fclose(cmd); }
  if (!pkg[0]) strncpy(pkg, "org.levimc.launcher", sizeof(pkg) - 1);

  char dir[600];
  snprintf(dir, sizeof(dir), "/storage/emulated/0/Android/media/%s/EnchantEffectProbe", pkg);
  mkdir(dir, 0777);
  snprintf(gLogPath, sizeof(gLogPath), "%s/log.txt", dir);
  FILE* lf = fopen(gLogPath, "w");
  if (lf) fclose(lf);
  Log("EnchantEffectProbe start (observe only).");

  Install(ro, drr, base, "9MobEffect", 9, &gOrig_MobEffect_s9, (void*)&Hook_MobEffect_s9);
  Install(ro, drr, base, "21AttackDamageMobEffect", 9, &gOrig_AttackDamage_s9, (void*)&Hook_AttackDamage_s9);
  Install(ro, drr, base, "23HealthAttributeDelegate", 4, &gOrig_HealthDelegate_s4, (void*)&Hook_HealthDelegate_s4);
  Install(ro, drr, base, "23HealthAttributeDelegate", 5, &gOrig_HealthDelegate_s5, (void*)&Hook_HealthDelegate_s5);
  Install(ro, drr, base, "23HealthAttributeDelegate", 6, &gOrig_HealthDelegate_s6, (void*)&Hook_HealthDelegate_s6);
  Install(ro, drr, base, "23HungerAttributeDelegate", 3, &gOrig_HungerDelegate_s3, (void*)&Hook_HungerDelegate_s3);
}
