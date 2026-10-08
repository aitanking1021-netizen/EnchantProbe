// EnchantHookProbe v2（観察専用・SDK版）
// JSON の「minecraft:keep_on_death / minecraft:item_lock」の文字列を使っている関数の先頭候補13か所に、
// 観察用フックを入れ、呼ばれたときの引数と時刻をログに書くだけのMODです。
// 戻り値は一切書き換えません（引数をそのまま元の関数へ渡す末尾呼び出し）。
// 引数の指す先は読みません（クラッシュを避けるため、レジスタの値だけ記録）。
//
// 先頭の命令が「関数の入口らしい形」か確認し、違えばそのフックは入れません。
// 各行の先頭の [秒] は、このMODが起動してからの経過時間です。
//
// ログ: /storage/emulated/0/Android/media/<ランチャー>/EnchantHookProbe/log.txt

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <sys/stat.h>
#include <vector>

#include <pl/Mod.hpp>
#include <pl/memory/Hook.hpp>
#include <pl/memory/Patch.hpp>

#if defined(__clang__)
#define TAILCALL [[clang::musttail]]
#else
#define TAILCALL
#endif

namespace {

constexpr int kLogFirst = 30;    // 最初のN回は全部記録
constexpr int kLogEvery = 500;   // 以降はN回に1回
char gLogPath[700] = {0};
double gStart = 0.0;

double NowSec() {
  timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec / 1e9;
}

void Log(const char *fmt, ...) {
  if (!gLogPath[0]) return;
  FILE *f = fopen(gLogPath, "a");
  if (!f) return;
  fprintf(f, "[%.2f] ", NowSec() - gStart);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fputc('\n', f);
  fclose(f);
}

bool ShouldLog(int n) { return n <= kLogFirst || n % kLogEvery == 0; }

uintptr_t FindBase() {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) return 0;
  char line[1024];
  uintptr_t base = 0;
  while (fgets(line, sizeof(line), maps)) {
    if (!strstr(line, "libminecraftpe.so")) continue;
    unsigned long long start = 0;
    if (sscanf(line, "%llx-", &start) == 1) {
      base = static_cast<uintptr_t>(start);
      break;
    }
  }
  fclose(maps);
  return base;
}

// 関数の入口らしい命令か: stp x29,x30,[sp,#imm]! か sub sp,sp,#imm
bool LooksLikePrologue(uint32_t w) {
  return (w & 0xFFC07FFF) == 0xA9807BFD || (w & 0xFF0003FF) == 0xD10003FF;
}

using GenericFn = uint64_t (*)(void *, void *, void *, void *);

#define DEFINE_HOOK(NAME)                                                                  \
  GenericFn gOrig_##NAME = nullptr;                                                        \
  std::atomic<int> gCalls_##NAME{0};                                                       \
  uint64_t Hook_##NAME(void *a, void *b, void *c, void *d) {                               \
    int n = ++gCalls_##NAME;                                                               \
    if (ShouldLog(n)) { Log(#NAME " #%d a=%p b=%p c=%p d=%p", n, a, b, c, d); }            \
    TAILCALL return gOrig_##NAME(a, b, c, d);                                              \
  }

DEFINE_HOOK(KOD_912cc)
DEFINE_HOOK(KOD_915ac)
DEFINE_HOOK(KOD_91670)
DEFINE_HOOK(KOD_917dc)
DEFINE_HOOK(KOD_9c7ac)
DEFINE_HOOK(KOD_9ca78)
DEFINE_HOOK(KOD_a3110)
DEFINE_HOOK(BOTH_9cae8)
DEFINE_HOOK(LOCK_810b8)
DEFINE_HOOK(LOCK_81428)
DEFINE_HOOK(LOCK_91af4)
DEFINE_HOOK(LOCK_91c44)
DEFINE_HOOK(LOCK_9c8d8)

struct Target {
  const char *name;
  uintptr_t offset;
  GenericFn *orig;
  GenericFn detour;
};

Target kTargets[] = {
    {"KOD_912cc", 0xff912cc, &gOrig_KOD_912cc, &Hook_KOD_912cc},
    {"KOD_915ac", 0xff915ac, &gOrig_KOD_915ac, &Hook_KOD_915ac},
    {"KOD_91670", 0xff91670, &gOrig_KOD_91670, &Hook_KOD_91670},
    {"KOD_917dc", 0xff917dc, &gOrig_KOD_917dc, &Hook_KOD_917dc},
    {"KOD_9c7ac", 0xff9c7ac, &gOrig_KOD_9c7ac, &Hook_KOD_9c7ac},
    {"KOD_9ca78", 0xff9ca78, &gOrig_KOD_9ca78, &Hook_KOD_9ca78},
    {"KOD_a3110", 0xffa3110, &gOrig_KOD_a3110, &Hook_KOD_a3110},
    {"BOTH_9cae8", 0xff9cae8, &gOrig_BOTH_9cae8, &Hook_BOTH_9cae8},
    {"LOCK_810b8", 0xff810b8, &gOrig_LOCK_810b8, &Hook_LOCK_810b8},
    {"LOCK_81428", 0xff81428, &gOrig_LOCK_81428, &Hook_LOCK_81428},
    {"LOCK_91af4", 0xff91af4, &gOrig_LOCK_91af4, &Hook_LOCK_91af4},
    {"LOCK_91c44", 0xff91c44, &gOrig_LOCK_91c44, &Hook_LOCK_91c44},
    {"LOCK_9c8d8", 0xff9c8d8, &gOrig_LOCK_9c8d8, &Hook_LOCK_9c8d8},
};

} // namespace

class HookProbeMod {
public:
  static HookProbeMod &instance() {
    static HookProbeMod inst;
    return inst;
  }

  HookProbeMod() : mSelf(*ll::mod::NativeMod::current()) {}

  bool load() { return true; }

  bool enable() {
    gStart = NowSec();
    char pkg[256] = {0};
    if (FILE *cmd = fopen("/proc/self/cmdline", "rb")) {
      fread(pkg, 1, sizeof(pkg) - 1, cmd);
      fclose(cmd);
    }
    if (!pkg[0]) strncpy(pkg, "org.levimc.launcher", sizeof(pkg) - 1);
    char dir[600];
    snprintf(dir, sizeof(dir), "/storage/emulated/0/Android/media/%s/EnchantHookProbe", pkg);
    mkdir(dir, 0777);
    snprintf(gLogPath, sizeof(gLogPath), "%s/log.txt", dir);
    if (FILE *lf = fopen(gLogPath, "w")) fclose(lf);
    Log("EnchantHookProbe v2 start (observe only).");

    const uintptr_t base = FindBase();
    if (!base) {
      Log("libminecraftpe.so base not found.");
      return true;
    }
    Log("base=0x%llx", (unsigned long long)base);

    mHooks.resize(sizeof(kTargets) / sizeof(kTargets[0]));
    for (size_t i = 0; i < mHooks.size(); i++) {
      Target &t = kTargets[i];
      const uintptr_t addr = base + t.offset;
      auto bytes = pl::memory::readBytes(addr, 4);
      uint32_t word = 0;
      if (bytes.size() == 4) memcpy(&word, bytes.data(), 4);
      if (!LooksLikePrologue(word)) {
        Log("%s: first word 0x%08x is not a function prologue. skipped.", t.name, word);
        continue;
      }
      mHooks[i] = pl::memory::HookHandle(reinterpret_cast<void *>(addr),
                                         reinterpret_cast<void *>(t.detour),
                                         reinterpret_cast<void **>(t.orig),
                                         pl::memory::HookPriority::Normal);
      Log("%s: hook installed=%d (+0x%llx)", t.name, mHooks[i].installed() ? 1 : 0,
          (unsigned long long)t.offset);
    }
    return true;
  }

  bool disable() {
    for (auto &h : mHooks) h.reset();
    return true;
  }

  bool unload() { return true; }

  [[nodiscard]] ll::mod::NativeMod &getSelf() const { return mSelf; }

private:
  ll::mod::NativeMod &mSelf;
  std::vector<pl::memory::HookHandle> mHooks;
};

PL_REGISTER_MOD(HookProbeMod, HookProbeMod::instance())
