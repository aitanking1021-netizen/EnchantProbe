// EnchantHookProbe（観察専用・SDK版）
// LeviLauncher の Hook API を使って、JSON の「minecraft:keep_on_death / minecraft:item_lock」を
// 扱っていると見られる関数4つに観察用フックを入れ、呼ばれたときの引数をログに書くだけのMODです。
// 戻り値は一切書き換えません（引数をそのまま元の関数へ渡す末尾呼び出し）。
//
// 対象は libminecraftpe.so の「アドレス = 本体の先頭 + オフセット」で指定します。
// ゲームの版が違うとオフセットがずれるので、先頭の命令が想定どおりかを確認し、違えばフックしません。
//
// ログ: /storage/emulated/0/Android/media/<ランチャー>/EnchantHookProbe/log.txt

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

constexpr int kLogFirst = 60;    // 最初のN回は全部記録
constexpr int kLogEvery = 200;   // 以降はN回に1回
char gLogPath[700] = {0};

void Log(const char *fmt, ...) {
  if (!gLogPath[0]) return;
  FILE *f = fopen(gLogPath, "a");
  if (!f) return;
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

// 引数をそのまま元の関数へ渡す、汎用の観察フック。戻り値の型に関係なく素通しになる
using GenericFn = uint64_t (*)(void *, void *, void *, void *);

uint64_t Peek(void *p, size_t off) {
  if (!p) return 0;
  return *reinterpret_cast<uint64_t *>(reinterpret_cast<uintptr_t>(p) + off);
}

#define DEFINE_HOOK(NAME, PEEK_ARG)                                                        \
  GenericFn gOrig_##NAME = nullptr;                                                        \
  std::atomic<int> gCalls_##NAME{0};                                                       \
  uint64_t Hook_##NAME(void *a, void *b, void *c, void *d) {                               \
    int n = ++gCalls_##NAME;                                                               \
    if (ShouldLog(n)) {                                                                    \
      Log(#NAME " #%d a=%p b=%p c=%p d=%p | [" #PEEK_ARG "+0x10]=0x%llx", n, a, b, c, d,   \
          (unsigned long long)Peek(PEEK_ARG, 0x10));                                       \
    }                                                                                      \
    TAILCALL return gOrig_##NAME(a, b, c, d);                                              \
  }

// keep_on_death 関連 (1引数版 / 2引数版), item_lock 関連 (判定 / 解釈)
DEFINE_HOOK(KeepOnDeath_A_0xff917dc, a)
DEFINE_HOOK(KeepOnDeath_B_0xff9ca78, b)
DEFINE_HOOK(ItemLock_A_0xff91dc4, a)
DEFINE_HOOK(ItemLock_B_0xff9cae8, b)

struct Target {
  const char *name;
  uintptr_t offset;      // libminecraftpe.so 先頭からの位置
  uint32_t firstWord;    // 想定する先頭の命令(リトルエンディアンの4バイト)
  GenericFn *orig;
  GenericFn detour;
};

Target kTargets[] = {
    {"KeepOnDeath_A", 0xff917dc, 0xa9be7bfd, &gOrig_KeepOnDeath_A_0xff917dc, &Hook_KeepOnDeath_A_0xff917dc},
    {"KeepOnDeath_B", 0xff9ca78, 0xa9be7bfd, &gOrig_KeepOnDeath_B_0xff9ca78, &Hook_KeepOnDeath_B_0xff9ca78},
    {"ItemLock_A", 0xff91dc4, 0xa9be7bfd, &gOrig_ItemLock_A_0xff91dc4, &Hook_ItemLock_A_0xff91dc4},
    {"ItemLock_B", 0xff9cae8, 0xd10343ff, &gOrig_ItemLock_B_0xff9cae8, &Hook_ItemLock_B_0xff9cae8},
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
    Log("EnchantHookProbe start (observe only).");

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
      if (word != t.firstWord) {
        Log("%s: first word 0x%08x != expected 0x%08x (版が違う可能性). skipped.", t.name, word,
            t.firstWord);
        continue;
      }
      mHooks[i] = pl::memory::HookHandle(reinterpret_cast<void *>(addr),
                                         reinterpret_cast<void *>(t.detour),
                                         reinterpret_cast<void **>(t.orig),
                                         pl::memory::HookPriority::Normal);
      Log("%s: hook installed=%d (addr=0x%llx)", t.name, mHooks[i].installed() ? 1 : 0,
          (unsigned long long)addr);
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
