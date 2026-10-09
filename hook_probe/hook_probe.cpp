// EnchantHookProbe v3.2（観察専用・SDK版）: アイテムの追加データ(タグ)の読み取りテスト
// ・ホバーテキスト(+0xff9cae8)だけは、引数のアイテム(ItemStack)の追加データ([ItemStack+0x10])を、
//   ゲーム自身の読み取り関数(+0x11203310 = 名前があるか / +0x112036a4 = 名前の値(1バイト))で調べる。
// ・死亡時の2関数(+0xff9ca78, +0xff917dc)は、引数の指す先を読まず、値だけをログに書く。
//   （v3 では死亡時の関数の引数をアイテムと決めつけて読み、/kill でクラッシュした。その修正版）
// ゲームのデータは一切書き換えません。元の関数へは引数をそのまま渡します（末尾呼び出し）。
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

constexpr int kLogFirst = 60;
constexpr int kLogEvery = 200;
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

uint32_t ReadWord(uintptr_t addr) {
  auto bytes = pl::memory::readBytes(addr, 4);
  uint32_t w = 0;
  if (bytes.size() == 4) memcpy(&w, bytes.data(), 4);
  return w;
}

// ゲーム自身のタグ読み取り関数（アドレスは起動時に base + オフセット で決める）
using ContainsFn = bool (*)(void *tag, const char *key, size_t len);
using GetByteFn = uint8_t (*)(void *tag, const char *key, size_t len);
ContainsFn gContains = nullptr;
GetByteFn gGetByte = nullptr;

// Android のヒープのポインタは、最上位バイトにタグ(例: 0xb4)が付く。CPU は参照時に最上位バイトを無視するので
// そのまま読めるが、範囲の確認では最上位バイトを除いて調べる
bool PlausiblePtr(void *p) {
  uintptr_t v = reinterpret_cast<uintptr_t>(p) & 0x00FFFFFFFFFFFFFFULL;
  return v > 0x10000 && v < 0x0000800000000000ULL && (v & 0x7) == 0;
}

struct KeyDef { const char *name; size_t len; };
constexpr KeyDef kKeys[] = {
    {"minecraft:keep_on_death", 23}, {"minecraft:item_lock", 19},
    {"minecraft:dynamic_properties", 28}, {"dynamic_properties", 18},
    {"display", 7}, {"ench", 4}, {"Damage", 6},
};

// ItemStack の追加データ([ItemStack+0x10])を調べてログに書く（ホバー専用。検証済みの呼び出しだけに使う）
void ProbeStack(const char *who, int n, void *stack) {
  if (!gContains || !gGetByte) return;
  if (!PlausiblePtr(stack)) { Log("%s #%d stack=%p (not a plausible pointer)", who, n, stack); return; }
  void *tag = *reinterpret_cast<void **>(reinterpret_cast<uintptr_t>(stack) + 0x10);
  if (!PlausiblePtr(tag)) { Log("%s #%d stack=%p tag=%p (no user data)", who, n, stack, tag); return; }
  char buf[384];
  int off = snprintf(buf, sizeof(buf), "%s #%d stack=%p tag=%p |", who, n, stack, tag);
  for (const KeyDef &k : kKeys) {
    bool has = gContains(tag, k.name, k.len);
    off += snprintf(buf + off, sizeof(buf) - off, " %s=%d", k.name, has ? 1 : 0);
  }
  int kod = gGetByte(tag, "minecraft:keep_on_death", 23);
  int lock = gGetByte(tag, "minecraft:item_lock", 19);
  snprintf(buf + off, sizeof(buf) - off, " | byte(kod)=%d byte(lock)=%d", kod, lock);
  Log("%s", buf);
}

using GenericFn = uint64_t (*)(void *, void *, void *, void *);

// ホバーテキスト(+0xff9cae8): 第2引数が ItemStack（v3 の実機ログで確認済み）
GenericFn gOrig_Hover = nullptr;
std::atomic<int> gCalls_Hover{0};
uint64_t Hook_Hover(void *a, void *b, void *c, void *d) {
  int n = ++gCalls_Hover;
  if (ShouldLog(n)) ProbeStack("HOVER", n, b);
  TAILCALL return gOrig_Hover(a, b, c, d);
}

// 死亡時の判定(+0xff9ca78): 引数の指す先は読まず、値だけ記録する
GenericFn gOrig_Death = nullptr;
std::atomic<int> gCalls_Death{0};
uint64_t Hook_Death(void *a, void *b, void *c, void *d) {
  int n = ++gCalls_Death;
  if (ShouldLog(n)) Log("DEATH #%d a=%p b=%p c=%p d=%p", n, a, b, c, d);
  TAILCALL return gOrig_Death(a, b, c, d);
}

// 「keep_on_death を持つか」を調べている関数(+0xff917dc): こちらも値だけ記録する
GenericFn gOrig_KodCheck = nullptr;
std::atomic<int> gCalls_KodCheck{0};
uint64_t Hook_KodCheck(void *a, void *b, void *c, void *d) {
  int n = ++gCalls_KodCheck;
  if (ShouldLog(n)) Log("KODCHECK #%d a=%p b=%p c=%p d=%p", n, a, b, c, d);
  TAILCALL return gOrig_KodCheck(a, b, c, d);
}

struct Target {
  const char *name;
  uintptr_t offset;
  GenericFn *orig;
  GenericFn detour;
};

Target kTargets[] = {
    {"HOVER_9cae8", 0xff9cae8, &gOrig_Hover, &Hook_Hover},
    {"DEATH_9ca78", 0xff9ca78, &gOrig_Death, &Hook_Death},
    {"KODCHECK_917dc", 0xff917dc, &gOrig_KodCheck, &Hook_KodCheck},
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
    Log("EnchantHookProbe v3.2 start (observe only).");

    const uintptr_t base = FindBase();
    if (!base) { Log("libminecraftpe.so base not found."); return true; }
    Log("base=0x%llx", (unsigned long long)base);

    // タグ読み取り関数の先頭命令を確認してから使う（版が違えば使わない）
    const uint32_t wContains = ReadWord(base + 0x11203310);
    const uint32_t wGetByte = ReadWord(base + 0x112036a4);
    if (wContains == 0xd10143ff && wGetByte == 0xd10103ff) {
      gContains = reinterpret_cast<ContainsFn>(base + 0x11203310);
      gGetByte = reinterpret_cast<GetByteFn>(base + 0x112036a4);
      Log("tag readers ready (contains/getByte)");
    } else {
      Log("tag readers NOT ready: words 0x%08x 0x%08x (版が違う可能性)", wContains, wGetByte);
    }

    mHooks.resize(sizeof(kTargets) / sizeof(kTargets[0]));
    for (size_t i = 0; i < mHooks.size(); i++) {
      Target &t = kTargets[i];
      const uintptr_t addr = base + t.offset;
      const uint32_t w = ReadWord(addr);
      const bool ok = (w & 0xFFC07FFF) == 0xA9807BFD || (w & 0xFF0003FF) == 0xD10003FF;
      if (!ok) { Log("%s: first word 0x%08x not a prologue. skipped.", t.name, w); continue; }
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
