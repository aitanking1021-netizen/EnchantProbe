// EnchantHookProbe v3.3（観察専用・SDK版）: アイテムの追加データ(タグ)の読み取りテスト
// ・v3.3: ホバー時に、タグの中にあるキー名を全部ログへ書き出す（動的プロパティの保存先を探すため）。
//   メモリは write() 経由の安全な読み取りだけで調べる（無効なアドレスでも落ちずに失敗として返る）。
// ・ホバーテキスト(+0xff9cae8)だけは、引数のアイテム(ItemStack)の追加データ([ItemStack+0x10])を、
//   ゲーム自身の読み取り関数(+0x11203310 = 名前があるか / +0x112036a4 = 名前の値(1バイト))で調べる。
// ・死亡時の2関数(+0xff9ca78, +0xff917dc)は、引数の指す先を読まず、値だけをログに書く。
//   （v3 では死亡時の関数の引数をアイテムと決めつけて読み、/kill でクラッシュした。その修正版）
// ゲームのデータは一切書き換えません。元の関数へは引数をそのまま渡します（末尾呼び出し）。
//
// ログ: /storage/emulated/0/Android/media/<ランチャー>/EnchantHookProbe/log.txt

#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <mutex>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
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


// ---- 安全なメモリ読み取り ----
// パイプへの write() は、無効なアドレスだと落ちずに EFAULT で失敗する。これを使って、読んでよいか確かめながら読む
int gPipe[2] = {-1, -1};
std::mutex gPipeMutex;

bool InitSafeRead() {
  return pipe2(gPipe, O_NONBLOCK | O_CLOEXEC) == 0;
}

bool SafeRead(uint64_t addr, void *out, size_t n) {
  if (gPipe[0] < 0 || n == 0 || n > 4096) return false;
  addr &= 0x00FFFFFFFFFFFFFFULL; // 最上位バイトのタグは外す
  if (addr < 0x10000 || addr >= 0x0000800000000000ULL) return false;
  std::lock_guard<std::mutex> lock(gPipeMutex);
  ssize_t w = write(gPipe[1], reinterpret_cast<const void *>(static_cast<uintptr_t>(addr)), n);
  if (w != static_cast<ssize_t>(n)) {
    if (w > 0) { char tmp[4096]; ssize_t r = read(gPipe[0], tmp, static_cast<size_t>(w)); (void)r; }
    return false;
  }
  return read(gPipe[0], out, n) == static_cast<ssize_t>(n);
}

uint64_t Mask(uint64_t v) { return v & 0x00FFFFFFFFFFFFFFULL; }

std::string Hex(const unsigned char *p, size_t n) {
  std::string s;
  char t[4];
  for (size_t i = 0; i < n; i++) {
    snprintf(t, sizeof(t), "%02x", p[i]);
    s += t;
    if (i % 8 == 7 && i + 1 < n) s += ' ';
  }
  return s;
}

// libc++ の std::string(24バイト)を読む。短い文字列は先頭バイトの最下位ビットが0、長い文字列は1
std::string ReadStdString(uint64_t addr) {
  unsigned char raw[24];
  if (!SafeRead(addr, raw, sizeof(raw))) return "<unreadable>";
  std::string s;
  if ((raw[0] & 1) == 0) {
    size_t len = raw[0] >> 1;
    if (len > 22) return "<bad short len>";
    s.assign(reinterpret_cast<char *>(raw + 1), len);
  } else {
    uint64_t len = 0, ptr = 0;
    memcpy(&len, raw + 8, 8);
    memcpy(&ptr, raw + 16, 8);
    if (len == 0 || len > 80) return "<bad long len>";
    char tmp[96];
    if (!SafeRead(ptr, tmp, static_cast<size_t>(len))) return "<unreadable data>";
    s.assign(tmp, static_cast<size_t>(len));
  }
  for (char &c : s) if (c < 0x20 || c > 0x7e) c = '?';
  return s;
}

// CompoundTag の中のキー名を全部書き出す。
// 仮定（libc++ の std::map）: [tag+0x08]=先頭ノード, [tag+0x10]=根, [tag+0x18]=要素数。
//   ノード: +0=左, +8=右, +0x10=親, +0x20=キー(std::string 24バイト), +0x38〜=値
// 仮定が外れていても、先頭の生バイト(TAGHEAD)と各ノードの生バイトが残るので、次の調査に使える
void DumpTagKeys(const char *who, int n, void *tagp) {
  const uint64_t t = Mask(reinterpret_cast<uint64_t>(tagp));
  unsigned char head[0x30];
  if (!SafeRead(t, head, sizeof(head))) { Log("%s #%d TAGHEAD unreadable", who, n); return; }
  Log("%s #%d TAGHEAD %s", who, n, Hex(head, sizeof(head)).c_str());
  uint64_t begin = 0, root = 0, size = 0;
  memcpy(&begin, head + 0x08, 8);
  memcpy(&root, head + 0x10, 8);
  memcpy(&size, head + 0x18, 8);
  const uint64_t endNode = t + 0x10;
  if (size == 0 || size > 64) {
    Log("%s #%d TAGKEYS size=%llu (the layout guess may be wrong)", who, n, (unsigned long long)size);
    return;
  }
  uint64_t node = Mask(begin);
  int count = 0;
  for (; count < 64 && node != endNode; count++) {
    unsigned char nd[0x50];
    if (!SafeRead(node, nd, sizeof(nd))) { Log("%s #%d TAGKEYS node %d unreadable", who, n, count); return; }
    uint64_t left = 0, right = 0, parent = 0;
    memcpy(&left, nd, 8);
    memcpy(&right, nd + 8, 8);
    memcpy(&parent, nd + 0x10, 8);
    std::string key = ReadStdString(node + 0x20);
    Log("%s #%d KEY[%d] \"%s\" value+0x38: %s", who, n, count, key.c_str(), Hex(nd + 0x38, 0x18).c_str());

    uint64_t next = 0;
    if (Mask(right) != 0) {
      next = Mask(right);
      for (int j = 0; j < 64; j++) {
        uint64_t l = 0;
        if (!SafeRead(next, &l, 8)) { Log("%s #%d TAGKEYS walk failed", who, n); return; }
        if (Mask(l) == 0) break;
        next = Mask(l);
      }
    } else {
      uint64_t x = node;
      for (int j = 0; j < 64; j++) {
        uint64_t p = 0, pl = 0;
        if (!SafeRead(x + 0x10, &p, 8)) { Log("%s #%d TAGKEYS walk failed", who, n); return; }
        p = Mask(p);
        if (!SafeRead(p, &pl, 8)) { Log("%s #%d TAGKEYS walk failed", who, n); return; }
        if (Mask(pl) == x) { next = p; break; }
        x = p;
      }
    }
    if (next == 0) { Log("%s #%d TAGKEYS no successor", who, n); return; }
    node = next;
  }
  Log("%s #%d TAGKEYS done: walked=%d size=%llu", who, n, count, (unsigned long long)size);
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
  DumpTagKeys(who, n, tag);
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
    Log("EnchantHookProbe v3.3 start (observe only).");

    Log("safe read %s", InitSafeRead() ? "ready" : "NOT ready");

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
