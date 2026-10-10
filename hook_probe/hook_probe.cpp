// EnchantHookProbe v5.0（SDK版）: アイテムの追加データ(タグ)の読み取りテスト + 採掘速度・攻撃力・防御力・防具強度の個体別変更
// ・v5.0: 攻撃力（関数表38番）・防御力（59番）・防具強度（60番）を返す関数の項目を差し替え、手に持った/着た個体の
//   動的プロパティで戻り値を変える。変更後の値 = (元の値 + 〜Add) × 〜Mul。
//   攻撃力: attackAdd/attackMul  防御力: defenseAdd/defenseMul  防具強度: toughnessAdd/toughnessMul
//   これらの関数は ItemStack を受け取らないので、呼び出し元のレジスタ(x19〜x22)から持ち主の ItemStack を探し、確かめられたときだけ変える。
//   kEnableStatEdit を false にすると、差し替えは行わない（元に戻る）。
// ・v4.0: 採掘速度を返す関数（関数表の89番。DiggerItem 系 +0xffe71f0 / WeaponItem +0xfd67148）にフックを入れ、
//   手に持った道具の動的プロパティ miningSpeedAdd（加算）/ miningSpeedMul（倍率）で戻り値を変える。
//   変更後の値 = (元の値 + miningSpeedAdd) × miningSpeedMul。どちらも未設定なら元の値のまま。
//   ※ここだけは観察専用ではなく、ゲームの動作を変える。kEnableMiningEdit を false にすると完全に止まる。
// ・v3.3: ホバー時に、タグの中にあるキー名を全部ログへ書き出す（動的プロパティの保存先を探すため）。
// ・v3.5: 起動時に別スレッドで、アイテム性能に関わるクラス（DiggerItemComponent など）の vtable を探し、
//   各関数のアドレス(base からのオフセット)をログに書く。どの関数が採掘速度・耐久などを返すかを絞り込むための調査用。
// ・v3.4: v3.3 のログで保存先は "DynamicProperties"（大文字小文字あり）と分かったので、入れ子の中身も深さ3までたどる。
//   メモリは write() 経由の安全な読み取りだけで調べる（無効なアドレスでも落ちずに失敗として返る）。
// ・ホバーテキスト(+0xff9cae8)だけは、引数のアイテム(ItemStack)の追加データ([ItemStack+0x10])を、
//   ゲーム自身の読み取り関数(+0x11203310 = 名前があるか / +0x112036a4 = 名前の値(1バイト))で調べる。
// ・死亡時の2関数(+0xff9ca78, +0xff917dc)は、引数の指す先を読まず、値だけをログに書く。
//   （v3 では死亡時の関数の引数をアイテムと決めつけて読み、/kill でクラッシュした。その修正版）
// ゲームのデータは一切書き換えません。元の関数へは引数をそのまま渡します（末尾呼び出し）。
//
// ログ: /storage/emulated/0/Android/media/<ランチャー>/EnchantHookProbe/log.txt

#include <algorithm>
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
#include <thread>
#include <unordered_map>
#include <sys/mman.h>
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

std::mutex gLogMutex;

void Log(const char *fmt, ...) {
  if (!gLogPath[0]) return;
  std::lock_guard<std::mutex> lock(gLogMutex);
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
  if (gPipe[0] < 0 || n == 0 || n > 16384) return false;
  addr &= 0x00FFFFFFFFFFFFFFULL; // 最上位バイトのタグは外す
  if (addr < 0x10000 || addr >= 0x0000800000000000ULL) return false;
  std::lock_guard<std::mutex> lock(gPipeMutex);
  ssize_t w = write(gPipe[1], reinterpret_cast<const void *>(static_cast<uintptr_t>(addr)), n);
  if (w != static_cast<ssize_t>(n)) {
    if (w > 0) {
      char tmp[4096];
      ssize_t left = w;
      while (left > 0) {
        ssize_t r = read(gPipe[0], tmp, std::min<size_t>(sizeof(tmp), static_cast<size_t>(left)));
        if (r <= 0) break;
        left -= r;
      }
    }
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
// printable に true が入るのは、全部が表示できる文字(0x20〜0x7e)だったとき
std::string ReadStdString(uint64_t addr, bool *printable = nullptr) {
  if (printable) *printable = false;
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
  bool ok = !s.empty();
  for (char &c : s) {
    if (c < 0x20 || c > 0x7e) { ok = false; c = '?'; }
  }
  if (printable) *printable = ok;
  return s;
}

// CompoundTag の中のキー名を書き出す。値が CompoundTag なら、その中も同じ方法でたどる（深さ3まで）
// 仮定（libc++ の std::map）: [tag+0x08]=先頭ノード, [tag+0x10]=根, [tag+0x18]=要素数。
//   ノード: +0=左, +8=右, +0x10=親, +0x20=キー(std::string 24バイト), +0x38〜=値（CompoundTag はここに直接入る）
// 値の先頭の8バイトは型ごとの vtable。トップのタグ(CompoundTag)の vtable と同じなら入れ子の CompoundTag とみなす
// 仮定が外れていても、各ノードの生バイトがログに残るので、次の調査に使える
void DumpCompound(const char *who, int n, uint64_t compound, uint64_t compoundVt, int depth,
                  const std::string &path, int &budget) {
  unsigned char head[0x20];
  if (!SafeRead(compound, head, sizeof(head))) { Log("%s #%d %s unreadable", who, n, path.c_str()); return; }
  uint64_t begin = 0, size = 0;
  memcpy(&begin, head + 0x08, 8);
  memcpy(&size, head + 0x18, 8);
  const uint64_t endNode = compound + 0x10;
  if (size == 0 || size > 64) {
    Log("%s #%d %s size=%llu (the layout guess may be wrong)", who, n, path.c_str(), (unsigned long long)size);
    return;
  }
  uint64_t node = Mask(begin);
  int count = 0;
  for (; count < 64 && node != endNode; count++) {
    if (budget-- <= 0) { Log("%s #%d %s budget exhausted", who, n, path.c_str()); return; }
    unsigned char nd[0x50];
    if (!SafeRead(node, nd, sizeof(nd))) { Log("%s #%d %s node %d unreadable", who, n, path.c_str(), count); return; }
    uint64_t right = 0, vt = 0;
    memcpy(&right, nd + 8, 8);
    memcpy(&vt, nd + 0x38, 8);
    std::string key = ReadStdString(node + 0x20);
    std::string here = path + "/" + key;
    const bool isCompound = (vt == compoundVt);
    if (isCompound) {
      Log("%s #%d KEY %s (compound)", who, n, here.c_str());
      if (depth < 3) DumpCompound(who, n, node + 0x38, compoundVt, depth + 1, here, budget);
    } else {
      // 値の中身を、いくつかの型だと仮定した読み方で並べる（どれが正しいかはログを見て判断する）
      int32_t i32 = 0; double f64 = 0; float f32 = 0;
      memcpy(&i32, nd + 0x40, 4);
      memcpy(&f64, nd + 0x40, 8);
      memcpy(&f32, nd + 0x40, 4);
      bool printable = false;
      std::string str = ReadStdString(node + 0x40, &printable);
      char extra[200];
      int off = snprintf(extra, sizeof(extra), "i32=%d f32=%g f64=%g", i32, (double)f32, f64);
      if (printable) snprintf(extra + off, sizeof(extra) - off, " str=\"%s\"", str.c_str());
      Log("%s #%d KEY %s raw: %s | %s", who, n, here.c_str(), Hex(nd + 0x38, 0x18).c_str(), extra);
    }

    uint64_t next = 0;
    if (Mask(right) != 0) {
      next = Mask(right);
      for (int j = 0; j < 64; j++) {
        uint64_t l = 0;
        if (!SafeRead(next, &l, 8)) { Log("%s #%d %s walk failed", who, n, path.c_str()); return; }
        if (Mask(l) == 0) break;
        next = Mask(l);
      }
    } else {
      uint64_t x = node;
      for (int j = 0; j < 64; j++) {
        uint64_t p = 0, pl = 0;
        if (!SafeRead(x + 0x10, &p, 8)) { Log("%s #%d %s walk failed", who, n, path.c_str()); return; }
        p = Mask(p);
        if (!SafeRead(p, &pl, 8)) { Log("%s #%d %s walk failed", who, n, path.c_str()); return; }
        if (Mask(pl) == x) { next = p; break; }
        x = p;
      }
    }
    if (next == 0) { Log("%s #%d %s no successor", who, n, path.c_str()); return; }
    node = next;
  }
  Log("%s #%d %s done: walked=%d size=%llu", who, n, path.c_str(), count, (unsigned long long)size);
}

void DumpTagKeys(const char *who, int n, void *tagp) {
  const uint64_t t = Mask(reinterpret_cast<uint64_t>(tagp));
  uint64_t vt = 0;
  if (!SafeRead(t, &vt, 8)) { Log("%s #%d TAGHEAD unreadable", who, n); return; }
  int budget = 48;
  DumpCompound(who, n, t, vt, 0, "", budget);
}

// ---- vtable の探索（調査用）----
// 仕組み: クラス名の文字列(例 "19DiggerItemComponent")を探す → その文字列を指す typeinfo を探す
//   → その typeinfo を指す vtable を探す。vtable は [offset_to_top][typeinfo][関数0][関数1]... の並び。
struct Range { uint64_t start, end; };

bool ReadLibMaps(std::vector<Range> &data, uint64_t &lo, uint64_t &hi) {
  FILE *f = fopen("/proc/self/maps", "r");
  if (!f) return false;
  char line[1024];
  lo = ~0ULL;
  hi = 0;
  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "libminecraftpe.so")) continue;
    unsigned long long s = 0, e = 0;
    char perms[8] = {0};
    if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
    if (s < lo) lo = s;
    if (e > hi) hi = e;
    if (perms[0] == 'r' && perms[2] != 'x') data.push_back({s, e});
  }
  fclose(f);
  return !data.empty();
}

// 8バイト境界の値を全部調べる（値は読めた範囲だけ）
template <class F>
void ForEachSlot(const std::vector<Range> &data, F f) {
  constexpr size_t kChunk = 16384;
  std::vector<unsigned char> buf(kChunk);
  for (const Range &r : data) {
    for (uint64_t pos = r.start & ~7ULL; pos < r.end; pos += kChunk) {
      size_t n = static_cast<size_t>(std::min<uint64_t>(kChunk, r.end - pos));
      n &= ~static_cast<size_t>(7);
      if (n == 0 || !SafeRead(pos, buf.data(), n)) continue;
      for (size_t i = 0; i < n; i += 8) {
        uint64_t v;
        memcpy(&v, buf.data() + i, 8);
        f(pos + i, v);
      }
    }
  }
}

void ScanVtables(const std::vector<Range> &data, uint64_t libLo, uint64_t libHi, uint64_t base,
                 const char *const *classes, int nClasses) {
  constexpr size_t kBuf = 16384, kOverlap = 64, kStep = kBuf - kOverlap;
  std::vector<std::string> pats;
  for (int c = 0; c < nClasses; c++) {
    std::string p(1, '\0');
    p += classes[c];
    p.push_back('\0');
    pats.push_back(p);
  }
  // 1) クラス名の文字列（前後が NUL）の場所
  std::unordered_map<uint64_t, int> nameAddr;
  {
    std::vector<unsigned char> buf(kBuf);
    for (const Range &r : data) {
      for (uint64_t pos = r.start; pos < r.end; pos += kStep) {
        size_t n = static_cast<size_t>(std::min<uint64_t>(kBuf, r.end - pos));
        if (!SafeRead(pos, buf.data(), n)) continue;
        const bool last = (pos + kStep >= r.end);
        for (int c = 0; c < nClasses; c++) {
          auto it = buf.begin();
          while (true) {
            it = std::search(it, buf.begin() + n, pats[c].begin(), pats[c].end());
            if (it == buf.begin() + n) break;
            size_t idx = static_cast<size_t>(it - buf.begin());
            if (idx < kStep || last) nameAddr[pos + idx + 1] = c;
            ++it;
          }
        }
      }
    }
  }
  Log("VTSCAN names found: %zu", nameAddr.size());

  // 2) その文字列を指す typeinfo（[vptr][name]...）
  std::unordered_map<uint64_t, int> typeinfos;
  ForEachSlot(data, [&](uint64_t slot, uint64_t v) {
    auto it = nameAddr.find(v);
    if (it != nameAddr.end()) typeinfos[slot - 8] = it->second;
  });
  {
    // typeinfo の先頭(vptr)がライブラリ内を指していなければ除く
    for (auto it = typeinfos.begin(); it != typeinfos.end();) {
      uint64_t vptr = 0;
      if (!SafeRead(it->first, &vptr, 8) || vptr < libLo || vptr >= libHi) it = typeinfos.erase(it);
      else ++it;
    }
  }
  Log("VTSCAN typeinfos found: %zu", typeinfos.size());

  // 3) その typeinfo を指す vtable（直前が offset_to_top = 小さな整数）
  struct VT { int cls; uint64_t slot; int64_t ott; };
  std::vector<VT> vts;
  ForEachSlot(data, [&](uint64_t slot, uint64_t v) {
    auto it = typeinfos.find(v);
    if (it == typeinfos.end()) return;
    int64_t ott = 0;
    if (!SafeRead(slot - 8, &ott, 8)) return;
    if (ott > 0x100000 || ott < -0x100000) return; // 小さな整数でなければ vtable ではない
    vts.push_back({it->second, slot, ott});
  });
  Log("VTSCAN vtables found: %zu", vts.size());

  for (const VT &v : vts) {
    const uint64_t vtAddr = v.slot + 8; // オブジェクトが持つ vtable ポインタが指す先
    Log("VTABLE %s vt=+0x%llx offset_to_top=%lld", classes[v.cls], (unsigned long long)(vtAddr - base),
        (long long)v.ott);
    uint64_t ent[64];
    if (!SafeRead(vtAddr, ent, sizeof(ent))) { Log("VTABLE %s entries unreadable", classes[v.cls]); continue; }
    for (int row = 0; row < 8; row++) {
      char line[512];
      int off = snprintf(line, sizeof(line), "VTENT %s [%02d]", classes[v.cls], row * 8);
      for (int k = 0; k < 8; k++) {
        const uint64_t e = ent[row * 8 + k];
        if (e >= libLo && e < libHi) off += snprintf(line + off, sizeof(line) - off, " +0x%llx", (unsigned long long)(e - base));
        else off += snprintf(line + off, sizeof(line) - off, " raw:0x%llx", (unsigned long long)e);
      }
      Log("%s", line);
    }
  }
  Log("VTSCAN done");
}

const char *const kVtClasses[] = {
    "23DurabilityItemComponent", "19DiggerItemComponent", "19DamageItemComponent",
    "19WeaponItemComponent", "21WearableItemComponent", "18ArmorItemComponent",
    "13ItemComponent", "10DiggerItem", "10WeaponItem", "4Item",
};


// ---- 採掘速度の個体別変更（v4.0） ----
constexpr bool kEnableMiningEdit = true;        // false にすると、採掘速度のフックは入れない
constexpr bool kOnlyWhenEffective = true;       // true: 元の値が 1.0 より大きいとき（道具が得意なブロック）だけ変える
constexpr uint64_t kDoubleVtOffset = 0x131a2be0; // 数値タグ(DoubleTag)の vtable の位置（base から）。版が変わると要取り直し
uint64_t gDoubleVt = 0;                          // 実行時に base + kDoubleVtOffset を入れる

// CompoundTag の次のノード（in-order 後続）を求める。DumpCompound と同じ仮定（libc++ の std::map）
bool NextNode(uint64_t node, uint64_t &next) {
  uint64_t right = 0;
  if (!SafeRead(node + 8, &right, 8)) return false;
  if (Mask(right) != 0) {
    next = Mask(right);
    for (int j = 0; j < 64; j++) {
      uint64_t l = 0;
      if (!SafeRead(next, &l, 8)) return false;
      if (Mask(l) == 0) return true;
      next = Mask(l);
    }
    return false;
  }
  uint64_t x = node;
  for (int j = 0; j < 64; j++) {
    uint64_t p = 0, pl = 0;
    if (!SafeRead(x + 0x10, &p, 8)) return false;
    p = Mask(p);
    if (!SafeRead(p, &pl, 8)) return false;
    if (Mask(pl) == x) { next = p; return true; }
    x = p;
  }
  return false;
}

// compound の子ノードを順に f(ノードのアドレス, キー名) へ渡す。f が true を返したら止めて true を返す
template <class F>
bool ForEachChild(uint64_t compound, F f) {
  unsigned char head[0x20];
  if (!SafeRead(compound, head, sizeof(head))) return false;
  uint64_t begin = 0, size = 0;
  memcpy(&begin, head + 0x08, 8);
  memcpy(&size, head + 0x18, 8);
  if (size == 0 || size > 64) return false;
  const uint64_t endNode = compound + 0x10;
  uint64_t node = Mask(begin);
  for (int i = 0; i < 64 && node != endNode; i++) {
    std::string key = ReadStdString(node + 0x20);
    if (f(node, key)) return true;
    uint64_t next = 0;
    if (!NextNode(node, next)) return false;
    node = next;
  }
  return false;
}

struct WantedNum {
  const char *name;
  double val;
  bool found;
};

// ItemStack のタグ(tagp)の DynamicProperties → アドオンごとの枠 → 名前 の順にたどり、数値(double)を読む。
// 型の目印(vtable)が DoubleTag と一致するものだけを数値として読む。見つかったものは found=true
void ReadDynamicNumbers(void *tagp, WantedNum *w, int count) {
  const uint64_t t = Mask(reinterpret_cast<uint64_t>(tagp));
  uint64_t compoundVt = 0;
  if (!SafeRead(t, &compoundVt, 8) || gDoubleVt == 0) return;
  ForEachChild(t, [&](uint64_t node, const std::string &key) -> bool {
    if (key != "DynamicProperties") return false;
    uint64_t vt = 0;
    if (!SafeRead(node + 0x38, &vt, 8) || vt != compoundVt) return true;
    ForEachChild(node + 0x38, [&](uint64_t packNode, const std::string &) -> bool {
      uint64_t pvt = 0;
      if (!SafeRead(packNode + 0x38, &pvt, 8) || pvt != compoundVt) return false;
      ForEachChild(packNode + 0x38, [&](uint64_t n2, const std::string &k2) -> bool {
        for (int i = 0; i < count; i++) {
          if (k2 != w[i].name) continue;
          uint64_t vt2 = 0;
          double d = 0;
          if (SafeRead(n2 + 0x38, &vt2, 8) && vt2 == gDoubleVt && SafeRead(n2 + 0x40, &d, 8)) {
            w[i].val = d;
            w[i].found = true;
          }
        }
        return false; // 枠の中は最後まで見る
      });
      return false;   // すべての枠を見る
    });
    return true;      // DynamicProperties は1つだけ
  });
}

double ClampD(double v, double lo, double hi) { return v < lo ? lo : (v > hi ? hi : v); }

struct KeyDef { const char *name; size_t len; };
constexpr KeyDef kKeys[] = {
    {"minecraft:keep_on_death", 23}, {"minecraft:item_lock", 19},
    {"minecraft:dynamic_properties", 28}, {"DynamicProperties", 17},
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


// ---- 採掘速度（関数表の89番）: 引数は (this, ItemStack, Block)、戻り値は float ----
using SpeedFn = float (*)(void *self, void *stack, void *block);
SpeedFn gOrig_SpeedDigger = nullptr;
SpeedFn gOrig_SpeedWeapon = nullptr;
std::atomic<int> gCalls_SpeedDigger{0};
std::atomic<int> gCalls_SpeedWeapon{0};
std::atomic<int> gEdits_Mining{0};

float ApplyMiningEdit(const char *who, float orig, void *stack) {
  if (!(orig == orig)) return orig;                 // NaN はそのまま
  if (kOnlyWhenEffective && orig <= 1.0f) return orig;
  if (!PlausiblePtr(stack)) return orig;
  void *tag = *reinterpret_cast<void **>(reinterpret_cast<uintptr_t>(stack) + 0x10);
  if (!PlausiblePtr(tag)) return orig;
  WantedNum w[2] = {{"miningSpeedAdd", 0.0, false}, {"miningSpeedMul", 1.0, false}};
  ReadDynamicNumbers(tag, w, 2);
  if (!w[0].found && !w[1].found) return orig;
  const double add = w[0].found ? ClampD(w[0].val, -100.0, 1000.0) : 0.0;
  const double mul = w[1].found ? ClampD(w[1].val, 0.0, 100.0) : 1.0;
  const double out = ClampD((static_cast<double>(orig) + add) * mul, 0.0, 10000.0);
  const int n = ++gEdits_Mining;
  if (ShouldLog(n)) Log("%s edit #%d: orig=%g add=%g mul=%g -> %g", who, n, (double)orig, add, mul, out);
  return static_cast<float>(out);
}

float Hook_SpeedDigger(void *self, void *stack, void *block) {
  float r = gOrig_SpeedDigger(self, stack, block);
  int n = ++gCalls_SpeedDigger;
  if (n <= 5) Log("SPEED_DIGGER call #%d: orig=%g stack=%p", n, (double)r, stack);
  return ApplyMiningEdit("SPEED_DIGGER", r, stack);
}

float Hook_SpeedWeapon(void *self, void *stack, void *block) {
  float r = gOrig_SpeedWeapon(self, stack, block);
  int n = ++gCalls_SpeedWeapon;
  if (n <= 5) Log("SPEED_WEAPON call #%d: orig=%g stack=%p", n, (double)r, stack);
  return ApplyMiningEdit("SPEED_WEAPON", r, stack);
}


// ---- 攻撃力・防御力・防具強度の個体別変更（v5.0） ----
// 関数表の項目（攻撃力=38番、防御力=59番、防具強度=60番）を差し替える。これらの関数は Item しか受け取らず、
// どの ItemStack の値かは分からない。そこで、呼び出し元が持っているレジスタ x19〜x22 の値を受け取り、
// 「その値（またはそれが指す先）が、self(Item) を持つ ItemStack か」を確かめて、持ち主の ItemStack を探す。
// 確かめられなければ元の値のまま返す（見つからない場合に、他のアイテムの値を変えてしまうことはない）。
//   変更後の値 = (元の値 + 〜Add) × 〜Mul   （四捨五入して整数にする）
//   攻撃力: attackAdd / attackMul    防御力: defenseAdd / defenseMul    防具強度: toughnessAdd / toughnessMul
constexpr bool kEnableStatEdit = true; // false にすると、関数表の差し替えは行わない
uint64_t gLibBase = 0;

// ItemStack の中身: [+8] = mItem の入れ物へのポインタ、[入れ物] = Item*（ItemStackBase::getItem の逆アセンブルどおり）
bool ItemOfStack(uint64_t stack, uint64_t *item) {
  uint64_t holder = 0;
  if (!SafeRead(stack + 8, &holder, 8)) return false;
  holder = Mask(holder);
  if (holder < 0x10000) return false;
  return SafeRead(holder, item, 8);
}

uint64_t FindOwnerStack(void *self, const uint64_t *regs) {
  if (!regs) return 0;
  const uint64_t selfV = Mask(reinterpret_cast<uint64_t>(self));
  for (int i = 0; i < 4; i++) {
    const uint64_t cand = Mask(regs[i]);
    if (cand < 0x10000) continue;
    for (int deref = 0; deref < 2; deref++) {
      uint64_t p = cand;
      if (deref) { // レジスタが ItemStack へのポインタを指している場合（一覧をたどる処理など）
        if (!SafeRead(cand, &p, 8)) continue;
        p = Mask(p);
      }
      if (p < 0x10000 || (p & 7) != 0) continue;
      uint64_t item = 0;
      if (ItemOfStack(p, &item) && Mask(item) == selfV) return p;
    }
  }
  return 0;
}

using IntGetter = int (*)(void *);
IntGetter gOrigStat[4] = {}; // 0: 剣の攻撃力  1: ツルハシ・シャベル等の攻撃力  2: 防御力  3: 防具強度

struct StatKeys {
  const char *label;
  const char *addKey;
  const char *mulKey;
};
const StatKeys kStatKeys[4] = {
    {"ATK_WEAPON", "attackAdd", "attackMul"},
    {"ATK_DIGGER", "attackAdd", "attackMul"},
    {"ARMOR_DEFENSE", "defenseAdd", "defenseMul"},
    {"ARMOR_TOUGHNESS", "toughnessAdd", "toughnessMul"},
};
std::atomic<int> gStatEdits[4];
std::atomic<int> gStatMisses[4];

// 差し替え関数から呼ばれる本体。regs は呼び出し元の x19〜x22（x86 のテストでは nullptr）
int StatImpl(void *self, const uint64_t *regs, int which) __asm__("EnchantProbe_StatImpl");
__attribute__((used, noinline)) int StatImpl(void *self, const uint64_t *regs, int which) {
  const int orig = gOrigStat[which](self);
  if (!kEnableStatEdit) return orig;
  const uint64_t stack = FindOwnerStack(self, regs);
  if (stack == 0) {
    const int m = ++gStatMisses[which];
    if (m <= 3) Log("%s: owner ItemStack not found (self=%p) #%d", kStatKeys[which].label, self, m);
    return orig;
  }
  uint64_t tag = 0;
  if (!SafeRead(stack + 0x10, &tag, 8) || Mask(tag) < 0x10000) return orig;
  WantedNum w[2] = {{kStatKeys[which].addKey, 0.0, false}, {kStatKeys[which].mulKey, 1.0, false}};
  ReadDynamicNumbers(reinterpret_cast<void *>(tag), w, 2);
  if (!w[0].found && !w[1].found) return orig;
  const double add = w[0].found ? ClampD(w[0].val, -100.0, 1000.0) : 0.0;
  const double mul = w[1].found ? ClampD(w[1].val, 0.0, 100.0) : 1.0;
  const double out = ClampD((static_cast<double>(orig) + add) * mul, 0.0, 10000.0);
  const int result = static_cast<int>(out + 0.5);
  const int n = ++gStatEdits[which];
  if (ShouldLog(n)) Log("%s edit #%d: orig=%d add=%g mul=%g -> %d", kStatKeys[which].label, n, orig, add, mul, result);
  return result;
}

// 差し替え関数。呼び出し元の x19〜x22 を保存して StatImpl に渡す（x0 の self はそのまま、x2 に番号を入れる）
#if defined(__aarch64__)
#define STAT_WRAPPER(NAME, N)                                  \
  __attribute__((naked)) int NAME(void *) {                    \
    __asm__ volatile(                                          \
        "sub sp, sp, #0x30\n"                                  \
        "stp x19, x20, [sp]\n"                                 \
        "stp x21, x22, [sp, #0x10]\n"                          \
        "str x30, [sp, #0x20]\n"                               \
        "mov x1, sp\n"                                         \
        "mov x2, #" #N "\n"                                    \
        "bl EnchantProbe_StatImpl\n"                           \
        "ldr x30, [sp, #0x20]\n"                               \
        "add sp, sp, #0x30\n"                                  \
        "ret\n");                                              \
  }
#else
#define STAT_WRAPPER(NAME, N) \
  int NAME(void *self) { return StatImpl(self, nullptr, N); }
#endif
STAT_WRAPPER(Wrap_AtkWeapon, 0)
STAT_WRAPPER(Wrap_AtkDigger, 1)
STAT_WRAPPER(Wrap_Armor59, 2)
STAT_WRAPPER(Wrap_Armor60, 3)

struct VtPatch {
  const char *name;
  uint64_t vtOff;    // 関数表の先頭（0番）の位置（base から）
  int slot;          // 差し替える項目の番号
  uint64_t origOff;  // 今入っているはずの関数（base から）。違えば差し替えない
  void *wrapper;     // 差し替える観察用の関数
  uint64_t slotAddr;
  bool applied;
};
std::vector<VtPatch> gPatches;

// 関数表の1項目（8バイト）を書き換える。読み取り専用のページは、一時的に書き込み可能にして戻す
bool WriteSlot(uint64_t slotAddr, uint64_t value) {
  const long page = sysconf(_SC_PAGESIZE);
  if (page <= 0) return false;
  const uint64_t start = slotAddr & ~static_cast<uint64_t>(page - 1);
  if (mprotect(reinterpret_cast<void *>(start), static_cast<size_t>(page), PROT_READ | PROT_WRITE) != 0) return false;
  *reinterpret_cast<volatile uint64_t *>(slotAddr) = value;
  mprotect(reinterpret_cast<void *>(start), static_cast<size_t>(page), PROT_READ);
  return true;
}

void InstallStatPatches(uint64_t base) {
  gLibBase = base;
  gOrigStat[0] = reinterpret_cast<IntGetter>(base + 0xfd672d8);
  gOrigStat[1] = reinterpret_cast<IntGetter>(base + 0xffe6a90);
  gOrigStat[2] = reinterpret_cast<IntGetter>(base + 0xff805bc);
  gOrigStat[3] = reinterpret_cast<IntGetter>(base + 0xff805c4);
  // 関数表の位置と元の関数は、vtables_item.txt（実機で取得）の値。今入っている関数が違えば差し替えない
  VtPatch table[] = {
      {"Weapon/38", 0x1306db38, 38, 0xfd672d8, reinterpret_cast<void *>(&Wrap_AtkWeapon), 0, false},
      {"Digger/38", 0x1308bf30, 38, 0xffe6a90, reinterpret_cast<void *>(&Wrap_AtkDigger), 0, false},
      {"Pickaxe/38", 0x13085d70, 38, 0xffe6a90, reinterpret_cast<void *>(&Wrap_AtkDigger), 0, false},
      {"Shovel/38", 0x1307d3b0, 38, 0xffe6a90, reinterpret_cast<void *>(&Wrap_AtkDigger), 0, false},
      {"Armor/59", 0x13089df0, 59, 0xff805bc, reinterpret_cast<void *>(&Wrap_Armor59), 0, false},
      {"Armor/60", 0x13089df0, 60, 0xff805c4, reinterpret_cast<void *>(&Wrap_Armor60), 0, false},
  };
  for (VtPatch &p : table) {
    p.slotAddr = base + p.vtOff + 8ull * static_cast<uint64_t>(p.slot);
    uint64_t cur = 0;
    if (!SafeRead(p.slotAddr, &cur, 8) || cur != base + p.origOff) {
      Log("%s: vtable slot holds 0x%llx (expected +0x%llx). skipped.", p.name, (unsigned long long)cur,
          (unsigned long long)p.origOff);
      continue;
    }
    if (WriteSlot(p.slotAddr, reinterpret_cast<uint64_t>(p.wrapper))) {
      p.applied = true;
      Log("%s: vtable slot %d replaced (stat edit)", p.name, p.slot);
    } else {
      Log("%s: mprotect failed. skipped.", p.name);
    }
    gPatches.push_back(p);
  }
}

void RemoveStatPatches() {
  for (VtPatch &p : gPatches) {
    if (p.applied && WriteSlot(p.slotAddr, gLibBase + p.origOff)) p.applied = false;
  }
}

struct SpeedTarget {
  const char *name;
  uintptr_t offset;
  uint32_t expectWord; // 先頭の命令（この値と完全に一致しなければ入れない）
  void **orig;
  void *detour;
};

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
    Log("EnchantHookProbe v5.0 start (mining speed edit %s, stat edit %s).", kEnableMiningEdit ? "ON" : "OFF", kEnableStatEdit ? "ON" : "OFF");

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

    gDoubleVt = base + kDoubleVtOffset;

    // 採掘速度のフック: 先頭の命令が想定どおりのときだけ入れる（版が違えば何もしない）
    if (kEnableMiningEdit) {
      const SpeedTarget speedTargets[] = {
          {"SPEED_DIGGER_e71f0", 0xffe71f0, 0xfc1d0fe8, reinterpret_cast<void **>(&gOrig_SpeedDigger),
           reinterpret_cast<void *>(&Hook_SpeedDigger)},
          {"SPEED_WEAPON_67148", 0xfd67148, 0xd10283ff, reinterpret_cast<void **>(&gOrig_SpeedWeapon),
           reinterpret_cast<void *>(&Hook_SpeedWeapon)},
      };
      mSpeedHooks.resize(sizeof(speedTargets) / sizeof(speedTargets[0]));
      for (size_t i = 0; i < mSpeedHooks.size(); i++) {
        const SpeedTarget &t = speedTargets[i];
        const uintptr_t addr = base + t.offset;
        const uint32_t w = ReadWord(addr);
        if (w != t.expectWord) {
          Log("%s: first word 0x%08x (expected 0x%08x). skipped.", t.name, w, t.expectWord);
          continue;
        }
        mSpeedHooks[i] = pl::memory::HookHandle(reinterpret_cast<void *>(addr), t.detour, t.orig,
                                                pl::memory::HookPriority::Normal);
        Log("%s: hook installed=%d (+0x%llx)", t.name, mSpeedHooks[i].installed() ? 1 : 0,
            (unsigned long long)t.offset);
      }
    }
    if (kEnableStatEdit) InstallStatPatches(base);

    std::thread([base]() {
      std::vector<Range> data;
      uint64_t lo = 0, hi = 0;
      if (!ReadLibMaps(data, lo, hi)) { Log("VTSCAN: maps not found"); return; }
      Log("VTSCAN start: %zu data ranges", data.size());
      ScanVtables(data, lo, hi, base, kVtClasses, static_cast<int>(sizeof(kVtClasses) / sizeof(kVtClasses[0])));
    }).detach();
    return true;
  }

  bool disable() {
    for (auto &h : mHooks) h.reset();
    for (auto &h : mSpeedHooks) h.reset();
    RemoveStatPatches();
    return true;
  }

  bool unload() { return true; }

  [[nodiscard]] ll::mod::NativeMod &getSelf() const { return mSelf; }

private:
  ll::mod::NativeMod &mSelf;
  std::vector<pl::memory::HookHandle> mHooks;
  std::vector<pl::memory::HookHandle> mSpeedHooks;
};

PL_REGISTER_MOD(HookProbeMod, HookProbeMod::instance())
