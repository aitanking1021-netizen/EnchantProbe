// EnchantAttrProbe
// アトリビュート／MobEffect系クラスの関数表(vtable)を読み取り、テキストに書き出すだけの調査用MODです。
// ゲームの動作は一切書き換えません（読み取り専用）。EnchantProbe の probe.cpp をベースにしています。
//
// 出力先: /storage/emulated/0/Android/media/<ランチャーのパッケージ名>/EnchantAttrProbe/vtables_attr.txt

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <strings.h>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "EnchantAttrProbe", __VA_ARGS__)

static const int kSlots = 48; // 各クラスで読む最大項目数（0が出たら関数表の終わりとみなして止める）
static const uintptr_t kLibSpan = 0x20000000; // 本体内のアドレスとみなす範囲(512MB)

struct Section {
  uintptr_t addr;
  size_t size;
};

// libminecraftpe.so の読み込み先と、.rodata / .data.rel.ro の位置を調べる
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
  if (fstat(fd, &st) < 0) {
    close(fd);
    return false;
  }
  void* map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) return false;

  bool ok = false;
  ElfW(Ehdr)* eh = (ElfW(Ehdr)*)map;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0) {
    ElfW(Shdr)* sh = (ElfW(Shdr)*)((uintptr_t)map + eh->e_shoff);
    const char* names = (const char*)((uintptr_t)map + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++) {
      const char* n = names + sh[i].sh_name;
      if (!strcasecmp(n, ".rodata")) {
        rodata.addr = base + sh[i].sh_addr;
        rodata.size = sh[i].sh_size;
      } else if (!strcasecmp(n, ".data.rel.ro")) {
        drr.addr = base + sh[i].sh_addr;
        drr.size = sh[i].sh_size;
      }
    }
    ok = rodata.addr && drr.addr;
  }
  munmap(map, st.st_size);
  return ok;
}

// クラス名の文字列(例: "9MobEffect") -> typeinfo -> 関数表 の順にたどる
static void** FindVtable(const Section& ro, const Section& drr, const char* typeStr) {
  size_t len = strlen(typeStr);
  char* zts = nullptr;
  size_t off = 0;
  while (off < ro.size) {
    char* m = (char*)memmem((void*)(ro.addr + off), ro.size - off, typeStr, len + 1);
    if (!m) break;
    if ((uintptr_t)m == ro.addr || *(m - 1) == '\0') {
      zts = m;
      break;
    }
    off = (uintptr_t)m - ro.addr + 1;
  }
  if (!zts) return nullptr;

  uintptr_t zti = 0;
  for (size_t i = 0; i + sizeof(uintptr_t) <= drr.size; i += sizeof(uintptr_t)) {
    if (*(uintptr_t*)(drr.addr + i) == (uintptr_t)zts) {
      zti = drr.addr + i - sizeof(uintptr_t);
      break;
    }
  }
  if (!zti) return nullptr;

  uintptr_t vtable = 0;
  for (size_t i = 0; i + sizeof(uintptr_t) <= drr.size; i += sizeof(uintptr_t)) {
    if (*(uintptr_t*)(drr.addr + i) == zti) {
      uintptr_t cand = drr.addr + i + sizeof(uintptr_t);
      if (i >= sizeof(uintptr_t) && *(uintptr_t*)(drr.addr + i - sizeof(uintptr_t)) == 0) {
        vtable = cand;
        break;
      }
      if (!vtable) vtable = cand;
    }
  }
  return (void**)vtable;
}

__attribute__((constructor)) static void Init() {
  Section ro{}, drr{};
  uintptr_t base = 0;
  if (!LoadSections(ro, drr, base)) {
    LOG("sections not found");
    return;
  }

  char pkg[256] = {0};
  FILE* cmd = fopen("/proc/self/cmdline", "rb");
  if (cmd) {
    fread(pkg, 1, sizeof(pkg) - 1, cmd);
    fclose(cmd);
  }
  if (!pkg[0]) strncpy(pkg, "org.levimc.launcher", sizeof(pkg) - 1);

  char dir[600], path[700];
  snprintf(dir, sizeof(dir), "/storage/emulated/0/Android/media/%s/EnchantAttrProbe", pkg);
  mkdir(dir, 0777);
  snprintf(path, sizeof(path), "%s/vtables_attr.txt", dir);
  FILE* f = fopen(path, "w");
  if (!f) {
    LOG("cannot open %s", path);
    return;
  }

  static const char* Classes[] = {
      // 効果（ポーション等）
      "9MobEffect", "21AttackDamageMobEffect", "19AbsorptionMobEffect",
      "22InstantaneousMobEffect", "20WindChargedMobEffect", "15OozingMobEffect",
      "16WeavingMobEffect", "17InfestedMobEffect",
      // アトリビュートの本体・修飾
      "17AttributeInstance", "17AttributeModifier", "13AttributeBuff",
      "21TemporalAttributeBuff", "26InstantaneousAttributeBuff",
      // 値が変わるときの処理
      "25AttributeInstanceDelegate", "23HealthAttributeDelegate",
      "23HungerAttributeDelegate", "27ExhaustionAttributeDelegate"};

  fprintf(f, "# EnchantAttrProbe base=0x%llx maxslots=%d\n", (unsigned long long)base, kSlots);
  fprintf(f, "# format: <class> <slot> <+offset from libminecraftpe base | raw:value>\n");
  fprintf(f, "# '<class> END <slot>' = 関数表の終わり（次の項目が0だった位置）\n");

  int found = 0;
  for (const char* name : Classes) {
    void** vt = FindVtable(ro, drr, name);
    if (!vt) {
      fprintf(f, "%s NOTFOUND\n", name);
      continue;
    }
    found++;
    fprintf(f, "%s vtable +0x%llx\n", name, (unsigned long long)((uintptr_t)vt - base));
    for (int i = 0; i < kSlots; i++) {
      uintptr_t v = (uintptr_t)vt[i];
      if (v == 0) {
        fprintf(f, "%s END %d\n", name, i);
        break;
      }
      if (v >= base && v < base + kLibSpan)
        fprintf(f, "%s %d +0x%llx\n", name, i, (unsigned long long)(v - base));
      else
        fprintf(f, "%s %d raw:0x%llx\n", name, i, (unsigned long long)v);
    }
  }
  fclose(f);
  LOG("wrote %s (%d/%zu classes)", path, found, sizeof(Classes) / sizeof(Classes[0]));
}
