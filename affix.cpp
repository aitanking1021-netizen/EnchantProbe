// EnchantAffix (実験版)
// 「アイテムごとの効果」は、そのアイテムに付いているエンチャントで決まります。
// 各エンチャント(ID 0〜41)に対して、ダメージ加算(関数表9番)と防御軽減(7番)を
// エンチャントごとの倍率・固定加算で書き換えます。元の関数はそのまま呼びます。
//
//   damage_mult.<名前>      = ダメージ加算にかける倍率      (既定 1.0)
//   damage_flat.<名前>      = レベル1あたり加える固定ダメージ (既定 0.0)
//   protection_mult.<名前>  = 防御軽減にかける倍率           (既定 1.0)
//   protection_flat.<名前>  = レベル1あたり加える固定の軽減    (既定 0.0)
//
// 設定: /storage/emulated/0/Android/media/<ランチャー>/EnchantAffix/config.txt
// ログ: 同じフォルダの log.txt

#include <android/log.h>
#include <dlfcn.h>
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

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "EnchantAffix", __VA_ARGS__)

static const uintptr_t kLibSpan = 0x20000000;  // 本体内のアドレスとみなす範囲(512MB)
static const int kSlotProtection = 7;          // 被ダメージ軽減
static const int kSlotDamageBonus = 9;         // ダメージ加算
static const int kCount = 42;                  // エンチャントの種類(ID 0〜41)

// ID順の名前(EnchantLvlModifier の config と同じ並び)
static const char* kNames[kCount] = {
    "protection", "fire_protection", "feather_falling", "blast_protection", "projectile_protection",
    "thorns", "respiration", "depth_strider", "aqua_affinity", "sharpness", "smite",
    "bane_of_arthropods", "knockback", "fire_aspect", "looting", "efficiency", "silk_touch",
    "unbreaking", "fortune", "power", "punch", "flame", "infinity", "luck_of_the_sea", "lure",
    "frost_walker", "mending", "binding", "vanishing", "impaling", "riptide", "loyalty",
    "channeling", "multishot", "piercing", "quick_charge", "soul_speed", "swift_sneak",
    "wind_burst", "density", "breach", "lunge"};

struct Section {
    uintptr_t addr;
    size_t size;
};

struct Rule {
    float damageMult = 1.0f, damageFlat = 0.0f;
    float protMult = 1.0f, protFlat = 0.0f;
};

static Rule gRules[kCount];
static char gLogPath[700] = {0};
static std::atomic<int> gMeleeCalls{0};
static std::atomic<int> gProtCalls{0};

// 余分なレジスタ引数も元の関数にそのまま渡すための型(引数の形が未確認のため)
typedef float (*FnFloat)(void*, long, long, long, long, long);
typedef int (*FnInt)(void*, long, long, long, long, long);
static FnFloat gOrigMelee = nullptr;
static FnInt gOrigProt = nullptr;

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

static int EnchantId(void* self) {
    int id = (int)*(uint8_t*)((uintptr_t)self + 0x8);  // EnchantLvlModifier と同じ読み方
    return id < kCount ? id : -1;
}

// ---- 差し替え後の関数 ----------------------------------------------------

static float HookDamageBonus(void* self, long a, long b, long c, long d, long e) {
    float orig = gOrigMelee(self, a, b, c, d, e);
    int id = EnchantId(self);
    if (id < 0) return orig;
    int level = (int)a;
    float res = orig * gRules[id].damageMult + gRules[id].damageFlat * (float)level;
    int n = ++gMeleeCalls;
    if (n <= 40 || n % 500 == 0)
        Log("damage #%d id=%d(%s) level=%d orig=%f -> %f", n, id, kNames[id], level, orig, res);
    return res;
}

static int HookProtection(void* self, long a, long b, long c, long d, long e) {
    int orig = gOrigProt(self, a, b, c, d, e);
    int id = EnchantId(self);
    if (id < 0) return orig;
    int level = (int)a;
    int res = (int)((float)orig * gRules[id].protMult + gRules[id].protFlat * (float)level + 0.5f);
    if (res < 0) res = 0;
    int n = ++gProtCalls;
    if (n <= 40 || n % 500 == 0)
        Log("protection #%d id=%d(%s) level=%d orig=%d -> %d", n, id, kNames[id], level, orig, res);
    return res;
}

// ---- 本体(libminecraftpe.so)の解析 --------------------------------------

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

// 関数表の1項目を書き換える(書き込み許可を一時的に取り、すぐ読み取り専用に戻す)
static bool PatchSlot(void** vt, int slot, void* fn) {
    uintptr_t addr = (uintptr_t)&vt[slot];
    uintptr_t page = addr & ~((uintptr_t)sysconf(_SC_PAGESIZE) - 1);
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    if (mprotect((void*)page, ps, PROT_READ | PROT_WRITE) != 0) return false;
    vt[slot] = fn;
    mprotect((void*)page, ps, PROT_READ);
    return true;
}

static bool InLib(void* p, uintptr_t base) {
    uintptr_t v = (uintptr_t)p;
    return v >= base && v < base + kLibSpan;
}

// ---- 設定 ----------------------------------------------------------------

static float Clamp(float v, float lo, float hi) {
    if (!(v >= lo)) return lo;  // NaNも下限に寄せる
    return v > hi ? hi : v;
}

// "damage_mult.sharpness=2.0" のような1行を読み取る
static void ParseLine(const char* line) {
    char key[96];
    float v = 0;
    if (sscanf(line, " %95[^=]=%f", key, &v) != 2) return;
    struct Kind { const char* prefix; int field; float lo, hi; };
    static const Kind kinds[] = {
        {"damage_mult.", 0, 0.0f, 100.0f}, {"damage_flat.", 1, -50.0f, 100.0f},
        {"protection_mult.", 2, 0.0f, 100.0f}, {"protection_flat.", 3, -10.0f, 20.0f}};
    for (const Kind& k : kinds) {
        size_t pl = strlen(k.prefix);
        if (strncmp(key, k.prefix, pl) != 0) continue;
        for (int i = 0; i < kCount; i++) {
            if (strcmp(key + pl, kNames[i]) != 0) continue;
            float x = Clamp(v, k.lo, k.hi);
            Rule& r = gRules[i];
            (k.field == 0 ? r.damageMult : k.field == 1 ? r.damageFlat : k.field == 2 ? r.protMult : r.protFlat) = x;
            return;
        }
    }
}

static void LoadConfig(const char* dir) {
    // 実験用の既定値: 近接(smite=5倍 / bane_of_arthropods=レベル1あたり+2)、防御(fire_protection=3倍)
    gRules[10].damageMult = 5.0f;
    gRules[11].damageFlat = 2.0f;
    gRules[1].protMult = 3.0f;

    char p[700];
    snprintf(p, sizeof(p), "%s/config.txt", dir);
    FILE* f = fopen(p, "r");
    if (!f) {
        f = fopen(p, "w");
        if (f) {
            fprintf(f, "# <種類>.<エンチャント名>=<数値>  (種類: damage_mult / damage_flat / protection_mult / protection_flat)\n");
            fprintf(f, "# 書かなかった項目は、倍率が1.0、固定加算が0.0(=元のまま)になります。\n");
            fprintf(f, "damage_mult.smite=5.0\ndamage_flat.bane_of_arthropods=2.0\nprotection_mult.fire_protection=3.0\n");
            fclose(f);
        }
        return;
    }
    // 設定ファイルがある場合は、ファイルの内容だけを使う(実験用の既定値は消す)
    for (int i = 0; i < kCount; i++) gRules[i] = Rule();
    char line[160];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;
        ParseLine(line);
    }
    fclose(f);
}

// ---- 起動時の処理 --------------------------------------------------------

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

    char dir[600];
    snprintf(dir, sizeof(dir), "/storage/emulated/0/Android/media/%s/EnchantAffix", pkg);
    mkdir(dir, 0777);
    snprintf(gLogPath, sizeof(gLogPath), "%s/log.txt", dir);
    FILE* lf = fopen(gLogPath, "w");  // 起動のたびにログを作り直す
    if (lf) fclose(lf);

    LoadConfig(dir);
    int active = 0;
    for (int i = 0; i < kCount; i++) {
        const Rule& r = gRules[i];
        if (r.damageMult != 1.0f || r.damageFlat != 0.0f || r.protMult != 1.0f || r.protFlat != 0.0f) {
            Log("rule %s: damage x%.2f +%.2f/Lv | protection x%.2f +%.2f/Lv", kNames[i],
                r.damageMult, r.damageFlat, r.protMult, r.protFlat);
            active++;
        }
    }
    Log("EnchantAffix start. %d rule(s).", active);

    void** baseVt = FindVtable(ro, drr, "7Enchant");
    void** meleeVt = FindVtable(ro, drr, "18MeleeWeaponEnchant");
    void** protVt = FindVtable(ro, drr, "17ProtectionEnchant");
    if (!baseVt || !meleeVt || !protVt) {
        Log("vtable not found. nothing patched.");
        return;
    }

    bool okMelee = InLib(meleeVt[kSlotDamageBonus], base) && meleeVt[kSlotDamageBonus] != baseVt[kSlotDamageBonus];
    bool okProt = InLib(protVt[kSlotProtection], base) && protVt[kSlotProtection] != baseVt[kSlotProtection];

    if (okMelee) {
        gOrigMelee = (FnFloat)meleeVt[kSlotDamageBonus];
        Log("melee slot %d: patched=%d", kSlotDamageBonus, PatchSlot(meleeVt, kSlotDamageBonus, (void*)&HookDamageBonus) ? 1 : 0);
    } else {
        Log("melee slot %d does not look as expected. skipped.", kSlotDamageBonus);
    }
    if (okProt) {
        gOrigProt = (FnInt)protVt[kSlotProtection];
        Log("protection slot %d: patched=%d", kSlotProtection, PatchSlot(protVt, kSlotProtection, (void*)&HookProtection) ? 1 : 0);
    } else {
        Log("protection slot %d does not look as expected. skipped.", kSlotProtection);
    }
}
