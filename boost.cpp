// EnchantBoost (動作確認用の最小版)
// 1) 近接エンチャント(鋭さなど)のダメージ加算 に倍率をかける   (関数表の9番)
// 2) 防御エンチャント(ダメージ軽減など)の軽減量 に倍率をかける (関数表の7番)
// 元の関数をそのまま呼び、戻り値にだけ倍率をかけます。
//
// 設定:  /storage/emulated/0/Android/media/<ランチャー>/EnchantBoost/config.txt
// ログ:  /storage/emulated/0/Android/media/<ランチャー>/EnchantBoost/log.txt

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

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "EnchantBoost", __VA_ARGS__)

static const uintptr_t kLibSpan = 0x20000000;  // 本体内のアドレスとみなす範囲(512MB)
static const int kSlotProtection = 7;          // 被ダメージ軽減
static const int kSlotDamageBonus = 9;         // ダメージ加算

struct Section {
    uintptr_t addr;
    size_t size;
};

static float gDamageMul = 5.0f;
static float gProtectionMul = 3.0f;
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

// ---- 差し替え後の関数 ----------------------------------------------------

static float HookDamageBonus(void* self, long a, long b, long c, long d, long e) {
    float orig = gOrigMelee(self, a, b, c, d, e);
    float res = orig * gDamageMul;
    int n = ++gMeleeCalls;
    if (n <= 30 || n % 500 == 0) Log("melee #%d level=%d orig=%f boosted=%f", n, (int)a, orig, res);
    return res;
}

static int HookProtection(void* self, long a, long b, long c, long d, long e) {
    int orig = gOrigProt(self, a, b, c, d, e);
    int res = (int)((float)orig * gProtectionMul + 0.5f);
    int n = ++gProtCalls;
    if (n <= 30 || n % 500 == 0) Log("protection #%d level=%d orig=%d boosted=%d", n, (int)a, orig, res);
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

static float Clamp(float v) {
    if (!(v >= 0.0f)) return 1.0f;  // NaNや負の数は1倍に戻す
    return v > 100.0f ? 100.0f : v;
}

static void LoadConfig(const char* dir) {
    char p[700];
    snprintf(p, sizeof(p), "%s/config.txt", dir);
    FILE* f = fopen(p, "r");
    if (!f) {
        f = fopen(p, "w");
        if (f) {
            fprintf(f, "damage_multiplier=%.1f\nprotection_multiplier=%.1f\n", gDamageMul, gProtectionMul);
            fclose(f);
        }
        return;
    }
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        float v = 0;
        if (sscanf(line, "damage_multiplier=%f", &v) == 1) gDamageMul = Clamp(v);
        else if (sscanf(line, "protection_multiplier=%f", &v) == 1) gProtectionMul = Clamp(v);
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
    snprintf(dir, sizeof(dir), "/storage/emulated/0/Android/media/%s/EnchantBoost", pkg);
    mkdir(dir, 0777);
    snprintf(gLogPath, sizeof(gLogPath), "%s/log.txt", dir);

    FILE* lf = fopen(gLogPath, "w");  // 起動のたびにログを作り直す
    if (lf) fclose(lf);

    LoadConfig(dir);
    Log("EnchantBoost start. damage_multiplier=%.2f protection_multiplier=%.2f", gDamageMul, gProtectionMul);

    void** baseVt = FindVtable(ro, drr, "7Enchant");
    void** meleeVt = FindVtable(ro, drr, "18MeleeWeaponEnchant");
    void** protVt = FindVtable(ro, drr, "17ProtectionEnchant");
    if (!baseVt || !meleeVt || !protVt) {
        Log("vtable not found (base=%p melee=%p prot=%p). nothing patched.", (void*)baseVt, (void*)meleeVt, (void*)protVt);
        return;
    }

    // 想定どおりの関数表か確認する(ゲームの更新で並びが変わっていたら何もしない)
    bool okMelee = InLib(meleeVt[kSlotDamageBonus], base) && meleeVt[kSlotDamageBonus] != baseVt[kSlotDamageBonus];
    bool okProt = InLib(protVt[kSlotProtection], base) && protVt[kSlotProtection] != baseVt[kSlotProtection];

    if (okMelee) {
        gOrigMelee = (FnFloat)meleeVt[kSlotDamageBonus];
        bool ok = PatchSlot(meleeVt, kSlotDamageBonus, (void*)&HookDamageBonus);
        Log("melee slot %d: original=+0x%llx patched=%d", kSlotDamageBonus,
            (unsigned long long)((uintptr_t)gOrigMelee - base), ok ? 1 : 0);
    } else {
        Log("melee slot %d does not look as expected. skipped.", kSlotDamageBonus);
    }

    if (okProt) {
        gOrigProt = (FnInt)protVt[kSlotProtection];
        bool ok = PatchSlot(protVt, kSlotProtection, (void*)&HookProtection);
        Log("protection slot %d: original=+0x%llx patched=%d", kSlotProtection,
            (unsigned long long)((uintptr_t)gOrigProt - base), ok ? 1 : 0);
    } else {
        Log("protection slot %d does not look as expected. skipped.", kSlotProtection);
    }
}
