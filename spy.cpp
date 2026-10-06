// EnchantSpy (調査用)
// 近接エンチャントの「攻撃後の処理」(関数表の10番)に割り込み、呼ばれたときの引数を記録します。
// 元の関数はそのまま呼ぶので、ゲームの動作は変わりません。
// 攻撃した側・された側のクラス名と関数表(最大400項目)も書き出します。
//
// ログ: /storage/emulated/0/Android/media/<ランチャー>/EnchantSpy/log.txt
// 関数表: 同じフォルダの vtable_<クラス名>.txt

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

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "EnchantSpy", __VA_ARGS__)

static const uintptr_t kLibSpan = 0x20000000;  // 本体内のアドレスとみなす範囲(512MB)
static const int kSlotPostAttack = 10;         // 攻撃後の処理
static const int kMaxVtableDump = 400;
static const int kMaxVtables = 4;

struct Section {
    uintptr_t addr;
    size_t size;
};

static char gDir[600] = {0};
static char gLogPath[700] = {0};
static uintptr_t gBase = 0;
static int gPipe[2] = {-1, -1};
static std::atomic<int> gCalls{0};
static uintptr_t gSeenVtables[kMaxVtables] = {0};
static int gSeenCount = 0;

typedef void (*FnPost)(void*, long, long, long, long, long);
static FnPost gOrigPost = nullptr;

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

// 不正なアドレスでも落ちずに読むための関数(パイプへ書き込めるかで判定する)
static bool SafeRead(const void* p, void* out, size_t n) {
    if (gPipe[0] < 0 || !p || n == 0 || n > 64) return false;
    if ((uintptr_t)p < 0x10000) return false;
    ssize_t w = write(gPipe[1], p, n);
    if (w != (ssize_t)n) {
        if (w > 0) {  // 途中まで入った分は捨てる
            char tmp[64];
            read(gPipe[0], tmp, (size_t)w);
        }
        return false;
    }
    return read(gPipe[0], out, n) == (ssize_t)n;
}

static bool InLib(uintptr_t v) { return v >= gBase && v < gBase + kLibSpan; }

// オブジェクトの先頭 -> 関数表の位置、 関数表の1つ前 -> typeinfo -> クラス名
static bool ObjectInfo(long objPtr, uintptr_t* vtOut, char* name, size_t nameLen) {
    uintptr_t vt = 0;
    if (!SafeRead((void*)objPtr, &vt, sizeof(vt))) return false;
    if (!InLib(vt)) return false;
    *vtOut = vt;
    name[0] = 0;
    uintptr_t ti = 0, np = 0;
    if (SafeRead((void*)(vt - 8), &ti, sizeof(ti)) && SafeRead((void*)(ti + 8), &np, sizeof(np))) {
        size_t i = 0;
        for (; i + 1 < nameLen; i++) {
            char ch = 0;
            if (!SafeRead((void*)(np + i), &ch, 1) || ch == 0) break;
            name[i] = (ch >= 32 && ch < 127) ? ch : '?';
        }
        name[i] = 0;
    }
    return true;
}

static void DumpVtable(uintptr_t vt, const char* name) {
    char safe[96];
    size_t k = 0;
    for (const char* s = name; *s && k + 1 < sizeof(safe); s++)
        safe[k++] = ((*s >= '0' && *s <= '9') || (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z')) ? *s : '_';
    safe[k] = 0;
    char path[800];
    snprintf(path, sizeof(path), "%s/vtable_%s.txt", gDir, safe[0] ? safe : "unknown");
    FILE* f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# %s vtable=+0x%llx (slot offset-from-base)\n", name, (unsigned long long)(vt - gBase));
    int n = 0;
    for (; n < kMaxVtableDump; n++) {
        uintptr_t v = 0;
        if (!SafeRead((void*)(vt + (uintptr_t)n * 8), &v, 8) || !InLib(v)) break;
        fprintf(f, "%d +0x%llx\n", n, (unsigned long long)(v - gBase));
    }
    fprintf(f, "# slots=%d\n", n);
    fclose(f);
}

static void Inspect(const char* role, long objPtr) {
    uintptr_t vt = 0;
    char name[128];
    if (!ObjectInfo(objPtr, &vt, name, sizeof(name))) {
        Log("  %s=%#lx (not an object / unreadable)", role, objPtr);
        return;
    }
    Log("  %s=%#lx class=%s vtable=+0x%llx", role, objPtr, name, (unsigned long long)(vt - gBase));
    for (int i = 0; i < gSeenCount; i++)
        if (gSeenVtables[i] == vt) return;
    if (gSeenCount < kMaxVtables) {
        gSeenVtables[gSeenCount++] = vt;
        DumpVtable(vt, name);
    }
}

// ---- 差し替え後の関数 ----------------------------------------------------

static void HookPostAttack(void* self, long a, long b, long c, long d, long e) {
    int n = ++gCalls;
    if (n <= 12) {
        uint8_t id = 255;
        SafeRead((const char*)self + 8, &id, 1);
        Log("postAttack #%d enchantId=%d level(arg3)=%ld", n, (int)id, (long)(int)c);
        Inspect("arg1", a);
        Inspect("arg2", b);
    }
    gOrigPost(self, a, b, c, d, e);  // 元の処理はそのまま実行する
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

// ---- 起動時の処理 --------------------------------------------------------

__attribute__((constructor)) static void Init() {
    Section ro{}, drr{};
    if (!LoadSections(ro, drr, gBase)) {
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

    snprintf(gDir, sizeof(gDir), "/storage/emulated/0/Android/media/%s/EnchantSpy", pkg);
    mkdir(gDir, 0777);
    snprintf(gLogPath, sizeof(gLogPath), "%s/log.txt", gDir);
    FILE* lf = fopen(gLogPath, "w");  // 起動のたびに作り直す
    if (lf) fclose(lf);

    if (pipe(gPipe) != 0) {
        gPipe[0] = gPipe[1] = -1;
        Log("pipe failed; spy disabled");
        return;
    }

    void** baseVt = FindVtable(ro, drr, "7Enchant");
    void** meleeVt = FindVtable(ro, drr, "18MeleeWeaponEnchant");
    if (!baseVt || !meleeVt) {
        Log("vtable not found. nothing patched.");
        return;
    }
    bool ok = InLib((uintptr_t)meleeVt[kSlotPostAttack]) && meleeVt[kSlotPostAttack] != baseVt[kSlotPostAttack];
    if (!ok) {
        Log("melee slot %d does not look as expected. skipped.", kSlotPostAttack);
        return;
    }
    gOrigPost = (FnPost)meleeVt[kSlotPostAttack];
    bool patched = PatchSlot(meleeVt, kSlotPostAttack, (void*)&HookPostAttack);
    Log("EnchantSpy start. melee slot %d: original=+0x%llx patched=%d", kSlotPostAttack,
        (unsigned long long)((uintptr_t)gOrigPost - gBase), patched ? 1 : 0);
}
