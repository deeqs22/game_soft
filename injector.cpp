#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "deeqs_inject", __VA_ARGS__)

// Шелл-код для вызова dlopen
uint8_t shellcode[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // x0 (путь)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // x8 (dlopen)
    0x40, 0x00, 0x80, 0xD2,                         // MOV X1, #2
    0x00, 0x01, 0x3F, 0xD6,                         // BLR X8
    0xC0, 0x03, 0x5F, 0xD6                          // RET
};

uintptr_t find_dlopen(pid_t pid) {
    char maps_path[64], line[512];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* f = fopen(maps_path, "r");
    if (!f) return 0;
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libdl.so")) {
            sscanf(line, "%lx-%*lx", &base);
            break;
        }
    }
    fclose(f);
    if (!base) return 0;
    
    char dl_path[64];
    snprintf(dl_path, sizeof(dl_path), "/proc/%d/root/system/lib64/libdl.so", pid);
    int fd = open(dl_path, O_RDONLY);
    if (fd < 0) return 0;
    
    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh)) { close(fd); return 0; }
    
    Elf64_Shdr* shdrs = (Elf64_Shdr*)malloc(eh.e_shnum * sizeof(Elf64_Shdr));
    lseek(fd, eh.e_shoff, SEEK_SET);
    read(fd, shdrs, eh.e_shnum * sizeof(Elf64_Shdr));
    
    const char* strtab = NULL;
    Elf64_Sym* symtab = NULL;
    int sym_count = 0;
    
    for (int i = 0; i < eh.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            symtab = (Elf64_Sym*)malloc(shdrs[i].sh_size);
            lseek(fd, shdrs[i].sh_offset, SEEK_SET);
            read(fd, symtab, shdrs[i].sh_size);
            sym_count = shdrs[i].sh_size / sizeof(Elf64_Sym);
        }
    }
    
    for (int i = 0; i < eh.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            int str_idx = shdrs[i].sh_link;
            if (str_idx >= 0 && str_idx < eh.e_shnum) {
                strtab = (const char*)malloc(shdrs[str_idx].sh_size);
                lseek(fd, shdrs[str_idx].sh_offset, SEEK_SET);
                read(fd, (void*)strtab, shdrs[str_idx].sh_size);
            }
        }
    }
    
    uintptr_t dlopen_offset = 0;
    if (symtab && strtab) {
        for (int i = 0; i < sym_count; i++) {
            if (strcmp(strtab + symtab[i].st_name, "dlopen") == 0) {
                dlopen_offset = symtab[i].st_value;
                break;
            }
        }
    }
    
    free(symtab); free((void*)strtab); free(shdrs);
    close(fd);
    return base + dlopen_offset;
}

bool write_memory(pid_t pid, uintptr_t addr, const void* data, size_t len) {
    struct iovec local = { (void*)data, len };
    struct iovec remote = { (void*)addr, len };
    return syscall(__NR_process_vm_writev, pid, &local, 1, &remote, 1, 0) == (ssize_t)len;
}

void inject_memfd(pid_t pid, const char* local_so_path) {
    int fd = open(local_so_path, O_RDONLY);
    if (fd < 0) { LOGI("[-] Failed to open .so"); return; }
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    void* so_data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    int mem_fd = syscall(__NR_memfd_create, "liboxide_cheat", 0);
    if (mem_fd < 0) { LOGI("[-] memfd_create failed"); return; }
    write(mem_fd, so_data, size);
    lseek(mem_fd, 0, SEEK_SET);

    char path[128];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", mem_fd);

    uintptr_t dlopen_addr = find_dlopen(pid);
    if (!dlopen_addr) { LOGI("[-] Failed to find dlopen"); return; }

    char maps_path[64], line[512];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* f = fopen(maps_path, "r");
    uintptr_t free_addr = 0;
    while (f && fgets(line, sizeof(line), f)) {
        if (strstr(line, "rw-p")) { sscanf(line, "%lx-%*lx", &free_addr); break; }
    }
    if (f) fclose(f);
    if (!free_addr) { LOGI("[-] Failed to find free region"); return; }

    uintptr_t path_addr = free_addr;
    uintptr_t code_addr = free_addr + 256;

    write_memory(pid, path_addr, path, strlen(path) + 1);

    uint64_t* patch = (uint64_t*)shellcode;
    patch[0] = path_addr;
    patch[1] = dlopen_addr;
    write_memory(pid, code_addr, shellcode, sizeof(shellcode));

    LOGI("[+] Injection successful! Path at %lx, code at %lx", path_addr, code_addr);
}

int main(int argc, char** argv) {
    if (argc < 3) { LOGI("Usage: %s <pid> <lib_path>", argv[0]); return 1; }
    pid_t pid = atoi(argv[1]);
    inject_memfd(pid, argv[2]);
    return 0;
}