#include "stdafx.h"
#include "InjectionCore.h"

#include <iostream>
#include <iomanip>
#include <memory>

namespace
{
    constexpr wchar_t kTargetProcessName[] = L"TargetProcess.exe";
    constexpr wchar_t kPayloadDllName[] = L"Payload.dll";

    std::wstring BuildDllPath()
    {
        return blackbone::Utils::GetExeDirectory() + L"\\" + kPayloadDllName;
    }

    bool LoadImage(const std::wstring& path, vecPEImages& images)
    {
        auto image = std::make_shared<blackbone::pe::PEImage>();
        NTSTATUS status = image->Load(path);
        if (!NT_SUCCESS(status))
        {
            std::wcerr << L"[!] 지정된 DLL을 불러올 수 없습니다: " << path
                       << L" (NTSTATUS 0x" << std::hex << std::setw(8) << std::setfill(L'0') << status << std::dec << L")" << std::endl;
            std::wcerr << std::setfill(L' ');
            return false;
        }

        images.emplace_back(std::move(image));
        return true;
    }

    bool ResolveTargetProcess(uint32_t& pid)
    {
        auto pids = blackbone::Process::EnumByName(kTargetProcessName);
        if (pids.empty())
        {
            std::wcerr << L"[!] 대상 프로세스를 찾을 수 없습니다: " << kTargetProcessName << std::endl;
            return false;
        }

        pid = pids.front();
        return true;
    }
}

int wmain()
{
    SetConsoleOutputCP(CP_UTF8);

    std::wcout << L"[+] ALBIS Native Injector를 시작합니다." << std::endl;

    HWND consoleWindow = nullptr;
    InjectionCore injector(consoleWindow);

    InjectContext context;
    context.cfg.procName = kTargetProcessName;
    context.cfg.processMode = Existing;
    context.cfg.injectMode = Normal;
    context.cfg.hijack = true;
    context.cfg.unlink = true;
    context.cfg.erasePE = true;
    context.cfg.procCmdLine.clear();
    context.cfg.initRoutine.clear();
    context.cfg.initArgs.clear();
    context.cfg.mmapFlags = 0;
    context.cfg.delay = 0;
    context.cfg.period = 0;
    context.cfg.skipProc = 0;
    context.cfg.close = false;
    context.cfg.krnHandle = false;
    context.cfg.injIndef = false;

    const std::wstring dllPath = BuildDllPath();
    context.cfg.images.clear();
    context.cfg.images.emplace_back(dllPath);

    if (!LoadImage(dllPath, context.images))
        return 1;

    uint32_t pid = 0;
    if (!ResolveTargetProcess(pid))
        return 1;

    context.pid = pid;
    context.cfg.pid = pid;
    context.procPath = kTargetProcessName;

    std::wcout << L"[+] 대상 프로세스: " << kTargetProcessName << L" (PID=" << pid << L")" << std::endl;
    std::wcout << L"[+] 주입 DLL 경로: " << dllPath << std::endl;

    NTSTATUS status = injector.InjectMultiple(&context);
    if (!NT_SUCCESS(status))
    {
        auto description = blackbone::Utils::GetErrorDescription(status);
        std::wcerr << L"[!] 인젝션에 실패했습니다. NTSTATUS=0x" << std::hex << std::setw(8) << std::setfill(L'0') << status << std::dec;
        if (!description.empty())
            std::wcerr << L" (" << description << L")";
        std::wcerr << std::endl;
        std::wcerr << std::setfill(L' ');
        return 1;
    }

    std::wcout << L"[+] 인젝션이 성공적으로 완료되었습니다." << std::endl;
    return 0;
}
