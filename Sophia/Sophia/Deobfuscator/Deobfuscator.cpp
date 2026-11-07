#include "../../Pch.h"
#include "Deobfuscator.h"
#include "DeobfContext.h"
#include "DeobfEncoders.h"
#include "DeobfIo.h"
#include "Targets/DeobfuscationTarget.h"
#include "Targets/ControlFlow/OpaqueJccTarget.h"
#include "Targets/ControlFlow/IndBranchTarget.h"
#include "Targets/Constants/MovConstTarget.h"
#include "Targets/Constants/ArithConstTarget.h"
#include "Targets/Constants/LeaConstTarget.h"
#include "Targets/Strings/StringBufferTarget.h"
#include "Targets/Strings/VecRedirectTarget.h"
#include "Targets/ControlFlow/CompareTarget.h"
#include "Targets/ControlFlow/IatTarget.h"
#include "Targets/ControlFlow/RopTarget.h"
#include "Targets/ControlFlow/CallParamTarget.h"
#include "Targets/SyscallParamTarget.h"
#include "Targets/ControlFlow/CfgWalkTarget.h"
#include "../Database/AutoDebugStore.h"
#include "../WinPE/PEScan.h"

#include <windows.h>
#include <Zydis/Zydis.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>


bool LoadFileBuf(const std::string& filepath, std::vector<uint8_t>& outbuf, std::string& outerr)
{
    std::ifstream f(filepath, std::ios::binary | std::ios::ate);
    if (!f)
    {
        outerr = "could not reopen input file for read";
        return false;
    }
    std::streamoff sz = f.tellg();
    f.seekg(0);
    outbuf.resize(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(outbuf.data()), static_cast<std::streamsize>(sz));
    if (!f)
    {
        outerr = "short read on input";
        return false;
    }
    return true;
}

bool WriteRebuild(const std::filesystem::path& outpath, const std::vector<uint8_t>& buf, std::string& outerr)
{
    std::ofstream of(outpath, std::ios::binary | std::ios::trunc);
    if (!of)
    {
        outerr = "could not open output file for write: " + outpath.string();
        return false;
    }
    of.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (!of)
    {
        outerr = "write failed on " + outpath.string();
        return false;
    }
    return true;
}


Deobfuscator::Report Deobfuscator::Run(const std::string& filepath)
{
    Report r;
    std::error_code ec;

    if (!std::filesystem::exists(filepath, ec))
    {
        r.Error = "file not found: " + filepath;
        DeobfIo::PrintFatal(r.Error);
        return r;
    }

    AutoDebugStore store;
    if (!store.OpenReadOnly(filepath))
    {
        r.Error = "no sophiaproj/<stem> directory for this input, or the projectdir is unreadable -- nothing to deobfuscate against";
        DeobfIo::PrintFatal(r.Error);
        return r;
    }
    DeobfIo::PrintProjectInfo(store.Dir().wstring(), store.Sha256());

    if (!store.LoadObservations())
    {
        DeobfIo::PrintFatal("LoadObservations reported errors -- continuing with what loaded");
    }
    const ObsStats& os = store.Stats();
    DeobfIo::PrintStoreStats(os, os.TotalRecords, os.UniqueRvas);

    if (os.Branches == 0)
    {
        r.Error = "no branch observations -- pass 1 has nothing to work with";
        DeobfIo::PrintFatal(r.Error);
        return r;
    }

    DeobfContext ctx;
    ctx.Filepath = filepath;
    ctx.Store = &store;
    DeobfIo::PromptConfig(ctx.Cfg);

    {
        std::string curhash;
        uint64_t curSize = 0;
        if (AutoDebugStore::HashFileSha256(filepath, curhash, curSize) &&
            !store.Sha256().empty() && curhash != store.Sha256())
        {
            DeobfIo::PrintHashMismatchWarn(store.Sha256(), curhash);
        }
    }

    ctx.Sites = PeScan::ScanFile(filepath, ctx.PreferredBase);
    if (ctx.Sites.empty())
    {
        r.Error = "PeScan produced no sites -- input has no scannable code";
        DeobfIo::PrintFatal(r.Error);
        return r;
    }

    ctx.BranchIdxByRva.reserve(ctx.Sites.size());
    for (size_t i = 0; i < ctx.Sites.size(); ++i)
    {
        if (ctx.Sites[i].Kind == SiteKind::Branch)
        {
            ctx.BranchIdxByRva.emplace(ctx.Sites[i].Rva, i);
        }
    }

    for (const InsnSite& s : ctx.Sites)
    {
        if (DeobfEncoders::IsPlainJcc(s)) ++r.JccTotal;
    }

    DeobfIo::PrintPescanStats(ctx.Sites.size(), r.JccTotal);

    if (!LoadFileBuf(filepath, ctx.Buf, r.Error))
    {
        DeobfIo::PrintFatal(r.Error);
        return r;
    }
    std::printf("[deobf] loaded %zu bytes of source PE into rewrite buffer\n", ctx.Buf.size());

    if (!DeobfEncoders::BuildSectionMap(ctx.Buf, ctx.Sm))
    {
        r.Error = "PE section-table parse failed on the loaded buffer";
        DeobfIo::PrintFatal(r.Error);
        return r;
    }

    ZydisDecoderInit(&ctx.Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ctx.PreMovRewriteBuf = ctx.Buf;

    std::vector<std::unique_ptr<DeobfuscationTarget>> targets;
    targets.reserve(16);
    targets.emplace_back(std::make_unique<OpaqueJccTarget>());
    targets.emplace_back(std::make_unique<IndBranchTarget>());
    targets.emplace_back(std::make_unique<MovConstTarget>());
    targets.emplace_back(std::make_unique<ArithConstTarget>());
    targets.emplace_back(std::make_unique<LeaConstTarget>());
    targets.emplace_back(std::make_unique<StringBufferTarget>());
    targets.emplace_back(std::make_unique<VecRedirectTarget>());
    targets.emplace_back(std::make_unique<CompareTarget>());
    targets.emplace_back(std::make_unique<IatTarget>());
    targets.emplace_back(std::make_unique<RopTarget>());
    targets.emplace_back(std::make_unique<CallParamTarget>());
    targets.emplace_back(std::make_unique<SyscallParamTarget>());
    targets.emplace_back(std::make_unique<CfgWalkTarget>());

    for (const auto& t : targets)
    {
        if (!t->Enabled(ctx.Cfg))
        {
            DeobfIo::PrintSkip(t->Name(), "by user (category disabled)");
            continue;
        }
        t->Deobfuscate(ctx, r);
    }

    std::filesystem::path ext = std::filesystem::path(filepath).extension();
    std::filesystem::path outpath = store.Dir() / (L"rebuild.soph" + ext.wstring());
    if (!WriteRebuild(outpath, ctx.Buf, r.Error))
    {
        DeobfIo::PrintFatal(r.Error);
        return r;
    }
    r.OutputPath = outpath;
    std::printf("[deobf] wrote %ls (%zu bytes)\n", outpath.wstring().c_str(), ctx.Buf.size());

    r.Ok = true;
    return r;
}

void Deobfuscator::PrintReport(const Report& r)
{
    DeobfIo::PrintReport(r);
}