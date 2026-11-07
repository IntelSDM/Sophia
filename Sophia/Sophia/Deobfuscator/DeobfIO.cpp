#include "../../Pch.h"
#include "DeobfIo.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

bool DeobfIo::PromptYesNo(const char* question, bool dflt)
{
    std::printf("%s [%s] ", question, dflt ? "y/n" : "y/n");
    std::fflush(stdout);
    std::string line;
    if (!std::getline(std::cin, line))
    {
        return dflt;
    }
    size_t i = 0;
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n'))
    {
        ++i;
    }
    if (i >= line.size())
    {
        return dflt;
    }
    char c = static_cast<char>(std::tolower(static_cast<unsigned char>(line[i])));
    if (c == 'y') return true;
    if (c == 'n') return false;
    return dflt;
}

void DeobfIo::PromptConfig(DeobfConfig& cfg)
{
    std::puts("");
    std::puts("[deobf] Category filter (empty / other input defaults to y):");
    cfg.WantBranch = PromptYesNo("Deobfuscate branches?     ", true);
    cfg.WantCall = PromptYesNo("Deobfuscate calls?        ", true);
    cfg.WantCompare = PromptYesNo("Deobfuscate compares?     ", true);
    cfg.WantArith = PromptYesNo("Deobfuscate arith?        ", true);
    cfg.WantMov = PromptYesNo("Deobfuscate movs?         ", true);
    cfg.WantVec = PromptYesNo("Deobfuscate vecs?         ", true);
    cfg.WantIndBranch = PromptYesNo("Deobfuscate indirect jmps?", true);
    cfg.WantIndCall = PromptYesNo("Deobfuscate indirect calls?", true);
    cfg.WantLea = PromptYesNo("Deobfuscate LEAs?         ", true);
    cfg.WantSyscall = PromptYesNo("Deobfuscate syscalls?     ", true);
    cfg.WantString = PromptYesNo("Deobfuscate strings?      ", true);

    std::puts("");
    std::puts("[deobf] List rewrites (packs multi-value sites into .sophXXXL):");
    if (cfg.WantMov)
    {
        cfg.WantMovList = PromptYesNo("  Apply mov list rewrite (.sophmovL)?  ", false);
    }
    if (cfg.WantArith)
    {
        cfg.WantAriList = PromptYesNo("  Apply arith list rewrite (.sophariL)?", false);
    }
    if (cfg.WantLea)
    {
        cfg.WantLeaList = PromptYesNo("  Apply LEA list rewrite (.sophleaL)?  ", false);
    }
    if (cfg.WantCompare)
    {
        cfg.WantCmpList = PromptYesNo("  Apply compare LEA-table (.sophcmp)?  ", false);
    }
}

void DeobfIo::Banner(const char* text)
{
    std::puts("");
    std::printf("[deobf] ==================== %s ====================\n", text);
}

void DeobfIo::RuleOpen(const char* text)
{
    std::puts("");
    std::printf("[deobf] ---------- %s ----------\n", text);
}

void DeobfIo::RuleClose()
{
    std::puts("[deobf] -----------------------------------------------");
}

void DeobfIo::Line(const char* text)
{
    std::printf("[deobf] %s\n", text);
}

void DeobfIo::KeyValueU32(const char* key, uint32_t value)
{
    std::printf("[deobf]   %-30s: %u\n", key, value);
}

void DeobfIo::KeyValueU64(const char* key, uint64_t value)
{
    std::printf("[deobf]   %-30s: %llu\n", key, static_cast<unsigned long long>(value));
}

void DeobfIo::KeyValueRvaU64(const char* key, uint64_t value)
{
    std::printf("[deobf]   %-30s: 0x%llx\n", key, static_cast<unsigned long long>(value));
}

void DeobfIo::KeyValueStr(const char* key, const char* value)
{
    std::printf("[deobf]   %-30s: %s\n", key, value ? value : "");
}

void DeobfIo::KeyValuePath(const char* key, const std::filesystem::path& p)
{
    if (p.empty()) return;
    std::printf("[deobf]   %-30s: %ls\n", key, p.wstring().c_str());
}

void DeobfIo::PrintProjectInfo(const std::wstring& dir, const std::string& hash)
{
    std::printf("[deobf] project: %ls\n", dir.c_str());
    std::printf("[deobf] manifest hash on file: %s\n", hash.empty() ? "(none)" : hash.c_str());
}

void DeobfIo::PrintStoreStats(const ObsStats& os, uint64_t totalrecords, uint64_t uniquervas)
{
    std::printf("[deobf] loaded %llu records across %llu unique RVAs\n",
        static_cast<unsigned long long>(totalrecords),
        static_cast<unsigned long long>(uniquervas));
    std::printf("[deobf]   branch=%u  call=%u  compare=%u  mov=%u  arith=%u  string=%u  vec=%u  ind_br=%u  ind_call=%u  lea=%u\n",
        os.Branches, os.Calls, os.Compares, os.Movs, os.Ariths, os.Strings, os.Vecs, os.IndBranches, os.IndCalls, os.Leas);
}

void DeobfIo::PrintPescanStats(size_t totalsites, uint32_t plainjccs)
{
    std::printf("[deobf] pescan: %zu total sites, %u are plain Jccs\n", totalsites, plainjccs);
}

void DeobfIo::PrintHashMismatchWarn(const std::string& manifesthash, const std::string& inputhash)
{
    std::fprintf(stderr,
        "[deobf] WARNING: input file hash differs from manifest hash.\n"
        "        manifest: %s\n"
        "        input:    %s\n"
        "        Observations may refer to RVAs that shifted or ceased to exist.\n",
        manifesthash.c_str(), inputhash.c_str());
}

void DeobfIo::PrintSkip(const char* passname, const char* reason)
{
    std::printf("[deobf] %s: SKIPPED %s\n", passname, reason);
    RuleClose();
}

void DeobfIo::PrintFatal(const std::string& msg)
{
    std::fprintf(stderr, "[deobf] %s\n", msg.c_str());
}

const char* DeobfIo::MnPadded(const char* mn)
{
    return (mn && mn[0]) ? mn : "";
}

void DeobfIo::PrintReport(const Deobfuscator::Report& r)
{
    Banner("summary");
    if (!r.Ok)
    {
        std::printf("[deobf] FAILED: %s\n", r.Error.c_str());
        std::puts("[deobf] =================================================");
        return;
    }
    std::printf("[deobf] ControlFlow Opaques:\n");
    KeyValueU32("Jcc sites in catalog", r.JccTotal);
    KeyValueU64("BranchHit records read", r.BranchRecordsSeen);
    KeyValueU32("Jcc sites observed at runtime", r.JccObserved);
    KeyValueU32("observed but non-Jcc", r.JccUnclassified);
    KeyValueU32("opaque (monopoly)", r.JccOpaque);
    KeyValueU32("always taken", r.JccAlwaysTaken);
    KeyValueU32("never taken", r.JccAlwaysNtaken);
    KeyValueU32("mixed (real conditionals)", r.JccMixed);
    std::printf("[deobf] opaques (rewrite):\n");
    KeyValueU32("opaques rewritten", r.JccRewriteOk);
    KeyValueU32("opaques skipped", r.JccRewriteSkip);
    KeyValueU64("bytes patched", r.BytesPatched);
    KeyValuePath("opaques log", r.OpaqueJccLogPath);

    std::printf("[deobf] ControlFlow Indirect Branch:\n");
    KeyValueU64("IndHit records read", r.IndRecordsSeen);
    KeyValueU32("indirect sites observed", r.IndObserved);
    KeyValueU32("monopoly (candidate)", r.IndMonopoly);
    KeyValueU32("mixed (dispatch table)", r.IndMixed);
    KeyValueU32("indirects rewritten", r.IndRewriteOk);
    KeyValueU32("indirects skipped", r.IndRewriteSkip);
    KeyValueU64("bytes patched", r.IndBytesPatched);
    KeyValuePath("indcalls log", r.IndCallsLogPath);
    KeyValuePath("indbranches log", r.IndBranchesLogPath);

    std::printf("[deobf] Constant MOV:\n");
    KeyValueU64("MovHit records read", r.MovRecordsSeen);
    KeyValueU32("mov sites observed", r.MovObserved);
    KeyValueU32("monopoly (candidate)", r.MovMonopoly);
    KeyValueU32("mixed (varying values)", r.MovMixed);
    KeyValueU32("movs rewritten", r.MovRewriteOk);
    KeyValueU32("in-place", r.MovRewriteInplace);
    KeyValueU32("trampoline", r.MovRewriteTramp);
    KeyValueU32("movs skipped", r.MovRewriteSkip);
    KeyValueU64("bytes patched", r.MovBytesPatched);
    if (r.MovTrampSectionBytes)
    {
        KeyValueRvaU64(".sophmov section RVA", r.MovTrampSectionRva);
        KeyValueU32(".sophmov section bytes", r.MovTrampSectionBytes);
        KeyValueU64("corruption avoided (bytes)", r.MovTrampBytesSaved);
    }

    std::printf("[deobf] Constant Arithmetic:\n");
    KeyValueU64("ArithHit records read", r.ArithRecordsSeen);
    KeyValueU32("rewritable arith sites obs.", r.ArithObserved);
    KeyValueU32("monopoly (candidate)", r.ArithMonopoly);
    KeyValueU32("mixed (varying inputs)", r.ArithMixed);
    KeyValueU32("ariths rewritten", r.ArithRewriteOk);
    KeyValueU32("in place", r.ArithRewriteInplace);
    KeyValueU32("trampoline", r.ArithRewriteTramp);
    KeyValueU32("ariths skipped", r.ArithRewriteSkip);
    KeyValueU64("bytes patched", r.ArithBytesPatched);
    if (r.ArithTrampSectionBytes)
    {
        KeyValueRvaU64(".sophari section RVA", r.ArithTrampSectionRva);
        KeyValueU32(".sophari section bytes", r.ArithTrampSectionBytes);
        KeyValueU64("corruption avoided (bytes)", r.ArithTrampBytesSaved);
    }

    std::printf("[deobf] Constant LEA:\n");
    KeyValueU64("LEA records read", r.LeaRecordsSeen);
    KeyValueU32("LEA sites observed", r.LeaObserved);
    KeyValueU32("monopoly (candidate)", r.LeaMonopoly);
    KeyValueU32("mixed (varying EA)", r.LeaMixed);
    KeyValueU32("LEAs rewritten", r.LeaRewriteOk);
    KeyValueU32("in place", r.LeaRewriteInplace);
    KeyValueU32("trampoline", r.LeaRewriteTramp);
    KeyValueU32("LEAs skipped", r.LeaRewriteSkip);
    KeyValueU64("bytes patched", r.LeaBytesPatched);
    if (r.LeaTrampSectionBytes)
    {
        KeyValueRvaU64(".sophlea section RVA", r.LeaTrampSectionRva);
        KeyValueU32(".sophlea section bytes", r.LeaTrampSectionBytes);
        KeyValueU64("corruption avoided (bytes)", r.LeaTrampBytesSaved);
    }

    std::printf("[deobf] String Buffer:\n");
    KeyValueU64("StringHit records read", r.StrRecordsSeen);
    KeyValueU64("VecHit records read", r.VecRecordsSeen);
    KeyValueU32("addr reconstruction failed", r.BufAddrFailed);
    KeyValueU32("distinct addrs observed", r.BufAddrsObserved);
    KeyValueU32("in-image", r.BufInImage);
    KeyValueU32("out of image", r.BufOutOfImage);
    KeyValueU32("monopoly", r.BufMonopoly);
    KeyValueU32("mixed", r.BufMixed);
    KeyValueU32("already plaintext", r.BufAlreadyPlaintext);
    KeyValueU32("buffers patched", r.BufPatchOk);
    KeyValueU32("buffers skipped", r.BufPatchSkip);
    KeyValueU64("bytes patched", r.BufBytesPatched);
    KeyValuePath("strings log", r.StringsLogPath);

    std::printf("[deobf] String Vec:\n");
    if (r.NoHeaderSlack)
    {
        std::printf("[deobf]   SKIPPED (no header slack for new section)\n");
    }
    else
    {
        KeyValueU32("candidates", r.RedirectCandidates);
        KeyValueU32("redirected", r.RedirectOk);
        KeyValueU32("multi addr bundles", r.RedirectMultiAddrSites);
        KeyValueU32("strings packed", r.RedirectStringsPacked);
        KeyValueU32("skip: no string-like content", r.RedirectSkipContent);
        KeyValueU32("skip: out of reach", r.RedirectSkipReach);
    }

    std::printf("[deobf] ControlFlow Compare:\n");
    KeyValueU64("compare records read", r.CmpRecordsSeen);
    KeyValueU32("distinct RVAs", r.CmpDistinctRvasSeen);
    KeyValueU32("in-scope observed", r.CmpObserved);
    KeyValueU32("monopoly", r.CmpMonopoly);
    KeyValueU32("mixed", r.CmpMixed);
    KeyValueU32("rewritten (imm)", r.CmpRewriteImmOk);
    KeyValueU32("rewritten (LEA table)", r.CmpRewriteLeaOk);
    KeyValueU32("skipped", r.CmpRewriteSkip);
    KeyValueU64("bytes patched", r.CmpBytesPatched);

    std::printf("[deobf] ControlFlow IAT:\n");
    KeyValueU64("IAT records read", r.IatRecordsSeen);
    KeyValueU32("sites observed", r.IatSitesObserved);
    KeyValueU32("monopoly", r.IatSitesMonopoly);
    KeyValueU32("mixed", r.IatSitesMixed);
    KeyValueU32("modules used", r.IatModulesUsed);
    KeyValueU32("exports used", r.IatExportsUsed);
    KeyValueU32("rewritten", r.IatRewriteOk);
    KeyValueU32("skipped", r.IatRewriteSkip);
    KeyValueU64("bytes patched", r.IatBytesPatched);

    std::printf("[deobf] ControlFlow ROP:\n");
    KeyValueU64("ROP records read", r.RopRecordsSeen);
    KeyValueU32("sites observed", r.RopSitesObserved);
    KeyValueU32("overlap with IAT", r.RopSitesOverlapIat);
    KeyValueU32("monopoly", r.RopSitesMonopoly);
    KeyValueU32("mixed", r.RopSitesMixed);
    KeyValueU32("gadgets unique", r.RopGadgetsUnique);
    KeyValueU32("gadgets extracted", r.RopGadgetsExtracted);
    KeyValueU32("rewritten (CALL)", r.RopRewriteOkCall);
    KeyValueU32("rewritten (JMP)", r.RopRewriteOkJmp);
    KeyValueU32("skipped", r.RopRewriteSkip);
    KeyValueU64("bytes patched", r.RopBytesPatched);
    KeyValueU64("gadget bytes", r.RopGadgetBytes);

    std::printf("[deobf] ControlFlow Call Parameters:\n");
    KeyValueU64("CallArg records read", r.CallargRecordsSeen);
    KeyValueU32("sites (IAT)", r.CallargSitesIat);
    KeyValueU32("sites (other)", r.CallargSitesOther);
    KeyValuePath("iat log", r.CallArgIatLogPath);
    KeyValuePath("other log", r.CallArgOtherLogPath);

    std::printf("[deobf] Syscalls:\n");
    std::printf("[deobf]   direct  masters/args/rets     : %llu / %llu / %llu\n",
        static_cast<unsigned long long>(r.SyscallDirectMasterRecords),
        static_cast<unsigned long long>(r.SyscallDirectArgRecords),
        static_cast<unsigned long long>(r.SyscallDirectRetRecords));
    std::printf("[deobf]   indirect masters/args/rets    : %llu / %llu / %llu\n",
        static_cast<unsigned long long>(r.SyscallIndirectMasterRecords),
        static_cast<unsigned long long>(r.SyscallIndirectArgRecords),
        static_cast<unsigned long long>(r.SyscallIndirectRetRecords));
    KeyValueU32("direct sites", r.SyscallDirectSites);
    KeyValueU32("indirect sites", r.SyscallIndirectSites);
    KeyValueU32("services named", r.SyscallServicesNamed);
    KeyValueU32("services unresolved", r.SyscallServicesUnnamed);
    KeyValuePath("direct log", r.SyscallsDirectLogPath);
    KeyValuePath("indirect log", r.SyscallsIndirectLogPath);

    std::printf("[deobf] DeadCode Blocks:\n");
    KeyValueU64("seed RVAs", r.SeedRvas);
    KeyValueU64("live instructions", r.LiveInstructions);
    KeyValueU64("code bytes total", r.CodeBytesTotal);
    KeyValueU64("live bytes", r.LiveBytes);
    KeyValueU64("dead bytes (identified)", r.DeadBytes);

    std::printf("[deobf] INT3 Fill:\n");
    KeyValueU32(".pdata function ranges", r.PdataFunctions);
    KeyValueU64("fillable bytes", r.PdataFillableBytes);
    if (r.Int3FillApplied)
    {
        KeyValueStr("applied", "YES");
        KeyValueU64("bytes filled with 0xCC", r.Int3Bytes);
    }
    else
    {
        KeyValueStr("applied", "NO (declined or no .pdata)");
    }
    if (r.OutputPath.empty())
    {
        std::puts("[deobf]   (no artifact produced this phase)");
    }
    else
    {
        std::printf("[deobf] output : %ls\n", r.OutputPath.wstring().c_str());
    }
    std::puts("[deobf] =================================================");
}