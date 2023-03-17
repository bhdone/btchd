#include "prover.h"

#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/pos.h>
#include <chiapos/kernel/utils.h>

#include <plog/Log.h>
#include <tinyformat.h>

#include <algorithm>

#include "keyman.h"

#ifdef _WIN32

#include <windows.h>

#endif

namespace miner {

using MatchFunc = std::function<bool(std::string const&)>;

#ifdef _WIN32

std::tuple<std::vector<std::string>, uint64_t> EnumFilesFromDir(std::string const& dir, MatchFunc accept_func) {
    std::vector<std::string> res;
    std::string dir_mask = dir + "\\*.*";
    uint64_t total_size{0};

    WIN32_FIND_DATA wfd;

    HANDLE hFind = FindFirstFile(dir_mask.c_str(), &wfd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return std::make_tuple(res, 0);
    }

    do {
        if (((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) && accept_func(wfd.cFileName)) {
            // Not a directory
            res.push_back(dir + "\\" + wfd.cFileName);
            total_size += wfd.nFileSizeLow;
            uint64_t hi_size = wfd.nFileSizeHigh;
            if (hi_size > 0) {
                hi_size <<= 32;
                total_size += hi_size;
            }
        }
    } while (FindNextFile(hFind, &wfd) != 0);

    DWORD dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES) {
        // TODO find next file reports error
    }

    FindClose(hFind);
    return std::make_tuple(res, total_size);
}

#else

std::tuple<std::vector<std::string>, uint64_t> EnumFilesFromDir(std::string const& dir, MatchFunc accept_func) {
    std::vector<std::string> res;
    uint64_t total_size{0};
    fs::directory_iterator i(fs::path(dir.c_str())), end;
    for (auto const& dir_entry : fs::directory_iterator(fs::path(dir))) {
        if (!fs::is_directory(dir_entry.path()) && accept_func(dir_entry.path().string())) {
            res.push_back(dir_entry.path().string());
            total_size += fs::file_size(dir_entry.path());
        }
    }
    return std::make_tuple(res, total_size);
}

#endif

bool ExtractExtName(std::string const& filename, std::string& out_ext_name) {
    auto pos = filename.find_last_of('.');
    if (pos != std::string::npos) {
        // ext name
        out_ext_name = filename.substr(pos);
        return true;
    }
    return false;
}

std::tuple<std::vector<std::string>, uint64_t> EnumPlotsFromDir(std::string const& dir) {
    return EnumFilesFromDir(dir, [](std::string const& filename) -> bool {
        // Extract ext name
        std::string ext_name;
        if (ExtractExtName(filename, ext_name)) {
            if (ext_name == ".plot") {
                return true;
            }
        }
        return false;
    });
}

std::vector<Path> StrListToPathList(std::vector<std::string> const& str_list) {
    std::vector<Path> path_list;
    std::transform(std::begin(str_list), std::end(str_list), std::back_inserter(path_list),
                   [](std::string const& str) { return Path(str); });
    return path_list;
}

Prover::Prover(std::vector<Path> const& path_list, std::vector<uint8_t> const& allowed_k_vec) {
    CSHA256 generator;
    for (auto const& path : path_list) {
        std::vector<std::string> files;
        uint64_t total_size;
        std::tie(files, total_size) = EnumPlotsFromDir(path.string());
        m_total_size += total_size;
        for (auto const& file : files) {
            chiapos::CPlotFile plotFile(file);
            if (plotFile.IsReady()) {
                bool allowed{true};
                if (!allowed_k_vec.empty()) {
                    auto it = std::find(std::begin(allowed_k_vec), std::end(allowed_k_vec), plotFile.GetK());
                    allowed = it != std::end(allowed_k_vec);
                }
                if (allowed) {
                    PLOGD << tinyformat::format("Add plot, k=%d, path=%s", (int)plotFile.GetK(), file);
                    auto plot_id = plotFile.GetPlotId();
                    generator.Write(plot_id.begin(), plot_id.size());
                    m_plotter_files.push_back(std::move(plotFile));
                }
            } else {
                m_total_size -= fs::file_size(file);
                PLOG_ERROR << "bad plot: " << file;
            }
        }
    }
    generator.Finalize(m_group_hash.begin());
    PLOG_INFO << "found total " << m_plotter_files.size() << " plots, group hash: " << m_group_hash.GetHex()
              << ", total size: " << chiapos::MakeNumberStr(m_total_size);
    if (!allowed_k_vec.empty()) {
        std::stringstream ss;
        for (auto k : allowed_k_vec) {
            ss << (int)k << ", ";
        }
        PLOG_INFO << "PlotK allowed: " << ss.str();
    }
}

std::vector<chiapos::QualityStringPack> Prover::GetQualityStrings(uint256 const& challenge, int bits_of_filter) const {
    std::vector<chiapos::QualityStringPack> res;
    for (auto const& plotFile : m_plotter_files) {
        if (bits_of_filter > 0 && !chiapos::PassesFilter(plotFile.GetPlotId(), challenge, bits_of_filter)) {
            continue;
        }
        PLOG_DEBUG << "passed for plot-id: " << plotFile.GetPlotId().GetHex() << ", challenge: " << challenge.GetHex();
        std::vector<chiapos::QualityStringPack> qstrs;
        if (plotFile.GetQualityString(challenge, qstrs)) {
            std::copy(std::begin(qstrs), std::end(qstrs), std::back_inserter(res));
        }
    }
    return res;
}

bool Prover::QueryFullProof(Path const& plot_path, uint256 const& challenge, int index, chiapos::Bytes& out) {
    chiapos::CPlotFile plotFile(plot_path.string());
    return plotFile.GetFullProof(challenge, index, out);
}

bool Prover::ReadPlotMemo(Path const& plot_file_path, chiapos::PlotMemo& out) {
    chiapos::CPlotFile plotFile(plot_file_path.string());
    return plotFile.ReadMemo(out);
}

chiapos::Bytes Prover::CalculateLocalPkBytes(chiapos::Bytes const& local_master_sk) {
    keyman::Key sk(chiapos::MakeArray<keyman::Key::PRIV_KEY_LEN>(local_master_sk));
    auto local_sk = keyman::Wallet::GetLocalKey(sk, 0);
    return chiapos::MakeBytes(local_sk.GetPublicKey());
}

bool Prover::VerifyProof(chiapos::Bytes const& plot_id, uint8_t k, uint256 const& challenge,
                         chiapos::Bytes const& proof) {
    if (proof.size() != k * 8) {
        // the length of proof itself is invalid
        return false;
    }
    uint256 mixed_quality_string = chiapos::MakeMixedQualityString(chiapos::MakeUint256(plot_id), k, challenge, proof);
    return !mixed_quality_string.IsNull();
}

}  // namespace miner
