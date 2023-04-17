#include "prover.h"

#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/pos.h>
#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/bls_key.h>

#include <plog/Log.h>
#include <tinyformat.h>

#include <algorithm>

#ifdef _WIN32

#include <windows.h>

#endif

namespace miner {

using MatchFunc = std::function<bool(std::string const&)>;

std::tuple<std::vector<std::string>, uint64_t> EnumFilesFromDir(std::string const& dir, MatchFunc accept_func) {
    std::vector<std::string> res;
    uint64_t total_size{0};
    try {
        for (auto const& dir_entry : fs::directory_iterator(fs::path(dir))) {
            if (!fs::is_directory(dir_entry.path()) && accept_func(dir_entry.path().string())) {
                res.push_back(dir_entry.path().string());
                total_size += fs::file_size(dir_entry.path());
            }
        }
    } catch (std::exception& e) {
        PLOGE << tinyformat::format("cannot read dir: %s", dir);
    }
    return std::make_tuple(res, total_size);
}

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

void Prover::RevokeByFarmerPk(chiapos::PubKey const& farmer_pk) {
    auto it_rm = std::remove_if(std::begin(m_plotter_files), std::end(m_plotter_files),
                                [&farmer_pk](chiapos::CPlotFile const& plot_file) -> bool {
                                    chiapos::PlotMemo memo;
                                    plot_file.ReadMemo(memo);
                                    assert(memo.farmer_pk.size() == farmer_pk.size());
                                    return (chiapos::MakeArray<chiapos::PK_LEN>(memo.farmer_pk) == farmer_pk);
                                });
    m_plotter_files.erase(it_rm, std::end(m_plotter_files));
}

bool Prover::QueryFullProof(Path const& plot_path, uint256 const& challenge, int index, chiapos::Bytes& out,
                            chiapos::PubKey& out_farmer_pk) {
    chiapos::CPlotFile plotFile(plot_path.string());
    chiapos::PlotMemo memo;
    if (!plotFile.ReadMemo(memo)) {
        throw std::runtime_error(tinyformat::format("cannot read memo from plot file: %s", plot_path));
    }
    assert(memo.farmer_pk.size() == out_farmer_pk.size());
    memcpy(out_farmer_pk.data(), memo.farmer_pk.data(), out_farmer_pk.size());
    return plotFile.GetFullProof(challenge, index, out);
}

bool Prover::ReadPlotMemo(Path const& plot_file_path, chiapos::PlotMemo& out) {
    chiapos::CPlotFile plotFile(plot_file_path.string());
    return plotFile.ReadMemo(out);
}

chiapos::Bytes Prover::CalculateLocalPkBytes(chiapos::Bytes const& local_master_sk) {
    chiapos::CWallet wallet(chiapos::CKey(chiapos::MakeArray<chiapos::SK_LEN>(local_master_sk)));
    auto local_key = wallet.GetLocalKey(0);
    return chiapos::MakeBytes(local_key.GetPubKey());
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
