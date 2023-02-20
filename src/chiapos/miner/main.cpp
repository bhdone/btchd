#include <chainparams.h>
#include <chainparamsbase.h>
#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/vdf.h>
#include <chiapos/timelord.h>
#include <gtest/gtest.h>
#include <plog/Appenders/ConsoleAppender.h>
#include <plog/Appenders/RollingFileAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Init.h>
#include <plog/Log.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <vdf_computer.h>
#include <util/validation.h>

#include <boost/asio.hpp>
#include <chrono>
#include <cstdint>
#include <cxxopts.hpp>
#include <fstream>
#include <functional>
#include <string>
#include <thread>

#ifdef _WIN32
#include <shlobj.h>
#include <windows.h>
#endif

#include <subsidy_utils.h>

#include "bhd_types.h"
#include "chiapos_miner.h"
#include "config.h"
#include "keyman.h"
#include "prover.h"
#include "rpc_client.h"
#include "test1.h"
#include "tools.h"

const std::function<std::string(char const*)> G_TRANSLATION_FUN = nullptr;

namespace miner {

enum class CommandType : int {
    UNKNOWN,
    GEN_CONFIG,
    MINING,
    BIND,
    DEPOSIT,
    REGARGET,
    WITHDRAW,
    BLOCK_SUBSIDY,
    SUPPLIED,
    MAX
};

std::string ConvertCommandToString(CommandType type) {
    switch (type) {
        case CommandType::UNKNOWN:
            return "(unknown)";
        case CommandType::GEN_CONFIG:
            return "generate-config";
        case CommandType::MINING:
            return "mining";
        case CommandType::BIND:
            return "bind";
        case CommandType::DEPOSIT:
            return "deposit";
        case CommandType::WITHDRAW:
            return "withdraw";
        case CommandType::BLOCK_SUBSIDY:
            return "block_subsidy";
        case CommandType::SUPPLIED:
            return "supplied";
        case CommandType::REGARGET:
            return "retarget";
        case CommandType::MAX:
            return "(max)";
    }
    return "(unknown)";
}

int MaxOfCommands() { return static_cast<int>(CommandType::MAX); }

CommandType ParseCommandFromString(std::string const& str) {
    for (int i = 1; i < MaxOfCommands(); ++i) {
        auto cmd = static_cast<CommandType>(i);
        if (str == ConvertCommandToString(cmd)) {
            return cmd;
        }
    }
    return CommandType::UNKNOWN;
}

std::string GetCommandsList() {
    std::stringstream ss;
    for (int i = 1; i < MaxOfCommands(); ++i) {
        auto str = ConvertCommandToString(static_cast<CommandType>(i));
        if (i + 1 < MaxOfCommands()) {
            ss << str << ", ";
        } else {
            ss << str;
        }
    }
    return ss.str();
}

struct Arguments {
    std::string command;
    bool verbose;  // show debug logs
    bool help;
    bool valid_only;  // only show valid records
    // arguments for command `account`
    bool check;        // parameter to check status with commands `bind`, `deposit`
    int amount;        // set the amount to deposit
    DepositTerm term;  // The term those BHD should be locked on chain
    chiapos::Bytes tx_id;
    std::string address;
    // Network related
    int difficulty_constant_factor_bits;  // dcf bits (chain parameter)
    int filter_bits;                      // filter bits (chain parameter)
    std::string datadir;                  // The root path of the data directory
    std::string cookie_path;              // The file stores the connecting information of current btchd server
} g_args;

miner::Config g_config;

std::unique_ptr<CChainParams const> g_chainparams;

CChainParams const& BuildChainParams(bool testnet) {
    g_chainparams = CreateChainParams(testnet ? CBaseChainParams::TESTNET : CBaseChainParams::MAIN);
    return *g_chainparams;
}

CChainParams const& GetChainParams() {
    assert(g_chainparams);
    return *g_chainparams;
}

}  // namespace miner

int HandleCommand_GenConfig(std::string const& config_path) {
    PLOG_INFO << "writing a empty config file: " << config_path;

    miner::Config config;
    std::ofstream out(config_path);
    if (!out.is_open()) {
        throw std::runtime_error("cannot write config");
    }
    out << config.ToJsonString();

    return 0;
}

int HandleCommand_Mining() {
    miner::Prover prover(miner::StrListToPathList(miner::g_config.GetPlotPath()));
    std::unique_ptr<miner::RPCClient> pclient = tools::CreateRPCClient(miner::g_config, miner::g_args.cookie_path);
    // Start mining
    miner::Miner miner(*pclient, prover, miner::g_config.GetFarmerSk(), miner::g_config.GetFarmerPk(),
                       miner::g_config.GetRewardDest(), miner::g_args.difficulty_constant_factor_bits,
                       miner::g_args.filter_bits);
    return miner.Run();
}

int HandleCommand_Bind() {
    std::unique_ptr<miner::RPCClient> pclient = tools::CreateRPCClient(miner::g_config, miner::g_args.cookie_path);
    if (miner::g_args.check) {
        auto txs = pclient->ListBindTxs(miner::g_config.GetRewardDest(), 99999, 0, true, true);
        int COLUMN_WIDTH{15};
        for (auto const& tx : txs) {
            std::cout << std::setw(COLUMN_WIDTH) << "--> txid: " << chiapos::BytesToHex(tx.tx_id) << std::endl
                      << std::setw(COLUMN_WIDTH) << "height: " << tx.block_height << std::endl
                      << std::setw(COLUMN_WIDTH) << "address: " << tx.address << std::endl
                      << std::setw(COLUMN_WIDTH) << "farmer: " << tx.farmer_pk << std::endl
                      << std::setw(COLUMN_WIDTH) << "valid: " << (tx.valid ? "yes" : "invalid") << std::endl
                      << std::setw(COLUMN_WIDTH) << "active: " << (tx.active ? "yes" : "inactive") << std::endl;
        }
        return 0;
    }
    chiapos::Bytes tx_id = pclient->BindPlotter(miner::g_config.GetRewardDest(), miner::g_config.GetFarmerSk());
    PLOG_INFO << "tx id: " << chiapos::BytesToHex(tx_id);
    return 0;
}

int GetNumOfExpiredHeight(int nPledgeHeight, miner::DepositTerm type) {
    auto params = miner::GetChainParams().GetConsensus();
    auto i = static_cast<int>(type);
    auto info = params.BHDIP009PledgeTerms[i];
    return info.nLockHeight + nPledgeHeight;
}

CAmount CalcActualAmountByTerm(CAmount nAmount, miner::DepositTerm type) {
    auto params = miner::GetChainParams().GetConsensus();
    auto info = params.BHDIP009PledgeTerms[static_cast<int>(type)];
    return info.nWeightPercent * nAmount / 100;
}

CAmount CalcActualAmount(CAmount original, int nPledgeHeight, int nWithdrawHeight, miner::DepositTerm type, bool* pExpired) {
    auto nExpireOnHeight = GetNumOfExpiredHeight(nPledgeHeight, type);
    if (nWithdrawHeight >= nExpireOnHeight) {
        if (pExpired) {
            *pExpired = true;
        }
        return CalcActualAmountByTerm(original, miner::DepositTerm::NoTerm);
    } else {
        if (pExpired) {
            *pExpired = false;
        }
        return CalcActualAmountByTerm(original, type);
    }
}

int HandleCommand_Deposit() {
    std::unique_ptr<miner::RPCClient> pclient = tools::CreateRPCClient(miner::g_config, miner::g_args.cookie_path);
    auto challenge = pclient->QueryChallenge();
    auto current_height = challenge.target_height - 1;
    PLOG_INFO << "height: " << current_height;
    auto params = miner::GetChainParams();
    if (miner::g_args.check) {
        // Show all deposit tx
        auto result = pclient->ListDepositTxs(99999, 0, true, true);
        for (auto const& entry : result) {
            if (miner::g_args.valid_only && (!entry.valid || entry.revoked)) {
                continue;
            }
            bool expired;
            CAmount actual_amount = CalcActualAmount(entry.amount, (entry.retarget ? entry.point_height : entry.height), current_height, entry.term, &expired);
            int pledge_index = (int)entry.term - (int)miner::DepositTerm::NoTerm;
            int lock_height = params.GetConsensus().BHDIP009PledgeTerms[pledge_index].nLockHeight;
            PLOG_DEBUG << "Calculating withdraw amount: lock_height=" << lock_height << ", point_height=" << entry.point_height << ", current_height=" << current_height << ", amount=" << entry.amount;
            CAmount withdraw_amount = GetWithdrawAmount(lock_height, entry.point_height, current_height, entry.amount);
            std::cout << std::setw(7) << (entry.valid ? std::to_string(entry.height) : "--  ")
                      << (entry.retarget ? " [ retarget ] " : " [   point  ] ")
                      << chiapos::BytesToHex(entry.tx_id) << " --> " << entry.to
                      << std::setw(10) << chiapos::FormatNumberStr(std::to_string(static_cast<int>(entry.amount))) << " BHD [ "
                      << std::setw(6) << miner::DepositTermToString(entry.term) << " ] "
                      << std::setw(10) << chiapos::FormatNumberStr(std::to_string(actual_amount)) << " BHD (actual) "
                      << std::setw(10) << chiapos::FormatNumberStr(std::to_string(withdraw_amount)) << " BHD (withdraw) "
                      << ((entry.height != 0 && expired) ? "expired" : "")
                      << std::endl;
        }
        return 0;
    }
    // Deposit with amount
    chiapos::Bytes tx_id = pclient->Deposit(miner::g_config.GetRewardDest(), miner::g_args.amount, miner::g_args.term);
    PLOG_INFO << "tx id: " << chiapos::BytesToHex(tx_id);
    return 0;
}

int HandleCommand_Withdraw() {
    std::unique_ptr<miner::RPCClient> pclient = tools::CreateRPCClient(miner::g_config, miner::g_args.cookie_path);
    chiapos::Bytes tx_id = pclient->Withdraw(miner::g_args.tx_id);
    PLOG_INFO << "tx id: " << chiapos::BytesToHex(tx_id);
    return 0;
}

struct SubsidyRecord {
    time_t start_time;
    int first_height;
    int last_height;
    CAmount total;
};

std::string TimeToDate(time_t t) {
    tm* local = localtime(&t);
    std::stringstream ss;
    ss << local->tm_year + 1900 << "-" << std::setw(2) << std::setfill('0') << local->tm_mon + 1 << "-" << std::setw(2)
       << std::setfill('0') << local->tm_mday;
    return ss.str();
}

int HandleCommand_BlockSubsidy() {
    int const TOTAL_YEARS = 25;
    int const SECS_YEAR = 60 * 60 * 24 * 365;
    auto const& params = miner::GetChainParams().GetConsensus();
    int height{0};
    CAmount total_amount{0}, this_year_amount{0};
    int curr_secs{0}, total_years_counted{0};
    std::vector<SubsidyRecord> amounts;
    SubsidyRecord rec;
    rec.start_time = 1531292789;  // copied from mainnet
    rec.first_height = 0;
    time_t time_bhdip009{0};
    while (1) {
        CAmount block_amount = GetBlockSubsidy(height, params);
        total_amount += block_amount;
        this_year_amount += block_amount;
        // calculate target spacing of the block
        int target_spacing = height < params.BHDIP008Height ? params.BHDIP001TargetSpacing
                                                            : params.BHDIP008TargetSpacing;
        curr_secs += target_spacing;
        if (curr_secs >= SECS_YEAR) {
            rec.last_height = height;
            rec.total = this_year_amount;
            amounts.push_back(rec);
            // initialize the values from record
            rec.start_time += curr_secs;
            rec.first_height = height + 1;
            // reset variables
            curr_secs = 0;
            this_year_amount = 0;
            ++total_years_counted;
            if (total_years_counted == TOTAL_YEARS) {
                // done the calculation
                break;
            }
        }
        ++height;
        if (height == params.BHDIP009Height) {
            time_bhdip009 = rec.start_time + curr_secs;
            CAmount extra_bhdip009 = total_amount * (params.BHDIP009TotalAmountUpgradeMultiply - 1);
            this_year_amount += extra_bhdip009;
            total_amount += extra_bhdip009;
        }
    }
    // show results
    std::cout << "==== " << TOTAL_YEARS << " years, chia consensus hard-fork on height: "
              << chiapos::FormatNumberStr(std::to_string(params.BHDIP009Height)) << " (" << TimeToDate(time_bhdip009)
              << "), total amount: " << chiapos::FormatNumberStr(std::to_string(total_amount / COIN))
              << " ====" << std::endl;
    total_amount = 0;
    for (auto const& year_rec : amounts) {
        total_amount += year_rec.total;
        CAmount year_pledge_amount = year_rec.total / COIN * (1000 - params.BHDIP009FundRoyaltyForLowMortgage) / 1000;
        CAmount pledge_amount_full = total_amount;
        CAmount pledge_amount_10 = static_cast<double>(total_amount) * 0.1 / COIN;
        CAmount pledge_amount_30 = static_cast<double>(total_amount) * 0.3 / COIN;
        CAmount pledge_amount_50 = static_cast<double>(total_amount) * 0.5 / COIN;
        CAmount pledge_amount_70 = static_cast<double>(total_amount) * 0.7 / COIN;
        std::cout << TimeToDate(year_rec.start_time) << std::setfill(' ') << " (" << std::setw(8)
                  << year_rec.first_height << ", " << std::setw(8) << year_rec.last_height << "): " << std::setw(10)
                  << chiapos::FormatNumberStr(std::to_string(year_rec.total / COIN)) << " (BHD) - " << std::fixed
                  << std::setw(4) << std::setprecision(2) << static_cast<double>(year_pledge_amount) / pledge_amount_10
                  << ": 10%, " << std::setw(4) << std::setprecision(2)
                  << static_cast<double>(year_pledge_amount) / pledge_amount_30 << ": 30%, " << std::setw(4)
                  << std::setprecision(2) << static_cast<double>(year_pledge_amount) / pledge_amount_50 << ": 50%, "
                  << std::setw(4) << std::setprecision(2) << static_cast<double>(year_pledge_amount) / pledge_amount_70
                  << ": 70%, " << std::setw(4) << std::setprecision(2)
                  << static_cast<double>(year_pledge_amount) / pledge_amount_full << ": 100%" << std::endl;
    }
    return 0;
}

int HandleCommand_Supplied() {
    std::unique_ptr<miner::RPCClient> pclient = tools::CreateRPCClient(miner::g_config, miner::g_args.cookie_path);
    auto challenge = pclient->QueryChallenge();
    auto netspace = pclient->QueryNetspace();
    int height = challenge.prev_block_height;
    auto const& params = miner::GetChainParams().GetConsensus();
    CAmount total{0};
    for (int i = 0; i < height; ++i) {
        if (i == params.BHDIP009Height) {
            total = total * params.BHDIP009TotalAmountUpgradeMultiply;
        }
        CAmount block_amount = GetBlockSubsidy(i, params);
        total += block_amount;
    }
    PLOG_INFO << ">>> current height: " << height
              << ", total supplied: " << chiapos::FormatNumberStr(std::to_string(total / COIN)) << " BHD";
    PLOG_INFO << ">>> current netspace " << chiapos::FormatNumberStr(std::to_string(netspace.netCapacityTB))
              << " TB calculated on height " << netspace.calculatedOnHeight;
    return 0;
}

int HandleCommand_Retarget() {
    std::unique_ptr<miner::RPCClient> pclient = tools::CreateRPCClient(miner::g_config, miner::g_args.cookie_path);
    auto tx_id = pclient->RetargetPledge(miner::g_args.tx_id, miner::g_args.address);
    PLOG_INFO << "Retarget pledge to address: " << miner::g_args.address << ", tx_id: " << chiapos::BytesToHex(tx_id);
    return 0;
}

int HandleCommand_SupplyTest() {
    LOCK(cs_main);
    Consensus::Params const& params = miner::GetChainParams().GetConsensus();
    CAmount total_supply = GetTotalSupplyBeforeBHDIP009(params);
    PLOG_INFO << "Total supply (before BHDIP009): " << total_supply << "=" << total_supply / COIN << "(BHD)";
    return 0;
}

template <typename T>
T MakeRandomInt() {
    int n = sizeof(T);
    auto bytes = std::unique_ptr<uint8_t>(new uint8_t[n]);
    for (int i = 0; i < n; ++i) {
        bytes.get()[i] = rand() % 256;
    }
    T r;
    memcpy(&r, bytes.get(), n);
    return r;
}

uint256 MakeRandomUint256() {
    int n = 256 / 64;
    std::unique_ptr<uint64_t> r(new uint64_t[n]);
    for (int i = 0; i < n; ++i) {
        r.get()[i] = MakeRandomInt<uint64_t>();
    }
    uint256 res;
    memcpy(res.begin(), r.get(), 256 / 8);
    return res;
}

int main(int argc, char** argv) {
    plog::ConsoleAppender<plog::TxtFormatter> console_appender;

    cxxopts::Options opts("btchd-miner", "BitcoinHD miner - A mining program for BitcoinHD, chia PoC consensus.");
    opts.add_options()                            // All options
            ("h,help", "Show help document")      // --help
            ("v,verbose", "Show debug logs")      // --verbose
            ("valid", "Show only valid records")  // --valid
            ("l,log", "The path to the log file, turn it of with an empty string",
             cxxopts::value<std::string>()->default_value("miner.log"))  // --log
            ("log-max_size", "The max size of each log file",
             cxxopts::value<int>()->default_value(std::to_string(1024 * 1024 * 10)))  // --log-max_size
            ("log-max_count", "How many log files should be saved",
             cxxopts::value<int>()->default_value("10"))  // --log-max_count
            ("c,config", "The config file stores all miner information",
             cxxopts::value<std::string>()->default_value("./config.json"))  // --config
            ("no-proxy", "Do not use proxy")                                 // --no-proxy
            ("check", "Check the account status")                            // --check
            ("term", "The term of those BHD will be locked on chain (noterm, term1, term2, term3)",
             cxxopts::value<std::string>()->default_value("noterm"))  // --term
            ("txid", "The transaction id, it should be provided with command: withdraw, retarget",
             cxxopts::value<std::string>()->default_value(""))                                          // --txid
            ("amount", "The amount to be deposit", cxxopts::value<int>()->default_value("0"))           // --amount
            ("address", "The address for retarget or related commands", cxxopts::value<std::string>())  // --address
            ("dcf-bits", "Difficulty constant factor bits",
             cxxopts::value<int>()->default_value(
                     std::to_string(chiapos::DIFFICULTY_CONSTANT_FACTOR_BITS)))  // --dcf-bits
            ("filter-bits", "Filter bits for plot-id",
             cxxopts::value<int>()->default_value(
                     std::to_string(chiapos::NUMBER_OF_ZEROS_BITS_FOR_FILTER)))  // --filter-bits
            ("d,datadir", "The root path of the data directory",
             cxxopts::value<std::string>())  // --datadir, -d
            ("cookie", "Full path to `.cookie` from btchd datadir",
             cxxopts::value<std::string>())  // --cookie
            ("command", std::string("Command") + miner::GetCommandsList(),
             cxxopts::value<std::string>())  // --command
            ;

    opts.parse_positional({"command"});
    cxxopts::ParseResult result = opts.parse(argc, argv);
    if (result["help"].as<bool>()) {
        std::cout << opts.help() << std::endl;
        std::cout << "Commands (" << miner::GetCommandsList() << ")" << std::endl;
        std::cout << "Usage:" << std::endl;
        std::cout << "  You should use command `generate-config` to make a new blank config." << std::endl;
        return 0;
    }

    if (result.count("command")) {
        miner::g_args.command = result["command"].as<std::string>();
    } else {
        throw std::runtime_error("no command, please use --help to read how to use the program.");
    }

    auto config_path = result["config"].as<std::string>();
    if (config_path.empty()) {
        throw std::runtime_error("no config path, please use `--config` to set the path to your config");
    }

    // we need to generate config before parsing it
    auto cmd = miner::ParseCommandFromString(miner::g_args.command);
    if (cmd == miner::CommandType::GEN_CONFIG) {
        return HandleCommand_GenConfig(config_path);
    }

    miner::g_args.check = result["check"].as<bool>();
    miner::g_args.verbose = result["verbose"].as<bool>();
    miner::g_args.valid_only = result["valid"].as<bool>();
    miner::g_args.amount = result["amount"].as<int>();
    miner::g_args.term = miner::DepositTermFromString(result["term"].as<std::string>());
    if (result.count("txid")) {
        miner::g_args.tx_id = chiapos::BytesFromHex(result["txid"].as<std::string>());
    }

    if (result.count("address") > 0) {
        miner::g_args.address = result["address"].as<std::string>();
    }

    miner::g_config = tools::ParseConfig(config_path);

    if (result.count("datadir")) {
        // Customized datadir
        miner::g_args.datadir = result["datadir"].as<std::string>();
    } else {
        miner::g_args.datadir = tools::GetDefaultDataDir(miner::g_config.Testnet());
    }

    if (result.count("cookie")) {
        miner::g_args.cookie_path = result["cookie"].as<std::string>();
    } else {
        Path cookie_path(miner::g_args.datadir);
        cookie_path /= ".cookie";
        if (fs::exists(cookie_path)) {
            miner::g_args.cookie_path = cookie_path.string();
        }
    }

    miner::g_args.difficulty_constant_factor_bits = result["dcf-bits"].as<int>();

    if (result.count("filter-bits")) {
        miner::g_args.filter_bits = result["filter-bits"].as<int>();
    }

    plog::Severity severity_type = (miner::g_args.verbose ? plog::debug : plog::info);
    auto& logger = plog::init((miner::g_args.verbose ? plog::debug : plog::info), &console_appender);

    std::string log_path = result["log"].as<std::string>();
    log_path = result["log"].as<std::string>();
    if (!log_path.empty()) {
        int max_size = result["log-max_size"].as<int>();
        int max_count = result["log-max_count"].as<int>();
        static plog::RollingFileAppender<plog::TxtFormatter> rollingfile_appender(log_path.c_str(), max_size,
                                                                                  max_count);
        logger.addAppender(&rollingfile_appender);
    }

    PLOG_DEBUG << "Initialized log system";

    PLOG_INFO << "network: " << (miner::g_config.Testnet() ? "testnet" : "main");

    miner::BuildChainParams(miner::g_config.Testnet());

    try {
        switch (miner::ParseCommandFromString(miner::g_args.command)) {
            case miner::CommandType::MINING:
                return HandleCommand_Mining();
            case miner::CommandType::BIND:
                return HandleCommand_Bind();
            case miner::CommandType::DEPOSIT:
                return HandleCommand_Deposit();
            case miner::CommandType::WITHDRAW:
                return HandleCommand_Withdraw();
            case miner::CommandType::BLOCK_SUBSIDY:
                return HandleCommand_BlockSubsidy();
            case miner::CommandType::SUPPLIED:
                return HandleCommand_Supplied();
            case miner::CommandType::REGARGET:
                return HandleCommand_Retarget();
            case miner::CommandType::GEN_CONFIG:
            case miner::CommandType::UNKNOWN:
            case miner::CommandType::MAX:
                break;
        }
        throw std::runtime_error(std::string("unknown command: ") + miner::g_args.command);
    } catch (std::exception const& e) {
        PLOG_ERROR << e.what();
        return 1;
    }
}
