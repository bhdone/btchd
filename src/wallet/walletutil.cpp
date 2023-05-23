// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <logging.h>
#include <util/system.h>

#include <coins.h>
#include <chain.h>
#include <primitives/transaction.h>
#include <validation.h>

fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetArg("-walletdir", "");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = GetDataDir();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

static bool IsBerkeleyBtree(const fs::path& path)
{
    if (!fs::exists(path)) return false;

    // A Berkeley DB Btree file has at least 4K.
    // This check also prevents opening lock files.
    boost::system::error_code ec;
    auto size = fs::file_size(path, ec);
    if (ec) LogPrintf("%s: %s %s\n", __func__, ec.message(), path.string());
    if (size < 4096) return false;

    fsbridge::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    file.seekg(12, std::ios::beg); // Magic bytes start at offset 12
    uint32_t data = 0;
    file.read((char*) &data, sizeof(data)); // Read 4 bytes of file to compare against magic

    // Berkeley DB Btree magic bytes, from:
    //  https://github.com/file/file/blob/5824af38469ec1ca9ac3ffd251e7afe9dc11e227/magic/Magdir/database#L74-L75
    //  - big endian systems - 00 05 31 62
    //  - little endian systems - 62 31 05 00
    return data == 0x00053162 || data == 0x62310500;
}

std::vector<fs::path> ListWalletDir()
{
    const fs::path wallet_dir = GetWalletDir();
    const size_t offset = wallet_dir.string().size() + 1;
    std::vector<fs::path> paths;
    boost::system::error_code ec;

    for (auto it = fs::recursive_directory_iterator(wallet_dir, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            LogPrintf("%s: %s %s\n", __func__, ec.message(), it->path().string());
            continue;
        }

        // Get wallet path relative to walletdir by removing walletdir from the wallet path.
        // This can be replaced by boost::filesystem::lexically_relative once boost is bumped to 1.60.
        const fs::path path = it->path().string().substr(offset);

        if (it->status().type() == fs::directory_file && IsBerkeleyBtree(it->path() / "wallet.dat")) {
            // Found a directory which contains wallet.dat btree file, add it as a wallet.
            paths.emplace_back(path);
        } else if (it.depth() == 0 && it->symlink_status().type() == fs::regular_file && IsBerkeleyBtree(it->path())) {
            if (it->path().filename() == "wallet.dat") {
                // Found top-level wallet.dat btree file, add top level directory ""
                // as a wallet.
                paths.emplace_back();
            } else {
                // Found top-level btree file not called wallet.dat. Current bitcoin
                // software will never create these files but will allow them to be
                // opened in a shared database environment for backwards compatibility.
                // Add it to the list of available wallets.
                paths.emplace_back(path);
            }
        }
    }

    return paths;
}

WalletLocation::WalletLocation(const std::string& name)
    : m_name(name)
    , m_path(fs::absolute(name, GetWalletDir()))
{
}

bool WalletLocation::Exists() const
{
    return fs::symlink_status(m_path).type() != fs::file_not_found;
}


/**
 * @brief Get the Transaction By Coin object
 *
 * @param inputs Coins view
 * @param outpoint The outpoint
 * @param tx Transaction return
 * @param params consensus parameters
 *
 * @return true The transaction is good
 * @return false Cannot get the transaction
 */
// bool GetTransactionByOutPoint(CCoinsViewCache const& inputs, COutPoint const& outpoint, CTransactionRef& tx, CChain const& chain, Consensus::Params const& params)
// {
//     auto const& coin = inputs.AccessCoin(outpoint);
//     auto pindex = chain[coin.nHeight];
//     uint256 hashBlock;
//     return GetTransaction(outpoint.hash, tx, params, hashBlock, pindex);
// }

/**
 * @brief Get all retarget records according the outpoint that
 *
 * @param inputs Coins
 * @param outpointToPoint The outpoint to the POINT
 * @param params The consensus parameters
 *
 * @return std::vector<COutPoint> All RETARGET records those related to the POINT
 */
// std::vector<COutPoint> EnumeratePointRetargetRecords(CCoinsViewCache const& inputs, COutPoint const& outpointToPoint, Consensus::Params const& params)
// {
//     std::vector<COutPoint> res;
//     CTransactionRef tx;
//     uint256 hashBlock;
//     auto const& coin = inputs.AccessCoin(outpointToPoint);
//     CBlockIndex* pindex = ::ChainActive()[coin.nHeight];
//     if (!GetTransaction(outpointToPoint.hash, tx, params, hashBlock, pindex)) {
//         throw std::runtime_error("wrong transaction and it cannot be found from coins view");
//     }
//     auto cursor = inputs.Cursor(coin.refOutAccountID);
//     while (cursor->Valid()) {
//         Coin curCoin;
//         if (!cursor->GetValue(curCoin)) {
//             throw std::runtime_error("cannot read value from database");
//         }
//         if (curCoin.IsPointRetarget()) {
//             COutPoint curOutpoint;
//             if (!cursor->GetKey(curOutpoint)) {
//                 throw std::runtime_error("cannot read key from database");
//             }
//             CTransactionRef curTx;
//             if (!GetTransactionByOutPoint(inputs, curOutpoint, curTx, ::ChainActive(), params)) {
//                 throw std::runtime_error("cannot retrieve the tx");
//             }
//             if (curTx->vin[0].prevout == outpointToPoint) {
//                 res.push_back(curOutpoint);
//             }
//         }
//         // next
//         cursor->Next();
//     }
//     return res;
// }
