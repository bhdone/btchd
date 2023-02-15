// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GUICONSTANTS_H
#define BITCOIN_QT_GUICONSTANTS_H

#include <cstdint>

/* Milliseconds between model updates */
static const int MODEL_UPDATE_DELAY = 250;

/* AskPassphraseDialog -- Maximum passphrase length */
static const int MAX_PASSPHRASE_SIZE = 1024;

/* BitcoinGUI -- Size of icons in status bar */
static const int STATUSBAR_ICONSIZE = 16;

static const bool DEFAULT_SPLASHSCREEN = true;

/* Invalid field background style */
#define STYLE_INVALID "background:#FF8080"

/* Transaction list -- unconfirmed transaction */
#define COLOR_UNCONFIRMED QColor(128, 128, 128)
/* Transaction list -- negative amount */
#define COLOR_NEGATIVE QColor(255, 0, 0)
/* Transaction list -- bare address (without label) */
#define COLOR_BAREADDRESS QColor(140, 140, 140)
/* Transaction list -- TX status decoration - open until date */
#define COLOR_TX_STATUS_OPENUNTILDATE QColor(64, 64, 255)
/* Transaction list -- TX status decoration - danger, tx needs attention */
#define COLOR_TX_STATUS_DANGER QColor(200, 100, 100)
/* Transaction list -- TX status decoration - default color */
#define COLOR_BLACK QColor(0, 0, 0)
/* Transaction list -- TX status decoration - disabled. point withdraw,unbind plotter */
#define COLOR_TX_STATUS_DISABLED QColor(192, 192, 192)

/* Address book -- Primary address */
#define COLOR_ADDRESSBOOK_PRIMARY QColor(240, 173, 78)

/* Tooltips longer than this (in characters) are converted into rich text,
   so that they can be word-wrapped.
 */
static const int TOOLTIP_WRAP_THRESHOLD = 80;

/* Number of frames in spinner animation */
#define SPINNER_FRAMES 36

#define QAPP_ORG_NAME "BitcoinHD"
#define QAPP_ORG_DOMAIN "bhd.one"
#define QAPP_APP_NAME_DEFAULT "BitcoinHD Chain"             //! Legacy name
#define QAPP_APP_NAME_TESTNET "BitcoinHD Chain [testnet]"   //! Legacy name
#define QAPP_APP_NAME_REGTEST "BitcoinHD Chain [regtest]"   //! Legacy name

/* One gigabyte (GB) in bytes */
static constexpr uint64_t GB_BYTES{1000000000};

#endif // BITCOIN_QT_GUICONSTANTS_H
