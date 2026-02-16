// Minimal stdin/stdout bridge to run script verification against current
// Bitcoin Core C++ internals (v28+ where libbitcoinconsensus was removed).

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace {

class TxInputStream
{
public:
    TxInputStream(const unsigned char* tx, size_t tx_len) : m_data(tx), m_remaining(tx_len) {}

    void read(std::span<std::byte> dst)
    {
        if (dst.size() > m_remaining) {
            throw std::ios_base::failure("tx stream: end of data");
        }
        if (dst.data() == nullptr || m_data == nullptr) {
            throw std::ios_base::failure("tx stream: null buffer");
        }
        std::memcpy(dst.data(), m_data, dst.size());
        m_remaining -= dst.size();
        m_data += dst.size();
    }

    template <typename T>
    TxInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

private:
    const unsigned char* m_data;
    size_t m_remaining;
};

std::vector<std::string> Split(const std::string& in, char delim)
{
    std::vector<std::string> out;
    std::string cur;
    std::istringstream stream(in);
    while (std::getline(stream, cur, delim)) out.push_back(cur);
    if (!in.empty() && in.back() == delim) out.emplace_back();
    return out;
}

int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool ParseHex(const std::string& hex, std::vector<unsigned char>& out)
{
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = HexNibble(hex[i]);
        const int lo = HexNibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

template <typename T>
std::optional<T> ParseIntegral(const std::string& s)
{
    if (s.empty()) return std::nullopt;
    std::istringstream is{s};
    T out{};
    is >> out;
    if (!is || !is.eof()) return std::nullopt;
    return out;
}

std::string HandleRequest(const std::string& line)
{
    if (line == "META") {
#ifdef NDEBUG
        constexpr bool kAssertsEnabled = false;
#else
        constexpr bool kAssertsEnabled = true;
#endif
        return std::string("META|asserts=") + (kAssertsEnabled ? "1" : "0");
    }

    // Request line format:
    // flags|input_index|amount_sat|script_pubkey_hex|tx_hex|spent_count|spent_outputs
    // spent_outputs format:
    // value:script_hex,value:script_hex,...
    const auto fields = Split(line, '|');
    if (fields.size() != 7) {
        return "ERR|bad_request_field_count";
    }

    const auto flags_opt = ParseIntegral<uint32_t>(fields[0]);
    const auto input_index_opt = ParseIntegral<uint32_t>(fields[1]);
    const auto amount_opt = ParseIntegral<int64_t>(fields[2]);
    const auto spent_count_opt = ParseIntegral<uint32_t>(fields[5]);
    if (!flags_opt || !input_index_opt || !amount_opt || !spent_count_opt) {
        return "ERR|bad_numeric_field";
    }
    const uint32_t flags = *flags_opt;
    const uint32_t input_index = *input_index_opt;
    const CAmount amount = *amount_opt;
    const uint32_t spent_count = *spent_count_opt;

    std::vector<unsigned char> script_pubkey_bytes;
    if (!ParseHex(fields[3], script_pubkey_bytes)) {
        return "ERR|bad_script_pubkey_hex";
    }
    const CScript script_pubkey(script_pubkey_bytes.begin(), script_pubkey_bytes.end());

    std::vector<unsigned char> tx_bytes;
    if (!ParseHex(fields[4], tx_bytes)) {
        return "ERR|bad_tx_hex";
    }

    const CTransaction tx = [&tx_bytes]() -> CTransaction {
        TxInputStream stream(tx_bytes.data(), tx_bytes.size());
        return CTransaction(deserialize, TX_WITH_WITNESS, stream);
    }();
    if (GetSerializeSize(TX_WITH_WITNESS(tx)) != tx_bytes.size()) {
        return "ERR|tx_size_mismatch";
    }

    if (input_index >= tx.vin.size()) {
        return "ERR|tx_index";
    }

    std::vector<CTxOut> spent_outputs;
    if (spent_count > 0) {
        const auto items = fields[6].empty() ? std::vector<std::string>{} : Split(fields[6], ',');
        if (items.size() != spent_count) {
            return "ERR|spent_count_mismatch";
        }
        spent_outputs.reserve(spent_count);
        for (const auto& item : items) {
            const auto colon = item.find(':');
            if (colon == std::string::npos || colon == 0 || colon + 1 >= item.size()) {
                return "ERR|bad_spent_entry";
            }
            const auto value_opt = ParseIntegral<int64_t>(item.substr(0, colon));
            if (!value_opt) {
                return "ERR|bad_spent_value";
            }
            std::vector<unsigned char> spk;
            if (!ParseHex(item.substr(colon + 1), spk)) {
                return "ERR|bad_spent_script_hex";
            }
            spent_outputs.emplace_back(*value_opt, CScript(spk.begin(), spk.end()));
        }
    } else if (!fields[6].empty()) {
        return "ERR|unexpected_spent_payload";
    }

    ScriptError script_error = SCRIPT_ERR_UNKNOWN_ERROR;
    PrecomputedTransactionData txdata(tx);
    if (!spent_outputs.empty()) {
        if (spent_outputs.size() != tx.vin.size()) {
            return "ERR|spent_count_mismatch";
        }
        txdata.Init(tx, std::move(spent_outputs));
    }

    const bool ok = VerifyScript(
        tx.vin[input_index].scriptSig,
        script_pubkey,
        &tx.vin[input_index].scriptWitness,
        flags,
        TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
        &script_error
    );

    return std::string("OK|") + (ok ? "1|" : "0|") + std::to_string(static_cast<int>(script_error));
}

} // namespace

int main()
{
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        try {
            std::cout << HandleRequest(line) << '\n';
        } catch (const std::exception& e) {
            std::cout << "ERR|exception:" << e.what() << '\n';
        }
        std::cout.flush();
    }
    return 0;
}
