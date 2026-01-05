#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cmath>
#include <limits>
#include <iomanip>

// ====== cryptoTools / libOTe (OKVS) ======
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Block.h>

#include <libOTe/Tools/LDPC/Util.h>   // PaxosParam
#include "Paxos.h"
#include "PaxosImpl.h"

// ====== 外部依赖（可选）用于 MD5，与 Python hashlib.md5 一致 ======
#include <openssl/md5.h>

// ====== 命名空间 ======
using namespace oc;          // oc::block, PRNG, Timer, CLP …
using namespace osuCrypto;   // 兼容早期命名
using namespace std;

//---------------------------------------------
// 工具：字符串MD5 -> 64位
//---------------------------------------------
static inline uint64_t md5mod64(const std::string& s) {
    unsigned char d[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(s.data()), s.size(), d);
    uint64_t v = 0;
    for (int k = 0; k < 8; ++k) v = (v << 8) | static_cast<uint64_t>(d[k]);
    return v;
}

//---------------------------------------------
// CuckooHashSender（与 Python 逻辑对齐）
//---------------------------------------------
class CuckooHashSender {
public:
    CuckooHashSender(const std::vector<long long>& X, int alpha, double epsilon = 0.27, int max_attempts = 100)
        : X_(X), n_(static_cast<int>(X.size())), epsilon_(epsilon), alpha_(alpha), max_attempts_(max_attempts)
    {
        m_ = static_cast<int>(std::ceil((1.0 + epsilon_) * n_));
        if (m_ <= 0) m_ = 1;
        TX_.assign(m_, kEmpty);
    }

    std::vector<long long> execute() {
        std::cout << m_ << std::endl; // 与 Python 版保持一致输出 m
        for (auto x : X_) {
            if (!insert_to_table(x)) {
                std::cerr << "无法完成所有元素的插入。请考虑增加哈希表大小或调整参数。" << std::endl;
                break;
            }
        }
        return TX_;
    }

    const std::vector<long long>& table() const { return TX_; }
    int m() const { return m_; }

private:
    static constexpr long long kEmpty = std::numeric_limits<long long>::min();

    int hash_function(long long x, int i) const {
        std::string s = std::to_string(x) + "-" + std::to_string(i);
        // 与 Python hashlib.md5 对齐
        uint64_t hv = md5mod64(s);
        return static_cast<int>(hv % static_cast<uint64_t>(m_));
    }
    long long combine(long long x, int i) const {
        // 十进制拼接，注意潜在溢出风险（与 Python 行为一致）
        std::string s = std::to_string(x) + std::to_string(i);
        return std::stoll(s);
    }
    long long extract_original_element(long long combined_value, int i) const {
        std::string cs = std::to_string(combined_value);
        std::string is = std::to_string(i);
        if (cs.size() < is.size()) return combined_value;
        std::string x_str = cs.substr(0, cs.size() - is.size());
        if (x_str.empty()) return 0;
        return std::stoll(x_str);
    }

    bool insert_to_table(long long x) {
        bool inserted = false;
        int attempt = 0;
        while (!inserted) {
            if (attempt >= max_attempts_) {
                std::cerr << "插入失败：在插入元素 " << x
                          << " 时超过最大尝试次数 " << max_attempts_ << "。" << std::endl;
                return false;
            }
            int j = (attempt % alpha_) + 1; // 1..alpha
            int h_j = hash_function(x, j);
            if (TX_[h_j] == kEmpty) {
                TX_[h_j] = combine(x, j);
                inserted = true;
            } else {
                long long x_prime = extract_original_element(TX_[h_j], j);
                TX_[h_j] = combine(x, j);
                x = x_prime; // 踢出继续
            }
            ++attempt;
        }
        return true;
    }

private:
    std::vector<long long> X_;
    int n_;
    double epsilon_;
    int m_;
    int alpha_;
    int max_attempts_;
    std::vector<long long> TX_;
};

//---------------------------------------------
// CSV 读/写
//---------------------------------------------
std::vector<long long> read_first_col_csv(const std::string& filename) {
    std::vector<long long> X;
    std::ifstream fin(filename);
    if (!fin.is_open()) {
        std::cerr << "无法打开文件: " << filename << std::endl;
        return X;
    }
    std::string line;
    while (std::getline(fin, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string first;
        if (std::getline(ss, first, ',')) {
            try { X.push_back(std::stoll(first)); } catch (...) {}
        }
    }
    return X;
}

void write_vector_to_csv(const std::string& filename, const std::vector<long long>& vec, long long empty_sentinel) {
    std::ofstream fout(filename);
    if (!fout.is_open()) {
        std::cerr << "无法写入文件: " << filename << std::endl;
        return;
    }
    for (auto v : vec) {
        if (v == empty_sentinel) fout << "" << "\n";
        else fout << v << "\n";
    }
}

//---------------------------------------------
// 把 long long 打包成 oc::block（低64位放数据，高64位放 0）
//---------------------------------------------
static inline block pack_ll_to_block(long long v) {
    return toBlock(static_cast<u64>(0), static_cast<u64>(v));
}
static inline long long unpack_block_to_ll(const block& b) {
    // 取低 64 位
    return static_cast<long long>(b.get<u64>(1));
}

//---------------------------------------------
// 用 Baxos（OKVS）对 (key,value) 做 solve/encode + decode
// keys/vals 都用 block 表示
//---------------------------------------------
void run_okvs_with_baxos(const std::vector<block>& keys,
                         const std::vector<block>& vals,
                         u64 w = 3, u64 ssp = 40,
                         PaxosParam::DataType dt = PaxosParam::GF128,
                         u64 binSize = (1u << 15))
{
    if (keys.size() != vals.size()) {
        std::cerr << "keys.size() != vals.size()" << std::endl;
        return;
    }
    const u64 n = static_cast<u64>(keys.size());
    if (n == 0) {
        std::cout << "OKVS: 空输入，跳过。" << std::endl;
        return;
    }

    // 初始化 Baxos，确定表大小
    u64 baxosSize;
    {
        Baxos paxos;
        paxos.init(n, binSize, w, ssp, dt, ZeroBlock);
        baxosSize = paxos.size(); // OKVS 存储大小
    }

    std::vector<block> pax(baxosSize);           // OKVS 编码表
    std::vector<block> rec_val(vals.size());     // 解码出来的 value

    Timer timer;
    auto start = timer.setTimePoint("start");

    {
        Baxos paxos;
        paxos.init(n, binSize, w, ssp, dt, ZeroBlock);
        // 直接 solve（一次把 keys/vals 编到 pax）
        paxos.solve<block>(const_cast<std::vector<block>&>(keys),
                           const_cast<std::vector<block>&>(vals),
                           pax, nullptr, 0);
        timer.setTimePoint("solve");

        // 再根据 key 从 pax 解码出 val
        paxos.decode<block>(const_cast<std::vector<block>&>(keys),
                            rec_val,
                            pax, 0);
        timer.setTimePoint("decode");
    }

    auto end = timer.setTimePoint("end");
    if (true) std::cout << timer << std::endl;

    // 校验
    size_t ok = 0;
    for (size_t i = 0; i < vals.size(); ++i) {
        if (rec_val[i] == vals[i]) ++ok;
    }
    auto ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);
    std::cout << "[OKVS] n=" << n
              << "  table_e=" << (double)baxosSize / (double)n
              << "  time=" << ms << "ms  correct=" << ok << "/" << n << std::endl;
}

//---------------------------------------------
// 你代码里的测试：修复了循环变量 bug
//---------------------------------------------
void testAdd_fixed(oc::CLP& cmd)
{
    auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    auto t = cmd.getOr("t", 1ull);
    std::vector<block> key(n), key1(n);
    std::cout << "Size of block: " << sizeof(block) << " bytes" << std::endl;
    PRNG prng(ZeroBlock);
    prng.get<block>(key);
    prng.get<block>(key1);
    Timer timer;
    auto start = timer.setTimePoint("start");
    auto end = start;
    for (u64 i = 0; i < t; ++i){
        for (u64 j = 0; j < n; ++j){ // 修复：这里应当用 j
            key[j] = key[j] + key1[j];
        }
        end = timer.setTimePoint("d" + std::to_string(i));
    }
    auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);
    std::cout << "total " << tt << "ms"<< std::endl;
}

//---------------------------------------------
// 主流程
//---------------------------------------------
int main(int argc, char** argv){
    CLP cmd; cmd.parse(argc, argv);

    // 1) 从 sender.csv 读取第一列为 X
    std::vector<long long> X = read_first_col_csv("sender.csv");

    // 2) 生成布谷鸟表 TX（Python 逻辑等价）
    int alpha = 3;         // 哈希函数数量
    double epsilon = 0.27; // 与 Python 一致
    int max_attempts = 100;

    CuckooHashSender sender(X, alpha, epsilon, max_attempts);
    std::vector<long long> TX = sender.execute();
    write_vector_to_csv("TX_output.csv", TX, std::numeric_limits<long long>::min());
    std::cout << "TX 列表已写入 TX_output.csv 文件。" << std::endl;

    // 3) 构造 OKVS (key,value)：
    //    这里示例用 “桶下标 -> 桶内值” 作为 (key,value)。
    //    key/value 都封装成 block 以便 Baxos 处理。
    std::vector<block> okvsKeys;
    std::vector<block> okvsVals;
    okvsKeys.reserve(TX.size());
    okvsVals.reserve(TX.size());
    for (int i = 0; i < (int)TX.size(); ++i) {
        if (TX[i] == std::numeric_limits<long long>::min()) continue; // 空桶跳过
        // key：你也可以换成元素哈希，示例用桶下标
        okvsKeys.push_back(pack_ll_to_block(i));
        okvsVals.push_back(pack_ll_to_block(TX[i]));
    }

    // 4) 用 Baxos 进行 OKVS 编码与解码校验
    //    参数可按需调整：w(稀疏度), ssp(安全参数), dt(GF128/Binary), binSize(桶大小)
    run_okvs_with_baxos(okvsKeys, okvsVals,
                        /*w=*/3, /*ssp=*/40,
                        PaxosParam::GF128,
                        /*binSize=*/(1u<<15));

    // 5) 你原文件里的性能小测试（修复版）
    // testAdd_fixed(cmd);

    return 0;
}

