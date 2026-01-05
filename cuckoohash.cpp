// main.cpp
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <openssl/md5.h>

class CuckooHashSender {
public:
    CuckooHashSender(const std::vector<long long>& X, int alpha, double epsilon = 0.27, int max_attempts = 100)
        : X_(X), n_(static_cast<int>(X.size())), epsilon_(epsilon), alpha_(alpha), max_attempts_(max_attempts)
    {
        m_ = static_cast<int>(std::ceil((1.0 + epsilon_) * n_));
        if (m_ <= 0) m_ = 1; // 避免空集导致除零
        TX_.assign(m_, kEmpty);
    }

    // 执行插入与置换过程
    std::vector<long long> execute() {
        std::cout << m_ << std::endl; // 与 Python 版保持一致：打印 m
        for (auto x : X_) {
            if (!insert_to_table(x)) {
                std::cerr << "无法完成所有元素的插入。请考虑增加哈希表大小或调整参数。" << std::endl;
                break;
            }
        }
        return TX_;
    }

private:
    static constexpr long long kEmpty = LLONG_MIN;

    // 与 Python: hashlib.md5(f"{x}-{i}").hexdigest() 的等价实现
    // 取 MD5( x-i ) 的前 8 字节转为 64 位整数，再对 m 取模
    int hash_function(long long x, int i) const {
        std::string s = std::to_string(x) + "-" + std::to_string(i);
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);

        // 将前 8 字节拼成一个无符号 64 位数（大端/小端都可，只要一致即可）
        uint64_t val = 0;
        for (int k = 0; k < 8; ++k) {
            val = (val << 8) | static_cast<uint64_t>(digest[k]);
        }
        return static_cast<int>(val % static_cast<uint64_t>(m_));
    }

    // Python 的 combine：把 x 与 i 的十进制字符串直接拼接，再转整数
    long long combine(long long x, int i) const {
        std::string s = std::to_string(x) + std::to_string(i);
        // 注意：若拼接后超过 long long 范围会溢出；与 Python 一样，这里假定 x 与 i 规模适中
        return std::stoll(s);
    }

    // Python 的 extract_original_element：去除末尾 i 的十进制位数
    long long extract_original_element(long long combined_value, int i) const {
        std::string cs = std::to_string(combined_value);
        std::string is = std::to_string(i);
        if (cs.size() < is.size()) {
            // 防御：不应该发生，返回原值
            return combined_value;
        }
        std::string x_str = cs.substr(0, cs.size() - is.size());
        if (x_str.empty()) return 0;
        return std::stoll(x_str);
    }

    bool insert_to_table(long long x) {
        bool inserted = false;
        int attempt = 0;

        while (!inserted) {
            if (attempt >= max_attempts_) {
                std::cerr << "插入失败：在插入元素 " << x << " 时超过最大尝试次数 "
                          << max_attempts_ << "。" << std::endl;
                return false;
            }

            int j = (attempt % alpha_) + 1; // 1..alpha 循环
            int h_j = hash_function(x, j);

            if (TX_[h_j] == kEmpty) {
                long long combined_value = combine(x, j);
                TX_[h_j] = combined_value;
                inserted = true;
            } else {
                long long x_prime = extract_original_element(TX_[h_j], j);
                TX_[h_j] = combine(x, j);
                x = x_prime; // 被踢出的元素继续插入下一轮
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

// 简单 CSV 第一列读取
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
            try {
                long long val = std::stoll(first);
                X.push_back(val);
            } catch (...) {
                // 忽略无法解析为整数的行
            }
        }
    }
    return X;
}

void write_vector_to_csv(const std::string& filename, const std::vector<long long>& vec) {
    std::ofstream fout(filename);
    if (!fout.is_open()) {
        std::cerr << "无法写入文件: " << filename << std::endl;
        return;
    }
    for (auto v : vec) {
        if (v == LLONG_MIN) {
            fout << "" << "\n"; // Python 里写出 None；这里写空单元
        } else {
            fout << v << "\n";
        }
    }
}

int main() {
    // 读取 sender.csv 第一列为 X
    std::vector<long long> X = read_first_col_csv("sender.csv");

    int alpha = 3;         // 哈希函数数量
    double epsilon = 0.27; // 与 Python 一致
    int max_attempts = 100;

    CuckooHashSender sender(X, alpha, epsilon, max_attempts);
    std::vector<long long> TX = sender.execute();

    write_vector_to_csv("TX_output.csv", TX);
    std::cout << "TX 列表已写入 TX_output.csv 文件。" << std::endl;

    return 0;
}

