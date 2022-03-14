#include <iostream>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unordered_map>
#include <array>

#include <iterator>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>

extern "C" {
    #include "ecelgamal.h"
}

using namespace std::chrono;

typedef struct {
    std::string country;
    std::string death;
    dig_t pdeath;
	//gamal_key_t k_i;
	//gamal_ciphertext_t c_i;
    unsigned char * keybyte;
    unsigned char * ciphertext;
} UNC;

typedef struct {
    std::string country;
    gamal_key_t k_i;
} UNK;

const int cnt = 60000;


class CSVRow
{
    public:
        std::string_view operator[](std::size_t index) const
        {
            return std::string_view(&m_line[m_data[index] + 1], m_data[index + 1] -  (m_data[index] + 1));
        }
        std::size_t size() const
        {
            return m_data.size() - 1;
        }
        void readNextRow(std::istream& str)
        {
            std::getline(str, m_line);

            m_data.clear();
            m_data.emplace_back(-1);
            std::string::size_type pos = 0;
            while((pos = m_line.find(',', pos)) != std::string::npos)
            {
                m_data.emplace_back(pos);
                ++pos;
            }
            // This checks for a trailing comma with no data after it.
            pos   = m_line.size();
            m_data.emplace_back(pos);
        }
    private:
        std::string         m_line;
        std::vector<int>    m_data;
};

std::istream& operator>>(std::istream& str, CSVRow& data)
{
    data.readNextRow(str);
    return str;
}   


static void addCiphertexts(UNC values[]){
    gamal_ciphertext_t C_T, C1, C2;
    dig_t plainSum;

    gamal_cipher_new(C_T);

    plainSum = values[0].pdeath + values[1].pdeath;
    //std::cout << "Plaintext Deaths =  " << plainSum << "\n";

    decode_ciphertext(C1, values[0].ciphertext, 1000000);
    decode_ciphertext(C2, values[1].ciphertext, 1000000);
   
    gamal_add(C_T, C1, C2);

    
    for (int i = 2; i < cnt; i++){
        gamal_ciphertext_t C_I;
        decode_ciphertext(C_I, values[i].ciphertext, 1000000);
        gamal_add(C_T, C_T, C_I);
        plainSum = plainSum + values[i].pdeath;
        //gamal_cipher_clear(C_I);
    }

    std::cout << "Ciphertext Addition Completed \n";
    std::cout << "Sum of Plaintext Deaths =  " << plainSum << "\n";

    gamal_cipher_clear(C_T);
    gamal_cipher_clear(C1);
    gamal_cipher_clear(C2);
}


static void addKeys(UNC values[]){
    gamal_key_t K_T, K1, K2;
    size_t size = 66;

    gamal_key_new(K_T);

    decode_key(K1, values[0].keybyte, size);
    decode_key(K2, values[1].keybyte, size);

    gamal_plm_addkey(K_T, K1, K2);

    for (int i = 2; i < cnt; i++){
        gamal_key_t K_I;
        decode_key(K_I, values[i].keybyte, size);
        gamal_plm_addkey(K_T, K_T, K_I);
    }

    std::cout << "Key Addition Completed for " << cnt << " keys \n";
    gamal_key_clear(K_T);
    gamal_key_clear(K1);
    gamal_key_clear(K2);
}


int main() {
	//bsgs_table_t table;


    high_resolution_clock::time_point p1, p2, k1, k2, c1, c2;
    //double par_time, keyadd_time, cip_time;

    gamal_init(CURVE_256_SEC);


	std::cout << OPENSSL_VERSION_TEXT << std::endl;
    std::cout << "PLM Experiments with an Additive EC-ElGamal with 32-bit integers\n" << std::endl;

    std::ifstream       file("data.csv");
    std::unordered_map<std::string, gamal_key_t> unique_key_table;
    //std::array<UNC, cnt> test1;
    UNC test1[cnt];
    //std::array<UNK, 50> test2;

    int index1 = 0;
    //int index2 = 0;

    p1 = high_resolution_clock::now();
    CSVRow              row;
    while(file >> row)
    {
        //std::cout << row[0] << " " << row[1] << " " << row[2] << " " << row[3] << " " << row[4] << " " << row[5] << " " << row[6] << " " << row[7] << "\n";
        gamal_key_t K1;
        gamal_ciphertext_t C1;

        if (index1 < cnt) {
            test1[index1].country = row[6];
            test1[index1].death = row[5];

            gamal_generate_keys(K1);

            //Convert key to a byte and store in array
            size_t size = get_encoded_key_size(K1, 0);
            test1[index1].keybyte = (unsigned char *) malloc(size);
            encode_key(test1[index1].keybyte, size, K1, 0);

            std::istringstream iss(test1[index1].death);
            iss >> test1[index1].pdeath;
            //std::cout << "Death as a uint64_t = " << test1[index1].pdeath << "\n";

            gamal_encrypt(C1, K1, test1[index1].pdeath);
            //Convert the ciphertext sum to a byte
            test1[index1].ciphertext = (unsigned char *) malloc(get_encoded_ciphertext_size(C1));
            encode_ciphertext(test1[index1].ciphertext, 100000, C1);
        }

    
        index1++;
    }

    p2 = high_resolution_clock::now();
    auto par_time = duration_cast<nanoseconds>(p2-p1).count();

    c1 = high_resolution_clock::now();
    addCiphertexts(test1);
    c2 = high_resolution_clock::now();
    auto cip_time = duration_cast<nanoseconds>(c2-c1).count();
    
    k1 = high_resolution_clock::now();
    addKeys(test1);
    k2 = high_resolution_clock::now();
    auto keyadd_time = duration_cast<nanoseconds>(k2-k1).count();


    std::cout << "Total Parse and Encrypt Time for " << cnt << " rows of Data = " <<  par_time / 1000000.0 << " ms" << std::endl;
    std::cout << "Ciphertext Addition Function took  " <<  cip_time / 1000000.0 << " ms" << std::endl;
    std::cout << "Functional Key Generation took " <<  keyadd_time / 1000000.0 << " ms" << std::endl;

    gamal_deinit();
    return 0;
}