#include "back_end.hpp"
#include "endian.hpp"

using namespace std;

namespace Vlinder {
namespace JOSE {
namespace Private {

vector<unsigned char> BackEnd::concatKDF(vector<unsigned char> const& shared_secret /* Z in the spec */,
                                         size_t key_data_len,
                                         string const& algorithm,
                                         vector<unsigned char> const& apu,
                                         vector<unsigned char> const& apv)
{
    // build AlgorithmID
    union {
        uint32_t value;
        unsigned char bytes[4];
    } alg_len_be;
    alg_len_be.value = toBigEndian(static_cast<uint32_t>(algorithm.length()));
    vector< unsigned char > algorithm_id;
    algorithm_id.insert(algorithm_id.end(), reinterpret_cast<unsigned char const*>(&alg_len_be),
                        reinterpret_cast<unsigned char const*>(&alg_len_be) + sizeof(uint32_t));
    algorithm_id.insert(algorithm_id.end(), algorithm.begin(), algorithm.end());

    // build PartyUInfo
    union {
        uint32_t value;
        unsigned char bytes[4];
    } apu_len_be;
    apu_len_be.value = toBigEndian(static_cast<uint32_t>(apu.size()));
    vector<unsigned char> party_u_info;
    party_u_info.insert(party_u_info.end(), reinterpret_cast<unsigned char const*>(&apu_len_be),
                        reinterpret_cast<unsigned char const*>(&apu_len_be) + sizeof(uint32_t));
    party_u_info.insert(party_u_info.end(), apu.begin(), apu.end());

    // build PartyVInfo
    union {
        uint32_t value;
        unsigned char bytes[4];
    } apv_len_be;
    apv_len_be.value = toBigEndian(static_cast<uint32_t>(apv.size()));
    vector<unsigned char> party_v_info;
    party_v_info.insert(party_v_info.end(), reinterpret_cast<unsigned char const*>(&apv_len_be),
                        reinterpret_cast<unsigned char const*>(&apv_len_be) + sizeof(uint32_t));
    party_v_info.insert(party_v_info.end(), apv.begin(), apv.end());

    // build SuppPubInfo
    union
    {
        uint32_t value;
        unsigned char bytes[4];
    } supp_pub_info_be;
    supp_pub_info_be.value = toBigEndian(static_cast<uint32_t>(key_data_len * 8));

    // build SuppPrivInfo (empty in our case)
    vector<unsigned char> supp_priv_info;

    // Concatenate all the components to form OtherInfo
    vector<unsigned char> other_info;
    other_info.insert(other_info.end(), algorithm_id.begin(), algorithm_id.end());
    other_info.insert(other_info.end(), party_u_info.begin(), party_u_info.end());
    other_info.insert(other_info.end(), party_v_info.begin(), party_v_info.end());
    other_info.insert(other_info.end(), supp_pub_info_be.bytes, supp_pub_info_be.bytes + sizeof(uint32_t));
    other_info.insert(other_info.end(), supp_priv_info.begin(), supp_priv_info.end());

    // Perform the KDF rounds
    vector<unsigned char> derived_key;
    size_t hash_len = 32;  // SHA-256 output size
    size_t reps = (key_data_len + hash_len - 1) / hash_len;
    for (size_t i = 1; i <= reps; ++i)  // 1-based round counter
    {
        vector<unsigned char> round_data;
        union {
            uint32_t value;
            unsigned char bytes[4];
        } round_be;
        round_be.value = toBigEndian(static_cast<uint32_t>(i));
        round_data.insert(round_data.end(), round_be.bytes, round_be.bytes + sizeof(uint32_t));
        round_data.insert(round_data.end(), shared_secret.begin(), shared_secret.end());
        round_data.insert(round_data.end(), other_info.begin(), other_info.end());
        vector<unsigned char> hash = this->hash(HashAlgorithm::sha256, round_data);
        derived_key.insert(derived_key.end(), hash.begin(), hash.end());
    }
    derived_key.resize(key_data_len);
    return derived_key;
}

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
