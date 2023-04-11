
#include "utils_ckks.h"
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

void print_moduli_chain(const PublicKey<DCRTPoly>& ckks_pub_key){

    const std::vector<DCRTPoly>& ckks_pk = ckks_pub_key->GetPublicElements();
	const DCRTPoly& poly = ckks_pk[0];

    int num_primes = poly.GetNumOfElements();
    double total_bit_len = 0.0;
    for (int i = 0; i < num_primes; i++) {
        auto qi = poly.GetParams()->GetParams()[i]->GetModulus();
        std::cout << "q_" << i << ": " 
                    << qi
                    << ",  log q_" << i <<": " << log(qi.ConvertToDouble()) / log(2)
                    << std::endl;
        total_bit_len += log(qi.ConvertToDouble()) / log(2);
    }
    std::cout << "Total bit length: " << total_bit_len << std::endl;
}

CCParams<CryptoContextCKKSRNS> generate_parameters_ckks(int n_time_slots){
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 55;
    usint firstMod               = 59; // defines CKKS precision

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY; 
    parameters.SetSecretKeyDist(secretKeyDist);

    parameters.SetRingDim(1 << 16); // sets the degree of the polynomials used in the FHE scheme as 2^14
    parameters.SetSecurityLevel(HEStd_128_classic); // 128 bits of security

    parameters.SetBatchSize(n_time_slots); // number of slots we'll use in CKKS plaintext

    parameters.SetNumLargeDigits(4);
    parameters.SetKeySwitchTechnique(HYBRID);

    std::vector<uint32_t> levelBudget = {3, 2};
    std::cout << "levelBudget = " << levelBudget << std::endl;

    // We approximate the number of levels bootstrapping will consume to help set our initial multiplicative depth.
    uint32_t approxBootstrapDepth = 7;
    std::cout << "approxBootstrapDepth = " << approxBootstrapDepth << std::endl;

    std::vector<uint32_t> bsgsDim = {0, 0};

    uint32_t levelsUsedBeforeBootstrap = 6;
    std::cout << "levelsUsedBeforeBootstrap = " << levelsUsedBeforeBootstrap << std::endl;
    usint depth =
        levelsUsedBeforeBootstrap + FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, levelBudget, secretKeyDist);
    std::cout << "depth = " << depth << std::endl;
    parameters.SetMultiplicativeDepth(depth);

	return parameters;
}


CryptoContext<DCRTPoly> generate_crypto_context_ckks(CCParams<CryptoContextCKKSRNS>& parameters){
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

	return cc;
}

Ciphertext<DCRTPoly> pack_and_encrypt(
										const vector<double>& msg,
										CryptoContext<DCRTPoly>& cc,
										const PublicKey<DCRTPoly>& ckks_pk
									 )
{
    Plaintext ptxt_msg = cc->MakeCKKSPackedPlaintext(msg); // pack
    Ciphertext<DCRTPoly> ctxt = cc->Encrypt(ckks_pk, ptxt_msg); // encrypt
	return ctxt;
}

Ciphertext<DCRTPoly> pack_and_mult(
										const Ciphertext<DCRTPoly>& ctxt,
										const vector<double>& msg,
										CryptoContext<DCRTPoly>& cc
									 )
{
    Plaintext ptxt_msg = cc->MakeCKKSPackedPlaintext(msg); // pack
	return cc->EvalMult(ctxt, ptxt_msg);
}

Ciphertext<DCRTPoly> pack_and_add(
										const Ciphertext<DCRTPoly>& ctxt,
										const std::vector<double>& msg,
										CryptoContext<DCRTPoly>& cc
									 )
{
    Plaintext ptxt_msg = cc->MakeCKKSPackedPlaintext(msg); // pack
	return cc->EvalAdd(ctxt, ptxt_msg);
}


Ciphertext<DCRTPoly> negate_all_slots(
										const Ciphertext<DCRTPoly>& ctxt,
										CryptoContext<DCRTPoly>& cc
									 ){

    unsigned int n_slots = cc->GetEncodingParams()->GetBatchSize();
	vector<double> ones(n_slots, 1.0);
    Plaintext ptxt_ones = cc->MakeCKKSPackedPlaintext(ones); // pack

	return cc->EvalSub(ptxt_ones, ctxt);
}

