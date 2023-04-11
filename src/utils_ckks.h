#ifndef __UTILS_CKKS
#define __UTILS_CKKS

#include "openfhe.h"

#include<vector>


using namespace lbcrypto;

void print_moduli_chain(const PublicKey<DCRTPoly>& ckks_pub_key);


CCParams<CryptoContextCKKSRNS> generate_parameters_ckks(int n_time_slots);



CryptoContext<DCRTPoly> generate_crypto_context_ckks(CCParams<CryptoContextCKKSRNS>& parameters);


Ciphertext<DCRTPoly> pack_and_encrypt(
										const std::vector<double>& msg,
										CryptoContext<DCRTPoly>& cc,
										const PublicKey<DCRTPoly>& ckks_pk
									 );
Ciphertext<DCRTPoly> pack_and_add(
										const Ciphertext<DCRTPoly>& ctxt,
										const std::vector<double>& msg,
										CryptoContext<DCRTPoly>& cc
									 );

Ciphertext<DCRTPoly> pack_and_mult(
										const Ciphertext<DCRTPoly>& ctxt,
										const std::vector<double>& msg,
										CryptoContext<DCRTPoly>& cc
									 );

Ciphertext<DCRTPoly> negate_all_slots(
										const Ciphertext<DCRTPoly>& ctxt,
										CryptoContext<DCRTPoly>& cc
									 );


#endif
