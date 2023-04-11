#include <time.h>
#include <stdlib.h>
#include <cassert>

#include "utils_ckks.h"
#include "vectorutils.hpp"

using namespace lbcrypto;
using namespace std;



/**
 *	Simulates the smart metter measuring the client's consumption in a time slot.
 *	Just returns a random "real" number between 0 and 10 with 2 decimal digits
 */
double measure_consumption(){
	return 0.01 * (rand() % 1000);
}

/**
 *	Simulates the smart metter measuring the client's supply a time slot.
 *	Just returns a random "real" number between 0 and 10 with 2 decimal digits
 */
double measure_supply(){
	return 0.01 * (rand() % 1000);
}


/**
 *		Simulates the process where the client estimate how much they will consume 
 *	or supply for each time slot (which is sent to the P2P market in order to
 *	match consumers to prosumers).
 *
 *		At the end of the execution, we have
 *			is_consumer[i] = 1 if client is a consumer in the i-th time slot, and 0 otherwise
 *			offer[i] is the promised value to be consumed in the i-th time slot if
 *			     is_consumer[i] == 1 and the promised value to be supplied if is_consumer[i] == 0
 *
 **/
void client_auction(std::vector<int>& is_consumer, std::vector<double>& offer, int n_time_slots) {
	
	offer.resize(n_time_slots);
	is_consumer.resize(n_time_slots);

	for (int i = 0; i < n_time_slots; i++){
		is_consumer[i] = rand() % 2; // XXX: for now, just decide at random if it is a consumer or not
		offer[i] = 0.01 * (rand() % 1000); // XXX: for now, just make a random offer
	}
}

/**
 * 	Definition of function client_setup:
 *
 *	Returns a tuple with ciphertexts encrypting the consumptions, the supplies,
 *	the deviations, and the signs of the deviations (marking negative or positive)
 */
std::tuple< Ciphertext<DCRTPoly>,
			Ciphertext<DCRTPoly>,
			Ciphertext<DCRTPoly>,
			Ciphertext<DCRTPoly>
		  >
			client_setup(  
									const std::vector<int>& is_consumer, // one if consumer, 0 if prosumer
									const std::vector<double>& promise, // promised consumption/supply in each time slot
									CryptoContext<DCRTPoly>& cc,
									const PublicKey<DCRTPoly>& ckks_pk
								 )
{

	int n_time_slots = promise.size();

	int N = cc->GetRingDimension();
	assert(n_time_slots <= N/2);  // we can pack up to N/2 values into one ciphertext

	vector<double> consumptions(n_time_slots);
	vector<double> supplies(n_time_slots);
	vector<double> deviations(n_time_slots);
	vector<double> sign_deviations(n_time_slots);


	for(int i = 0; i < n_time_slots; i++){
		consumptions[i] = measure_consumption();
		supplies[i] = measure_supply();
		if (1 == is_consumer[i]){ // client is a consumer in this time slot
			deviations[i] = promise[i] - consumptions[i];
		}else {  // client is a prosumer (supplier) in this time slot
			deviations[i] = promise[i] - supplies[i];
		}
		if (deviations[i] <= 0)
			sign_deviations[i] = 1;
		else
			sign_deviations[i] = 0;
	}

    Ciphertext<DCRTPoly> ct_consump = pack_and_encrypt(consumptions, cc, ckks_pk);
    Ciphertext<DCRTPoly> ct_supplies = pack_and_encrypt(supplies, cc, ckks_pk);
    Ciphertext<DCRTPoly> ct_deviations = pack_and_encrypt(deviations, cc, ckks_pk);
    Ciphertext<DCRTPoly> ct_signs = pack_and_encrypt(sign_deviations, cc, ckks_pk);

	return {ct_consump, ct_supplies, ct_deviations, ct_signs};
}
/* 	END definition of function client_setup  */





/**
 * 	Definition of function server_billing:
 *
 *  Receives 
 *  	the ciphertexts produced by client_setup,
 *  	a vector with the total deviation in clear,
 *  	a vector with the trading price of each time slot (in clear),
 *  	a vector with the retail price of each time slot (in clear),
 *  	a vector with the feed-in tariff of each time slot (in clear),
 *		the cryptographic context,
 *		the public key
 *
 *	Returns two ciphertexts encrypting the bill and the reward, respectively,
 *	for each time slot.
 *
 *	All ciphertexts are encrypted under the client's key
 */
std::tuple< Ciphertext<DCRTPoly>,
			Ciphertext<DCRTPoly> >
				server_biling( 
								Ciphertext<DCRTPoly> consump,
								Ciphertext<DCRTPoly> supplies,
								Ciphertext<DCRTPoly> deviations,
								Ciphertext<DCRTPoly> bit_signs,
								std::vector<double> total_deviation,
								std::vector<double> trading_price,
								std::vector<double> retail_price,
								std::vector<double> feed_in_tarif,
								std::vector<double> total_consumers,
								std::vector<double> total_prosumers,
								CryptoContext<DCRTPoly>& cc
							 )
{
	vector<double> mask_total_dev_zero(total_deviation.size(), 0.0);
	vector<double> mask_total_dev_negative(total_deviation.size(), 0.0);
	vector<double> mask_total_dev_positive(total_deviation.size(), 0.0);
	for (unsigned int i = 0; i < total_deviation.size(); i++){
		if (0 == total_deviation[i])
			mask_total_dev_zero[i] = 1;
		else if (0 < total_deviation[i])
			mask_total_dev_positive[i] = 1;
		else
			mask_total_dev_negative[i] = 1;
	}

	Ciphertext<DCRTPoly> not_bit_signs = negate_all_slots(bit_signs, cc);

	// if total deviation == 0
	Ciphertext<DCRTPoly> bill_zero = pack_and_mult(consump, trading_price, cc);
	Ciphertext<DCRTPoly> reward_zero = pack_and_mult(supplies, trading_price, cc);

	// if total deviation < 0
	Ciphertext<DCRTPoly> reward_negative = reward_zero;
	// if total deviation < 0 and individual deviation <= 0
	Ciphertext<DCRTPoly> bill_negative = cc->EvalMult(bill_zero, bit_signs);
	// if total deviation < 0 and individual deviation > 0
	// 	  then bill = (consumption - (total deviation) / total_consumers) * trading_price + (total deviation) / total_consumers) * retail_price
	// 	            = consumption*trading_price + ((total deviation) / total_consumers) * (retail_price - trading_price)
	vector<double> tmp = (retail_price - trading_price) / total_consumers;
	tmp *= total_deviation;
	Ciphertext<DCRTPoly> tmp_bill = pack_and_add(bill_zero, tmp, cc);
	bill_negative += cc->EvalMult(tmp_bill, not_bit_signs); // "evaluate the if"

	// if total deviation > 0
	Ciphertext<DCRTPoly> bill_positive = bill_zero;
	// if total deviation > 0 and individual deviation <= 0
	Ciphertext<DCRTPoly> reward_positive = cc->EvalMult(reward_zero, bit_signs);
	// if total deviation > 0 and individual deviation > 0
	// 	  then reward = (supply - total_deviation / total_consumers) * trading_price + total deviation * feed_in_tarif / total_consumers
	// 	              = supply*trading_price + (total deviation / total_consumers) * (feed_in_tarif  - trading_price)
	// 	              = reward_zero + (total deviation / total_consumers) * (feed_in_tarif  - trading_price)
	tmp = (feed_in_tarif - trading_price) / total_consumers;
	tmp *= total_deviation;
	Ciphertext<DCRTPoly> tmp_reward = pack_and_add(reward_zero, tmp, cc);
	reward_negative += cc->EvalMult(tmp_reward, not_bit_signs); // "evaluate the if"

	// construct bill and reward using masks of total deviation defined above
	Ciphertext<DCRTPoly> bill = pack_and_mult(bill_zero, mask_total_dev_zero, cc);
    bill += pack_and_mult(bill_positive, mask_total_dev_positive, cc);
    bill += pack_and_mult(bill_negative, mask_total_dev_negative, cc);

	Ciphertext<DCRTPoly> reward = pack_and_mult(reward_zero, mask_total_dev_zero, cc);
    reward += pack_and_mult(reward_positive, mask_total_dev_positive, cc);
    reward += pack_and_mult(reward_negative, mask_total_dev_negative, cc);

	return {bill, reward};
}


int main() {

	srand(time(NULL));

	int n_time_slots = 8;

	CCParams<CryptoContextCKKSRNS> parameters = generate_parameters_ckks(n_time_slots);


    CryptoContext<DCRTPoly> cc = generate_crypto_context_ckks(parameters);


    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    auto keys = cc->KeyGen(); // encryption and decryption keys
    cc->EvalMultKeyGen(keys.secretKey); // generates relinearization key
	const PublicKey<DCRTPoly>& ckks_pub_key = keys.publicKey;

	// Just to debug
    std::cout << "Moduli chain of pk: " << std::endl;
    print_moduli_chain(ckks_pub_key);


	vector<double> offer(n_time_slots);
	vector<int> is_consumer(n_time_slots);
	client_auction(is_consumer, offer, n_time_slots);

	// C++17 structured binding: run client_setup to get ciphertexts encrypting
	// consumptions, supplies, deviations, and signs
    auto [ ct_consump, ct_supplies, ct_deviations, ct_signs ] = client_setup(is_consumer, offer, cc, ckks_pub_key);
    
    // XXX: for now, itializing with arbitrary constants. We have to decide how to fill in these vectors
    std::vector<double> total_deviation(n_time_slots, 0); // all zeros
    std::vector<double> trading_price(n_time_slots, 2.5); // all 2.5
    std::vector<double> retail_price(n_time_slots, 1.3); // all 1.3
    std::vector<double> feed_in_tarif(n_time_slots, 2); // all 2
    std::vector<double> total_consumers(n_time_slots, 10); // all 10
    std::vector<double> total_prosumers(n_time_slots, 20);

    auto [ ct_bill, ct_reward ] = server_biling( ct_consump, ct_supplies, ct_deviations, ct_signs,
                                                 total_deviation, trading_price, retail_price, feed_in_tarif,
                                                 total_consumers, total_prosumers,
								                 cc);


    return 0;
}
