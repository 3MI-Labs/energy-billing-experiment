#include <time.h>
#include <stdlib.h>
#include <cassert>
#include <fmt/core.h>
#include <fstream>

#include "utils_ckks.h"
#include "vectorutils.hpp"

const static int DAYS = 1;
const static int TIMESLOTS_PER_DAY = 24;
const static int TIMESLOTS = DAYS * TIMESLOTS_PER_DAY;

using namespace lbcrypto;

#include <sstream>
double string_to_double( const std::string& s )
{
	std::istringstream i(s);
	double x;
	if (!(i >> x))
		return 0;
	return x;
} 

int string_to_int( const std::string& s )
{
	std::istringstream i(s);
	int x;
	if (!(i >> x))
		return 0;
	return x;
} 

std::vector<double> separate_double(std::string line)
{
	std::vector<double> result;
	std::stringstream lineStream(line);
	std::string cell;

	// skip first element, it's a header
	std::getline(lineStream, cell, ',');

	while(std::getline(lineStream, cell, ','))
    {
		double val = string_to_double(cell);
		double new_val = std::ceil(val * 100.0) / 100.0;

		// std::cout << val << std::endl;
		if (new_val == 0 && val != 0) {
			std::cout << "zero" <<std::endl;
		}

        result.push_back(new_val);
    }


	return result;
}

std::vector<int> separate_int(std::string line)
{
	std::vector<int> result;
	std::stringstream lineStream(line);
	std::string cell;

	// skip first element; it's a header
	std::getline(lineStream, cell, ',');

	while(std::getline(lineStream, cell, ','))
    {
		int val = string_to_int(cell);
        result.push_back(val);
    }


	return result;
}

// /**
//  *  Load data
//  */
// std::tuple<std::vector<double>,
// 		   std::vector<double>,
// 		   std::vector<double>,
// 		   std::vector<double>,
// 		   std::vector<double>,
// 		   std::vector<double>,
// 		   std::vector<double>,
// 		   std::vector<double>,
// 		   std::vector<double>>
// int load_user_data(int user_idx)
// {
// 	std::string fname = "/home/erik/Documents/billing/energy-billing-data-generation/data/data_user_" + std::to_string(user_idx) + ".csv";

// 	std::cout <<fname<<std::endl;
// 	ifstream inputFile(fname);
// 	if (!inputFile.is_open()) {
// 		return 1;
// 	}

// 	std::string line;

// 	// Feed-in tarif
// 	getline(inputFile, line);
// 	std::vector<double> feed_in_tarif = separate_double(line);

// 	// Consumption
// 	getline(inputFile, line);
// 	std::vector<double> consumption = separate_double(line);

// 	// Supply
// 	getline(inputFile, line);
// 	std::vector<double> supply = separate_double(line);

// 	// Actual consumption (production - consumption)
// 	getline(inputFile, line);
// 	std::vector<double> cp_profile = separate_double(line);

// 	// Consumption/production prediction
// 	getline(inputFile, line);
// 	std::vector<double> promise = separate_double(line);

// 	// Retail price
// 	getline(inputFile, line);
// 	std::vector<double> retail_price = separate_double(line);

// 	// Total prosumers
// 	getline(inputFile, line);
// 	std::vector<double> total_prosumers = separate_int(line);

// 	// Total consumers
// 	getline(inputFile, line);
// 	std::vector<double> total_consumers = separate_int(line);

// 	// Trading price
// 	getline(inputFile, line);
// 	std::vector<double> trading_price = separate_double(line);

// 	// Total deviation
// 	getline(inputFile, line);
// 	std::vector<double> total_deviation = separate_double(line);

// 	// Individual deviation
// 	getline(inputFile, line);
// 	std::vector<double> deviation = separate_double(line);

// 	inputFile.close();

// 	const std::vector<int> &is_consumer, // one if consumer, 0 if prosumer
// 	const std::vector<double> &promise,	 // promised consumption/supply in each time slot
// 	CryptoContext<DCRTPoly> &cc,
// 	const PublicKey<DCRTPoly> &ckks_pk

// 	return {
// 		promise,
// 		consumption,
// 		supply,
// 		total_deviation,
// 		deviation,
// 		trading_price,
// 		retail_price,
// 		feed_in_tarif,
// 		total_consumers
// 	};
// }

/**
 *	Simulates the smart metter measuring the client's consumption in a time slot.
 *	Just returns a random "real" number between 0 and 10 with 2 decimal digits
 */
double measure_consumption()
{
	return 0.01 * (rand() % 1000);
}

/**
 *	Simulates the smart metter measuring the client's supply a time slot.
 *	Just returns a random "real" number between 0 and 10 with 2 decimal digits
 */
double measure_supply()
{
	return 0.01 * (rand() % 1000);
}

/**
 *  Simulates the process where the client estimate how much they will consume
 *	or supply for each time slot (which is sent to the P2P market in order to
 *	match consumers to prosumers).
 *
 *	At the end of the execution, we have
 *	is_consumer[i] = 1 if client is a consumer in the i-th time slot, and 0 otherwise
 *	offer[i] is the promised value to be consumed in the i-th time slot if
 *	is_consumer[i] == 1 and the promised value to be supplied if is_consumer[i] == 0
 *
 **/
void client_auction(std::vector<int> &is_consumer, std::vector<double> &offer, int n_time_slots)
{

	offer.resize(n_time_slots);
	is_consumer.resize(n_time_slots);

	for (int i = 0; i < n_time_slots; i++)
	{
		is_consumer[i] = rand() % 2;	   // XXX: for now, just decide at random if it is a consumer or not
		offer[i] = 0.01 * (rand() % 1000); // XXX: for now, just make a random offer
	}
}

/**
 * 	Definition of function client_setup:
 *
 *	Returns a tuple with ciphertexts encrypting the consumptions, the supplies,
 *	the deviations, and the signs of the deviations (marking negative or positive)
 */
std::tuple<Ciphertext<DCRTPoly>,
		   Ciphertext<DCRTPoly>,
		   Ciphertext<DCRTPoly>,
		   Ciphertext<DCRTPoly>,
		   vector<double>,
		   vector<double>,
		   vector<double>,
		   vector<double>,
		//    vector<double>,
		   vector<double>,
		   vector<double>>
client_setup(
	int user_idx,
	CryptoContext<DCRTPoly> &cc,
	const PublicKey<DCRTPoly> &ckks_pk)
{
	// Open specified datafile
	// std::string fname = "/home/erik/Documents/billing/energy-billing-data-generation/data/data_user_" + std::to_string(user_idx) + ".csv";
	std::string fname = "/home/erik/Documents/billing/energy-billing-data-generation/data/data_user_101.csv";
	std::cout << fname << std::endl;

	ifstream inputFile(fname);
	if (!inputFile.is_open()) {
		throw std::invalid_argument("cannot open specified file");
	}
	std::string line;

	// Skip header line
	getline(inputFile, line);

	// Feed-in tarif
	getline(inputFile, line);
	std::vector<double> feed_in_tarif = separate_double(line);
	assert(feed_in_tarif.size() == TIMESLOTS);

	// Consumption
	getline(inputFile, line);
	std::vector<double> consumptions = separate_double(line);
	assert(consumptions.size() == TIMESLOTS);

	// Supply
	getline(inputFile, line);
	std::vector<double> supplies = separate_double(line);
	assert(supplies.size() == TIMESLOTS);

	// Actual consumption (production - consumption)
	getline(inputFile, line);
	std::vector<double> cp_profile = separate_double(line);
	assert(cp_profile.size() == TIMESLOTS);

	// Consumption/production prediction
	getline(inputFile, line);
	std::vector<double> promise = separate_double(line);
	assert(promise.size() == TIMESLOTS);

	// Retail price
	getline(inputFile, line);
	std::vector<double> retail_price = separate_double(line);
	assert(retail_price.size() == TIMESLOTS);

	// Trading price
	getline(inputFile, line);
	std::vector<double> trading_price = separate_double(line);
	assert(trading_price.size() == TIMESLOTS);

	// Trading accepted
	getline(inputFile, line);
	std::vector<double> accepted = separate_double(line);
	assert(accepted.size() == TIMESLOTS);

	// Total prosumers
	getline(inputFile, line);
	std::vector<double> total_prosumers = separate_double(line);
	assert(total_prosumers.size() == TIMESLOTS);

	// Total consumers
	getline(inputFile, line);
	std::vector<double> total_consumers = separate_double(line);
	assert(total_consumers.size() == TIMESLOTS);

	// Total deviation
	getline(inputFile, line);
	std::vector<double> total_deviation = separate_double(line);
	assert(total_deviation.size() == TIMESLOTS);

	// Individual deviation
	getline(inputFile, line);
	std::vector<double> deviations = separate_double(line);
	assert(deviations.size() == TIMESLOTS);

	inputFile.close();

	// CryptoContext<DCRTPoly> &cc,
	// const PublicKey<DCRTPoly> &ckks_pk

	// Check that we can handle the data size.
	int n_time_slots = promise.size();
	int N = cc->GetRingDimension();
	assert(n_time_slots <= N / 2); // we can pack up to N/2 values into one ciphertext

	vector<double> sign_deviations(n_time_slots);

	for (int i = 0; i < n_time_slots; i++)
	{
		if (deviations[i] <= 0)
			sign_deviations[i] = 1;
		else
			sign_deviations[i] = 0;
	}

	// Encrypt the secret data
	Ciphertext<DCRTPoly> ct_consump = pack_and_encrypt(consumptions, cc, ckks_pk);
	Ciphertext<DCRTPoly> ct_supplies = pack_and_encrypt(supplies, cc, ckks_pk);
	Ciphertext<DCRTPoly> ct_deviations = pack_and_encrypt(deviations, cc, ckks_pk);
	Ciphertext<DCRTPoly> ct_signs = pack_and_encrypt(sign_deviations, cc, ckks_pk);

	return {
		ct_consump, 
		ct_supplies, 
		ct_deviations, 
		ct_signs,
		total_deviation, 
		// trading_price,
		retail_price, 
		feed_in_tarif,
		total_consumers,
		total_prosumers,
		accepted
	};
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
std::tuple<Ciphertext<DCRTPoly>,
		   Ciphertext<DCRTPoly>>
server_billing(
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
	std::vector<double> accepted,
	CryptoContext<DCRTPoly> &cc,
	PrivateKey<DCRTPoly> privkey
	)
{
	vector<double> mask_total_dev_zero(total_deviation.size(), 0.0);
	vector<double> mask_total_dev_negative(total_deviation.size(), 0.0);
	vector<double> mask_total_dev_positive(total_deviation.size(), 0.0);
	for (unsigned int i = 0; i < total_deviation.size(); i++)
	{
		if (total_deviation[i] == 0)
			mask_total_dev_zero[i] = 1;
		else if (total_deviation[i] > 0)
			mask_total_dev_positive[i] = 1;
		else // total_deviation[i] <= 0
			mask_total_dev_negative[i] = 1;
	}

	vector<double> rejected(accepted.size(), 0.0);
	for (unsigned int i = 0; i < accepted.size(); i++)
	{
		if (accepted[i] == 1.0)
		{
			rejected[i] = 0;
		}
		else
		{
			rejected[i] = 1;
		}
	}

	Ciphertext<DCRTPoly> not_bit_signs = negate_all_slots(bit_signs, cc);

	

	// CASE = not accepted -> retail price
	Ciphertext<DCRTPoly> bill_no_p2p = pack_and_mult(consump, retail_price, cc);
	Ciphertext<DCRTPoly> reward_no_p2p = pack_and_mult(supplies, feed_in_tarif, cc);

	// CASE = accepted -> p2p

		// CASE: TD == 0
			Ciphertext<DCRTPoly> bill_tot_dev_zero = pack_and_mult(consump, trading_price, cc);
			Ciphertext<DCRTPoly> reward_tot_dev_zero = pack_and_mult(supplies, trading_price, cc);
			

		// CASE: TD < 0
			// demand > supply
			// suppliers get trading price
			// = reward_tot_dev_zero

			// (under)consumers get trading price (and non-dev)
			// = bill_tot_dev_zero
			
			// overconsumers get punished = buy extra/split against retail price
			// bill = (dem - total_dev/nr_p2p_consumers) * trading price + total_dev/nr_p2p_consumers * retail_price
			//      = dem * trading_price + total_dev/nr_p2p_consumers * (retail_price - trading price)
			//      = bill_tot_dev_zero + total_dev / nr_p2p_consumers * (retail_price - trading price)

			vector<double> extra_bill_pt = ((retail_price - trading_price) / total_consumers) * total_deviation;
			Ciphertext<DCRTPoly> extra_bill_ct = pack_and_add(bill_tot_dev_zero, extra_bill_pt, cc);
			extra_bill_ct = cc->EvalMult(extra_bill_ct, bit_signs);
		
		// CASE: TD > 0
			// demand < supply
			// consumers pay trading price
			// = bill_tot_dev_zero

			// (under)prosumers get trading price (and non-dev)
			// = reward_tot_dev_zero

			// (over)prosumers get punished = sell extra/split against feedin tarif
			// reward = (supply - td / nr_p2p_prosumers) * tp + td / nr_p2p_prosumers * fit
			//        = supply * tp + (td / nr_p2p_prosumers * (fit - tp)
			//        = reward_tot_dev_zero + (td / nr_p2p_prosumers * (fit - tp)
			vector<double> reward_sub_pt = ((feed_in_tarif - trading_price) / total_prosumers) * total_deviation;
			Ciphertext<DCRTPoly> reward_sub_ct = pack_and_add(reward_tot_dev_zero, reward_sub_pt, cc);
			reward_sub_ct = cc->EvalMult(reward_sub_ct, not_bit_signs);


		// Aggregating the cases
		Ciphertext<DCRTPoly> bill_p2p = bill_tot_dev_zero + pack_and_mult(extra_bill_ct, mask_total_dev_negative, cc);
		Ciphertext<DCRTPoly> reward_p2p = reward_tot_dev_zero + pack_and_mult(reward_sub_ct, mask_total_dev_positive, cc);

	// Aggregating the cases
	Ciphertext<DCRTPoly> bill = pack_and_mult(bill_p2p, accepted, cc) + pack_and_mult(bill_no_p2p, rejected, cc);
	Ciphertext<DCRTPoly> reward = pack_and_mult(reward_p2p, accepted, cc) + pack_and_mult(reward_no_p2p, rejected, cc);
	




	// // if total deviation < 0
	// Ciphertext<DCRTPoly> reward_ind_dev_negative = reward_tot_dev_zero;
	// // if total deviation < 0 and individual deviation <= 0
	// Ciphertext<DCRTPoly> bill_ind_dev_negative = cc->EvalMult(bill_tot_dev_zero, bit_signs);
	// // if total deviation < 0 and individual deviation > 0
	// // 	  then bill = (consumption - (total deviation) / total_consumers) * trading_price + (total deviation) / total_consumers) * retail_price
	// // 	            = consumption*trading_price + ((total deviation) / total_consumers) * (retail_price - trading_price)
	// vector<double> tmp = (retail_price - trading_price) / total_consumers;
	// tmp *= total_deviation;
	// Ciphertext<DCRTPoly> tmp_bill = pack_and_add(bill_tot_dev_zero, tmp, cc);
	// bill_ind_dev_negative += cc->EvalMult(tmp_bill, not_bit_signs); // "evaluate the if"

	// // if total deviation > 0
	// Ciphertext<DCRTPoly> bill_ind_dev_positive = bill_tot_dev_zero;
	// // if total deviation > 0 and individual deviation <= 0
	// Ciphertext<DCRTPoly> reward_ind_dev_positive = cc->EvalMult(reward_tot_dev_zero, bit_signs);
	// // if total deviation > 0 and individual deviation > 0
	// // 	  then reward = (supply - total_deviation / total_consumers) * trading_price + total deviation * feed_in_tarif / total_consumers
	// // 	              = supply*trading_price + (total deviation / total_consumers) * (feed_in_tarif  - trading_price)
	// // 	              = reward_zero + (total deviation / total_consumers) * (feed_in_tarif  - trading_price)
	// tmp = (feed_in_tarif - trading_price) / total_prosumers;
	// tmp *= total_deviation;
	// Ciphertext<DCRTPoly> tmp_reward = pack_and_add(reward_tot_dev_zero, tmp, cc);
	// reward_ind_dev_negative += cc->EvalMult(tmp_reward, not_bit_signs); // "evaluate the if"

	// // construct bill and reward using masks of total deviation defined above
	// Ciphertext<DCRTPoly> bill_p2p = pack_and_mult(bill_tot_dev_zero, mask_total_dev_zero, cc);
	// bill_p2p += pack_and_mult(bill_ind_dev_positive, mask_total_dev_positive, cc);
	// bill_p2p += pack_and_mult(bill_ind_dev_negative, mask_total_dev_negative, cc);


	// Ciphertext<DCRTPoly> reward_p2p = pack_and_mult(reward_tot_dev_zero, mask_total_dev_zero, cc);
	// reward_p2p += pack_and_mult(reward_ind_dev_positive, mask_total_dev_positive, cc);
	// reward_p2p += pack_and_mult(reward_ind_dev_negative, mask_total_dev_negative, cc);

	// lbcrypto::Plaintext plain;
	// cc->Decrypt(privkey, reward_tot_dev_zero, &plain);
	// std::cout << "zero reward: " << plain << std::endl;
	// cc->Decrypt(privkey, reward_ind_dev_positive, &plain);
	// std::cout << "reward pos: " << plain << std::endl;
	// cc->Decrypt(privkey, reward_ind_dev_negative, &plain);
	// std::cout << "reward neg: " << plain << std::endl;


	
	// lbcrypto::Plaintext p2p_reward_plain;
	// cc->Decrypt(privkey, reward_p2p, &p2p_reward_plain);
	// std::cout << "p2p reward: " << p2p_reward_plain << std::endl;
	


	// lbcrypto::Plaintext no_p2p_reward_plain;
	// cc->Decrypt(privkey, reward_no_p2p, &no_p2p_reward_plain);
	// std::cout << "non p2p reward: " << no_p2p_reward_plain << std::endl;

	// Ciphertext<DCRTPoly> bill = pack_and_mult(bill_p2p, accepted, cc);
	// bill += pack_and_mult(bill_no_p2p, rejected, cc);
	// Ciphertext<DCRTPoly> reward = pack_and_mult(reward_p2p, accepted, cc);
	// reward += pack_and_mult(reward_no_p2p, rejected, cc);

	return {bill, reward};
}

int main()
{
	srand(time(NULL));

	int n_time_slots = 32;

	int user_idx = 122;

	CCParams<CryptoContextCKKSRNS> parameters = generate_parameters_ckks(n_time_slots);

	CryptoContext<DCRTPoly> cc = generate_crypto_context_ckks(parameters);

	std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl
			  << std::endl;

	auto keys = cc->KeyGen();			// encryption and decryption keys
	cc->EvalMultKeyGen(keys.secretKey); // generates relinearization key
	const PublicKey<DCRTPoly> &ckks_pub_key = keys.publicKey;

	// Just to debug
	std::cout << "Moduli chain of pk: " << std::endl;
	print_moduli_chain(ckks_pub_key);

	vector<double> offer(n_time_slots);
	vector<int> is_consumer(n_time_slots);
	client_auction(is_consumer, offer, n_time_slots);

	// C++17 structured binding: run client_setup to get ciphertexts encrypting
	// consumptions, supplies, deviations, and signs
	auto [ct_consump, 
		ct_supplies, 
		ct_deviations, 
		ct_signs,
		total_deviation, 
		// trading_price, 
		retail_price, 
		feed_in_tarif,
		total_consumers,
		total_prosumers,
		accepted] = client_setup(user_idx, cc, ckks_pub_key);

	// XXX: for now, itializing with arbitrary constants. We have to decide how to fill in these vectors
	// std::vector<double> total_deviation(n_time_slots, 0);  // all zeros
	std::vector<double> trading_price(TIMESLOTS, 0.11);  // all 2.5
	// std::vector<double> retail_price(n_time_slots, 1.3);   // all 1.3
	// std::vector<double> feed_in_tarif(n_time_slots, 0.05);	// all 2
	// std::vector<double> total_consumers(n_time_slots, 10);
	const PrivateKey<DCRTPoly> &ckks_priv_key = keys.secretKey;

	auto [ct_bill, ct_reward] = server_billing(
		ct_consump, 
		ct_supplies, 
		ct_deviations, 
		ct_signs,
		total_deviation, 
		trading_price, 
		retail_price, 
		feed_in_tarif,
		total_consumers,
		total_prosumers,
		accepted,
		cc,
		ckks_priv_key
	);
	

	// Bill per timeslot
	lbcrypto::Plaintext pt_bill;
	cc->Decrypt(ckks_priv_key, ct_bill, &pt_bill);
	std::cout << "Bill: " << pt_bill << std::endl;

	// Reward per timeslot
	lbcrypto::Plaintext pt_reward;
	cc->Decrypt(ckks_priv_key, ct_reward, &pt_reward);
	std::cout << "Reward: " << pt_reward << std::endl;

	return 0;
}
