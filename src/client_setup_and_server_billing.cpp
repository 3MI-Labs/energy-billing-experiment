#include <time.h>
#include <stdlib.h>
#include <cassert>
#include <fmt/core.h>
#include <fstream>
#include <sstream>

#include "utils_ckks.h"
#include "vectorutils.hpp"
#include "billing_tools.hpp"

// Experiment settings
static const int DAYS = 1;
static const int TIMESLOTS_PER_DAY = 24;
static const int TIMESLOTS = DAYS * TIMESLOTS_PER_DAY;
static const int NR_CLIENTS = 150;



using namespace lbcrypto;

/**
 * Load the context data
 *  
 * Returns a tuple with plaintext vectors containing
 * - the total deviation,
 * - the trading price,
 * - the retail price,
 * - the feed_in_tarif,
 * - the number of consumers, and
 * - the number of prosumers.
 * 
 * Each vector contains data for the entire round.
 */
std::tuple<vector<double>,
 		   vector<double>,
		   vector<double>,
		   vector<double>,
		   vector<double>>
context_setup()
{
	std::string fname = "/home/erik/Documents/billing/energy-billing-data-generation/data/" + std::to_string(TIMESLOTS) + "/context.csv";
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
	std::vector<double> feedInTarif = parseToDoubles(line);
	assert(feedInTarif.size() == TIMESLOTS);

	// Trading prices
	getline(inputFile, line);
	std::vector<double> tradingPrice = parseToDoubles(line);
	assert(tradingPrice.size() == TIMESLOTS);

	// Total consumers
	getline(inputFile, line);
	std::vector<double> totalConsumers = parseToDoubles(line);
	assert(totalConsumers.size() == TIMESLOTS);

	// Total prosumers
	getline(inputFile, line);
	std::vector<double> totalProsumers = parseToDoubles(line);
	assert(totalProsumers.size() == TIMESLOTS);

	// Total deviation
	getline(inputFile, line);
	std::vector<double> totalDeviation = parseToDoubles(line);
	assert(totalDeviation.size() == TIMESLOTS);

	return {
		feedInTarif,
		tradingPrice,
		totalProsumers,
		totalConsumers,
		totalDeviation
	};
}

/**
 * 
*/
std::tuple<
	std::vector<double>,
	std::vector<double>,
	std::vector<double>,
	std::vector<double>,
	std::vector<double>,
	std::vector<double>,
	std::vector<double>,
	std::vector<double>,
	std::vector<double>
>
load_client_data(int clientID)
{
	// Open specified datafile
	std::string fname = "/home/erik/Documents/billing/energy-billing-data-generation/data/" + std::to_string(TIMESLOTS) + "/data_user_" + std::to_string(clientID) + ".csv";
	std::cout << fname << std::endl;

	ifstream inputFile(fname);
	if (!inputFile.is_open()) {
		throw std::invalid_argument("cannot open specified file");
	}
	std::string line;

	// Skip header line
	getline(inputFile, line);

	// Retail price
	getline(inputFile, line);
	std::vector<double> retailPrice = parseToDoubles(line);
	assert(retailPrice.size() == TIMESLOTS);

	// Consumption promise
	getline(inputFile, line);
	std::vector<double> consumption_promise = parseToDoubles(line);
	assert(consumption_promise.size() == TIMESLOTS);

	// Supply promise
	getline(inputFile, line);
	std::vector<double> supply_promise = parseToDoubles(line);
	assert(supply_promise.size() == TIMESLOTS);

	// Consumption
	getline(inputFile, line);
	std::vector<double> consumptions = parseToDoubles(line);
	assert(consumptions.size() == TIMESLOTS);

	// Supply
	getline(inputFile, line);
	std::vector<double> supplies = parseToDoubles(line);
	assert(supplies.size() == TIMESLOTS);
	
	// Individual deviation
	getline(inputFile, line);
	std::vector<double> deviations = parseToDoubles(line);
	assert(deviations.size() == TIMESLOTS);

	// Trading accepted
	getline(inputFile, line);
	std::vector<double> accepted = parseToDoubles(line);
	assert(accepted.size() == TIMESLOTS);

	// Expected bill
	getline(inputFile, line);
	std::vector<double> expectedBill = parseToDoubles(line);
	assert(expectedBill.size() == TIMESLOTS);

	// Expected reward
	getline(inputFile, line);
	std::vector<double> expectedReward = parseToDoubles(line);
	assert(expectedReward.size() == TIMESLOTS);

	inputFile.close();

	return {
		consumptions,
		supplies,
		consumption_promise,
		supply_promise,
		retailPrice,
		accepted,
		deviations,
		expectedBill,
		expectedReward
	};
}

/**
 * Definition of function client_setup:
 *
 * Returns a tuple with ciphertexts encrypting 
 * - the consumptions, 
 * - the supplies,
 * - the deviations, and 
 * - the signs of the deviations (marking negative or positive).
 * 
 * and a (plaintext) vector containing data on whether a user is accepted or not.
 */
std::tuple<
	Ciphertext<DCRTPoly>,
	Ciphertext<DCRTPoly>,
	Ciphertext<DCRTPoly>,
	Ciphertext<DCRTPoly>,
	Ciphertext<DCRTPoly>
>
client_setup(
	CryptoContext<DCRTPoly> &cc, 
	const PublicKey<DCRTPoly> &ckks_pk,
	std::vector<double> consumptions,
	std::vector<double> supplies,
	std::vector<double> deviations,
	std::vector<double> accepted
)
{
	// Compute signs of individual deviations
	vector<double> sign_deviations(TIMESLOTS);
	for (int i = 0; i < TIMESLOTS; i++)
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
	Ciphertext<DCRTPoly> ct_accepted = pack_and_encrypt(accepted, cc, ckks_pk);

	return {
		ct_consump, 
		ct_supplies, 
		ct_deviations, 
		ct_signs,
		ct_accepted
	};
}
/* 	END definition of function client_setup  */

std::tuple<
	std::vector<double>,
	std::vector<double>,
	std::vector<double>
>
server_setup(std::vector<double> totalDeviation)
{
	// Create total deviation masks
	vector<double> maskTotalDevZero(totalDeviation.size(), 0.0);
	vector<double> maskTotalDevNegative(totalDeviation.size(), 0.0);
	vector<double> maskTotalDevPositive(totalDeviation.size(), 0.0);
	for (unsigned int i = 0; i < totalDeviation.size(); i++)
	{
		if (totalDeviation[i] == 0)
			maskTotalDevZero[i] = 1;
		else if (totalDeviation[i] > 0)
			maskTotalDevPositive[i] = 1;
		else // total_deviation[i] < 0
			maskTotalDevNegative[i] = 1;
	}
	return {
		maskTotalDevPositive,
		maskTotalDevZero,
		maskTotalDevNegative
	};
}

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
	CryptoContext<DCRTPoly> &cc,
	PublicKey<DCRTPoly> publickey,
	PrivateKey<DCRTPoly> privkey, // todo: remove

	// Context information
	std::vector<double> tradingPrice,
	std::vector<double> retailPrice,
	std::vector<double> feedInTarif,
	std::vector<double> totalP2PConsumers,
	std::vector<double> totalP2PProsumers,

	// Deviation information
	std::vector<double> totalDeviation,
	std::vector<double>	maskTotalDevPositive,
	std::vector<double>	maskTotalDevZero,
	std::vector<double>	maskTotalDevNegative,

	// Private information
	Ciphertext<DCRTPoly> consumption,
	Ciphertext<DCRTPoly> supplies,
	Ciphertext<DCRTPoly> deviations,
	Ciphertext<DCRTPoly> negDevSigns,
	Ciphertext<DCRTPoly> accepted
)
{
	// Create rejected; a dual to the accepted mask
	Ciphertext<DCRTPoly> rejected = negate_all_slots(accepted, cc);
	Ciphertext<DCRTPoly> nonNegDevSigns = negate_all_slots(negDevSigns, cc);
	

	// CASE: User not accepted for P2P trading -> they pay/get retail price
	Ciphertext<DCRTPoly> bill_no_p2p = pack_and_mult(consumption, retailPrice, cc);
	Ciphertext<DCRTPoly> reward_no_p2p = pack_and_mult(supplies, feedInTarif, cc);

	// lbcrypto::Plaintext pt;
	// cc->Decrypt(privkey, reward_no_p2p, &pt);
	// std::cout << "Reward no p2p: " << pt << std::endl;
	// cc->Decrypt(privkey, supplies, &pt);
	// std::cout << "supplies: " << pt << std::endl;
	// std::cout << "fit: " << feedInTarif[1] << std::endl;

	// CASE: User was accepted for P2P trading
			Ciphertext<DCRTPoly> baseBill = pack_and_mult(consumption, tradingPrice, cc);
			Ciphertext<DCRTPoly> baseReward = pack_and_mult(supplies, tradingPrice, cc);

		// CASE: TD == 0
		    // consumer <- baseBill
			// prosumer <- baseReward

		// CASE: TD < 0
			// demand > supply

			// prosumer <- baseReward

			// CASE: indiv dev <= 0
				// consumer <- baseBill
			
			// CASE: indiv dev > 0
				// consumer gets a billSupplement; buy their portion of what was used too much against retail price.
				// bill = (consumption - TD / nr_p2p_consumers) * tradingPrice + TD / nr_p2p_consumers * retailPrice
				//      = consumption * tradingPrice + TD / nr_p2p_consumers * (retailPrice - tradingPrice)
				//      = baseBill + TD / nr_p2p_consumers * (retail_price - trading price)
				// hence,
				// supplement = TD / nr_p2p_consumers * (retail_price - trading price)

				vector<double> billSupplement_pt = ((retailPrice - tradingPrice) / totalP2PConsumers) * totalDeviation;
				Ciphertext<DCRTPoly> billSupplement_ct = pack_and_encrypt(billSupplement_pt, cc, publickey);
				billSupplement_ct = cc->EvalMult(billSupplement_ct, nonNegDevSigns);
		
		// CASE: TD > 0
			// demand < supply

			// consumers <- baseBill

			// CASE: indiv dev <= 0
				// prosumers <- baseReward

			// CASE: indiv dev > 0
				// prosumers get a penalty; they sell their portion of what was produced too much against feedin tarif
				// reward = (supply - TD / nr_p2p_prosumers) * tradingPrice + TD / nr_p2p_prosumers * feedInTarif
				//        = supply * tradingPrice + (TD / nr_p2p_prosumers * (feedInTarif - tradingPrice)
				//        = baseReward + (TD / nr_p2p_prosumers * (feedInTarif - tradingPrice)
				// hence,
				// penalty = (TD / nr_p2p_prosumers * (feedInTarif - tradingPrice)
				//
				// Note that the penalty is negative, since feedInTarif is assumed to be < tradingPrice
				vector<double> rewardPenalty_pt = ((feedInTarif - tradingPrice) / totalP2PProsumers) * totalDeviation;
				Ciphertext<DCRTPoly> rewardPenalty_ct = pack_and_encrypt(rewardPenalty_pt, cc, publickey);
				rewardPenalty_ct = cc->EvalMult(rewardPenalty_ct, nonNegDevSigns);

		// Aggregating the P2P cases
		Ciphertext<DCRTPoly> bill_p2p = baseBill + pack_and_mult(billSupplement_ct, maskTotalDevNegative, cc);
		Ciphertext<DCRTPoly> reward_p2p = baseReward + pack_and_mult(rewardPenalty_ct, maskTotalDevPositive, cc);

	// Aggregating P2P and no-P2P cases
	Ciphertext<DCRTPoly> bill_ct = cc->EvalMult(bill_p2p, accepted) + cc->EvalMult(bill_no_p2p, rejected);
	Ciphertext<DCRTPoly> reward_ct = cc->EvalMult(reward_p2p, accepted) + cc->EvalMult(reward_no_p2p, rejected);
	
	return {bill_ct, reward_ct};
}

void experiment()
{
	// Generate FHE context
	static const int N_TIME_SLOTS = 256;
	CCParams<CryptoContextCKKSRNS> parameters = generate_parameters_ckks(N_TIME_SLOTS);
	CryptoContext<DCRTPoly> cc = generate_crypto_context_ckks(parameters);
	std::cout << "CKKS scheme is using ring dimension " 
			  << cc->GetRingDimension()
			  << std::endl;

	// Check that we can handle the expected data size.
	int N = cc->GetRingDimension();
	assert(TIMESLOTS <= N / 2); // we can pack up to N/2 values into one ciphertext.

	// Generate FHE key-pair
	auto keys = cc->KeyGen();			// encryption and decryption keys
	cc->EvalMultKeyGen(keys.secretKey); // generates relinearization key
	const PublicKey<DCRTPoly> &ckks_pub_key = keys.publicKey;
	const PrivateKey<DCRTPoly> &ckks_priv_key = keys.secretKey;

	// Load experiment context
	auto [
		feedInTarif,
		tradingPrice,
		totalProsumers,
		totalConsumers,
		totalDeviation
	] = context_setup();

	// Setup server
	auto [
		maskTotalDevPositive,
		maskTotalDevZero,
		maskTotalDevNegative
	] = server_setup(totalDeviation);

	// Run experiment
	std::vector<double> client_timings(NR_CLIENTS, 0);
	std::vector<double> server_timings(NR_CLIENTS, 0);
	for (int userID = 0; userID < NR_CLIENTS; userID++)
	{
		// Load client data
		auto [
			consumptions,
			supplies,
			consumption_promise,
			supply_promise,
			retailPrice,
			accepted,
			deviations,
			expectedBill,
			expectedReward
		] = load_client_data(userID);		

		std::cout << consumptions[0] << std::endl;
		std::cout << supplies[0] << std::endl;
		std::cout << retailPrice[0] << std::endl;

		// Setup client
		std::cout << "Running client setup" << std::endl;
		auto [
			ct_consumption, 
			ct_supplies, 
			ct_deviations, 
			ct_signs,
			ct_accepted
		] = client_setup(cc, ckks_pub_key, consumptions, supplies, deviations, accepted);

		// Execute server billing
		std::cout << "Running billing" << std::endl;
		auto [ct_bill, ct_reward] = server_billing(
			cc,
			ckks_pub_key,
			ckks_priv_key,

			tradingPrice,
			retailPrice,
			feedInTarif,
			totalConsumers,
			totalProsumers,

			totalDeviation,
			maskTotalDevPositive,
			maskTotalDevZero,
			maskTotalDevNegative,

			ct_consumption,
			ct_supplies, 
			ct_deviations, 
			ct_signs,
			ct_accepted
		);

		// Decrypt bill and reward per timeslot
		lbcrypto::Plaintext pt_bill;
		cc->Decrypt(ckks_priv_key, ct_bill, &pt_bill);
		std::cout << "Bill: " << pt_bill << std::endl;

		lbcrypto::Plaintext pt_reward;
		cc->Decrypt(ckks_priv_key, ct_reward, &pt_reward);
		std::cout << "Reward: " << pt_reward << std::endl;

		// if (userID < 30) {
		// 	// Prosumers; only validate reward
		// 	for (int i = 0; i < TIMESLOTS; i ++) {
		// 		double reward = pt_reward[i];
		// 		assert(reward == expectedReward[i]);
		// 	}
		// } else {
		// 	// Consumer; only validate bill
		// 	for (int i = 0; i < TIMESLOTS; i ++) {
		// 		assert(pt_bill[i] == expectedBill[i]);
		// 	}

		// }
	}


}

int main()
{
	experiment();
	
	// for (int i = 0; i < NR_CLIENTS; i++)
	// {
	// 	// Generate FHE key-pair
	// 	auto keys = cc->KeyGen();			// encryption and decryption keys
	// 	cc->EvalMultKeyGen(keys.secretKey); // generates relinearization key
	// 	const PublicKey<DCRTPoly> &ckks_pub_key = keys.publicKey;
	// 	const PrivateKey<DCRTPoly> &ckks_priv_key = keys.secretKey;

	// 	// Just to debug
	// 	std::cout << "Moduli chain of pk: " << std::endl;
	// 	print_moduli_chain(ckks_pub_key);

	// 	// Compute bill
	// 	auto [ct_bill, ct_reward] = compute_bill(cc, ckks_pub_key, ckks_priv_key, i);

	// 	// Bill per timeslot
	// 	lbcrypto::Plaintext pt_bill;
	// 	cc->Decrypt(ckks_priv_key, ct_bill, &pt_bill);
	// 	std::cout << "Bill: " << pt_bill << std::endl;

	// 	// Reward per timeslot
	// 	lbcrypto::Plaintext pt_reward;
	// 	cc->Decrypt(ckks_priv_key, ct_reward, &pt_reward);
	// 	std::cout << "Reward: " << pt_reward << std::endl;
	// }

	return 0;
}
