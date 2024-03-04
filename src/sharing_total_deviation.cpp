#include "csprng.h"
#include "vectorutils.hpp"
#include <vector>
#include <iostream>
#include <cassert>
#include <chrono>
#include <time.h>

using namespace std;

static const int MODULUS = 759250133; // 30-bit prime (close to 2^29.5)
static const int NR_TIME_SLOTS = 1000; // each user will generate shares for this amount of time slots

#define SEED int8_t* 

SEED gen_random_seed() {
	SEED s = (SEED) malloc(16 * sizeof(int8_t));
	for(int i = 0; i < 16; i++)
		s[i] = rand() % 256;
	return s;
}

void erase_seed(SEED s) {
	free(s);
}

void print_seed(SEED s) {
	if (NULL == s) {
		cout << "{ }" << endl;
	}else {
		for(int i = 0; i < 16; i++)
			cout << (int) s[i] << " ";
		cout << endl;
	}
}

/** Generates the O(n^2) seeds corresponding to all the n users */
vector<vector<SEED>> generate_seed_matrix(int n_users) {
	vector<vector<SEED> > seed_matrix(n_users);
	for(int i = 0; i < n_users; i++){
		seed_matrix[i] = vector<SEED>(n_users);
		for(int j = 0; j < n_users; j++){
			if (i == j){
				seed_matrix[i][j] = NULL;
			}else {
				seed_matrix[i][j] = gen_random_seed();
			}
		}
	}
	return seed_matrix;
}
/** Generates the O(n^2) seeds corresponding to all the n users */
void delete_seed_matrix(vector<vector<SEED> >& seed_matrix){
    int n_users = seed_matrix.size();
	for(int i = 0; i < n_users; i++){
		for(int j = 0; j < n_users; j++){
			if (i != j){
			    erase_seed(seed_matrix[i][j]);
			}
		}
	}
}

vector<vector<CSPRNG*> > init_csprngs(const vector<vector<SEED> >& seeds, int n_time_slots, int modulus) {
    int n_users = seeds.size();
	vector<vector<CSPRNG*> > csprng_matrix(n_users);
	for(int i = 0; i < n_users; i++){
		csprng_matrix[i] = vector<CSPRNG*>(n_users);
		for(int j = 0; j < n_users; j++){
			if (i == j){
				csprng_matrix[i][j] = NULL;
			} else {
				csprng_matrix[i][j] = new CSPRNG(seeds[i][j]);
			}
		}
	}
	return csprng_matrix;
}

vector<vector<CSPRNG*> > setup(int n_users, int n_time_slots, int modulus) {
    vector<vector<SEED> > seeds = generate_seed_matrix(n_users);
    vector<vector<CSPRNG*> > csprngs = init_csprngs(seeds, n_time_slots, modulus);
    delete_seed_matrix(seeds);

    return csprngs;
}

int generate_share(int user_id, int round, int modulus, const vector<vector<CSPRNG*> >& csprngs) {
    int n_users = csprngs.size();
    int share = 0;
    int iv = 126 + (1 << 7) * round;
    for (int j = 0; j < n_users; j++){
        if (user_id != j){
            csprngs[user_id][j]->generate_random_bytes(iv, 1, modulus, 0);
        	share += csprngs[user_id][j]->get_random_int(modulus);
//            cout << "  +share = " << share << endl;
            share %= modulus;
        }
    }

    for (int i = 0; i < n_users; i++){
        if (user_id != i){
            csprngs[i][user_id]->generate_random_bytes(iv, 1, modulus, 0);
        	share -= csprngs[i][user_id]->get_random_int(modulus);
//            cout << "  -share = " << share << endl;
            share %= modulus;
        }
    }
	return share;
}

vector<int> generate_shares(int& round, int modulus, const vector<vector<CSPRNG*> >& csprngs) {
    int n_users = csprngs.size();
    vector<int> shares(n_users);
    for (int i = 0; i < n_users; i++)
        shares[i] = generate_share(i, round, modulus, csprngs);
    round++;
    return shares;
}


void test_shares(int n_users){
	cout << "csprngs = setup(n_users, n_time_slots, modulus);" << endl;
	vector<vector<CSPRNG*> > csprngs = setup(n_users, NR_TIME_SLOTS, MODULUS);

    int round = 0;

    vector<int> shares(n_users);

    for(int i = 0; i < NR_TIME_SLOTS; i++){
        if (0 == i%100)
            cout << "generating shares for round " << round << endl;
        shares = generate_shares(round, MODULUS, csprngs);
        int s = sum_mod(shares, MODULUS);

        assert(0 == s); // sum of shares = 0 mod modulus

        // now check randomness of shares
        for(int u = 0; u < n_users; u++){
            for(int v = 0; v < n_users; v++){
                if (u != v)
                    assert(shares[u] != shares[v]); // fails with negligible probability       
            }
        }
    }

}

/**
 * Test how long it takes to generate CSPRNG keys.
 */ 
void prngkeygen_experiment()
{
    for (int nr_users = 50; nr_users <= 500; nr_users += 50)
    {
        for (int nr_timeslots = 100; nr_timeslots <= 1000; nr_timeslots *= 10)
        {
            // Time the setup function
            auto setup_begin = std::chrono::high_resolution_clock::now();
            setup(nr_users, nr_timeslots, MODULUS);
            auto setup_end = std::chrono::high_resolution_clock::now();
            auto setup_duration = std::chrono::duration_cast<std::chrono::microseconds>(setup_end - setup_begin).count();

            // Display results
            std::cout << "nr_users: " << nr_users << ", "
                      << "nr_time_slots: " << nr_timeslots 
                      << " -> " << setup_duration 
                      << std::endl;
        }
    }
}


int main() {
    srand(time(NULL)); // XXX not secure. Enough for timing experiments.

    prngkeygen_experiment();

	return 0;
}
