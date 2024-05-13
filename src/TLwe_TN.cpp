#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/lwe-functions.h>
#include <tfhe/numeric_functions.h>
#include <tfhe/tlwe_functions.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstdint>
#include <fstream>

#include "threshold_decryption_functions.hpp"

std::vector<std::string> candidates = {"Captain America", "Iron Man", "Thor"};

int main(int argc, char *argv[])
{
	std::ifstream winner_file("app/winner.txt");

	std::string line;
	std::getline(winner_file, line);

	std::istringstream iss(line);
	int t, p, winner;
	std::vector<int> subset;

	iss >> t >> p;

	int party_id;
	while (iss >> party_id)
	{
		if (party_id <= p)
			subset.push_back(party_id);
	}

	// next line has a single integer which is the winner
	std::getline(winner_file, line);
	winner = std::stoi(line);

	// Sort and remove duplicates
	std::sort(subset.begin(), subset.end());
	auto it = std::unique(subset.begin(), subset.end());
	subset.resize(std::distance(subset.begin(), it));

	if (subset.size() < static_cast<size_t>(t))
	{
		std::cout << "Error: Provide at least " << t << " unique party-ids.\n";
		return 1;
	}

	// print all the values
	std::cout << "t: " << t << "\n";
	std::cout << "p: " << p << "\n";
	std::cout << "Party-ids: ";
	for (int i = 0; i < subset.size(); i++)
		std::cout << subset[i] << " ";
	std::cout << "\n";
	std::cout << "Winner: " << candidates[winner] << "\n";

	// Close the file
	winner_file.close();

	TLweParams *params = new_TLweParams(1024, 2, 0.01, 0.2);
	TLweKey *key = new_TLweKey(params);
	tLweKeyGen(key);

	// std::cout << "Key: [";
	// for (int i = 0; i < params->N; i++)
	// 	std::cout << key->key->coefs[i] << ", ";
	// std::cout << "]\n";

	TLweSample *ciphertext = new_TLweSample(params);
	TorusPolynomial *mu = new_TorusPolynomial(params->N);

	for (int i = 0; i < params->N; i++)
		mu->coefsT[i] = 0;

	for (int i = 0; i < 32; i++)
		mu->coefsT[i] += modSwitchToTorus32((winner >> i) & 1, MSIZE);

	tLweSymEncrypt(ciphertext, mu, 3e-8, key);

	// std::cout << "Ciphertext: [";
	// for (int i = 0; i < params->N; i++)
	// 	std::cout << ciphertext->a->coefsT[i] << ", ";
	// std::cout << "]\n";

	// std::cout << "Message (Torus): [";
	// for (int i = 0; i < params->N; i++)
	// 	std::cout << mu->coefsT[i] << ", ";
	// std::cout << "]\n";

	// int dmsg = 0;
	// TorusPolynomial *res = new_TorusPolynomial(params->N);
	// tLweSymDecrypt(res, ciphertext, key, MSIZE);

	// for (int i = 0; i < 32; i++)
	// 	dmsg += (modSwitchFromTorus32(res->coefsT[i], MSIZE) << i);

	// std::cout << "Direct Decryption result: " << dmsg << std::endl;

	struct timespec share_start, share_end;
	clock_gettime(CLOCK_MONOTONIC, &share_start);
	unsigned int high, low;
	__asm__ __volatile__("xorl %%eax,%%eax\n cpuid \n" ::: "%eax", "%ebx", "%ecx", "%edx");
	__asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
	auto clock_start_sharing = (static_cast<uint64_t>(high) << 32) | low;

	shareSecret2(t, p, key, params);

	__asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
	auto clock_stop_sharing = (static_cast<uint64_t>(high) << 32) | low;
	clock_gettime(CLOCK_MONOTONIC, &share_end);

	std::cout << "Secret Sharing Time: " << (((double)share_end.tv_nsec + 1.0e+9 * share_end.tv_sec) - ((double)share_start.tv_nsec + 1.0e+9 * share_start.tv_sec)) * 1.0e-9 << " sec (" << clock_stop_sharing - clock_start_sharing << " cycles)\n";

	double bound = 0.025;
	uint64_t *cycle_counts_partial = new uint64_t[t];
	uint64_t *cycle_counts_final = new uint64_t[t];
	TorusPolynomial **partial_ciphertexts = new TorusPolynomial *[t];

	for (int i = 0; i < t; i++)
		partial_ciphertexts[i] = new_TorusPolynomial(params->N);

	// while (bound > 1e-5)
	// {
	std::cout << "Noise: " << bound << '\n';
	for (int i = 0; i < t; i++)
	{
		cycle_counts_partial[i] = 0;
		cycle_counts_final[i] = 0;
		for (int j = 0; j < params->N; j++)
			partial_ciphertexts[i]->coefsT[j] = 0;
	}

	for (int i = 0; i < t; i++)
		partialDecrypt(ciphertext, params, partial_ciphertexts[i], cycle_counts_partial, i, subset, t, p, bound);

	for (int i = 0; i < t; i++)
		finalDecrypt(ciphertext, partial_ciphertexts, params, cycle_counts_final, i, subset, t, p);

	// 		bound /= 2;
	// 	}
}