/*
 * EML RSA - Alternative RSA implementation.
 * 
 * Authors:
 * Eduardo Garcia Misiuk <eduardogmisiuk@gmail.com>
 * Mauricio Caetano Silva <mauriciocaetanosilva@gmail.com>
 * Lucas Yudi Sugi <lucas.sugi@usp.br>
 */

/*
 	This file is part of EML RSA.

	EML RSA is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	EML RSA is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with EML RSA. If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <vector>
#include <gmpxx.h>

#include "eml-rsa.h"

#define DELIMITER '|'
#define CHUNK_SIZE 64
#define KEY_LENGTH_BITS 1024
#define REPEAT_MILLER_RABIN 50

/*
 * Generate random numbers.
 */
gmp_randclass rnd(gmp_randinit_default);

/*
 * Calculates the RC4 'S' permutation vector.
 */
void calculate_s_vector (std::vector<long int> &S, mpz_class subkey, long int message_size) {
	long int i, j = 0;
	mpz_class temp;
	for (i = 0; i < message_size; i++) S.push_back(i);
	for (i = 0; i < message_size; i++) {
		temp = j + S[i];
		temp += (long int) subkey.get_str()[i % subkey.get_str().size()];
		// temp = temp % 256
		mpz_mod(temp.get_mpz_t(), temp.get_mpz_t(), mpz_class(message_size).get_mpz_t());

		j = mpz_get_ui(temp.get_mpz_t());
		std::swap(S[i], S[j]);
	}
}

/*
 * RC4 permutation operation.
 */
void permutate_message (std::vector<long int> &S, std::string &message) {
	for (unsigned long int i = 0; i < message.size(); i++) {
		std::swap(message[i], message[S[i]]);
	}
}

/*
 * Inverse RC4 permutation operation.
 */
void depermutate_message (std::vector<long int> &S, std::string &message) {
	for (long int i = message.size()-1; i >= 0; i--) {
		std::swap(message[i], message[S[i]]);
	}
}

/*
 * Removes the delimiters to get the original message.
 */
void separate_tokens (std::string &message, std::string encrypted_message) {
	size_t j = 3;
	char d = DELIMITER;
	std::string delimiter = std::to_string((unsigned int) d);
	char temp;

	for (size_t i = 3; i < encrypted_message.size(); i++) {
		if (encrypted_message.substr(i, delimiter.size()) == delimiter) {
			// If this is true, the token is the delimiter, so we need to
			// go to the real delimiter
			if (i == j) continue;

			temp = (char) atoi(encrypted_message.substr(j, i-j).c_str());
			message += temp;

			i += delimiter.size() - 1;
			j = i + 1;
		}
	}
}

/*
 * EML RSA decryption algorithm.
 */
void eml_decrypt (std::vector<mpz_class> &encrypted_message, mpz_class &n, mpz_class &d, mpz_class &n1, std::vector<mpz_class> &subkeys, std::string &message) {
	mpz_class res;
	std::vector<long int> S; // S vector from RC4 algorithm

	// Since our message is separated by spaces, we can get
	// the characters directly from the file
	for (mpz_class &c : encrypted_message) {
		res = c;

		// Executing consecutives XOR operations
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[0].get_mpz_t());
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[1].get_mpz_t());
		// Caesar's Cypher
		res = res - n1;
		// Executing consecutives XOR operations
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[0].get_mpz_t());
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[1].get_mpz_t());

		// mpz_powm() doesn't prevent timing attacks, but mpz_powm_sec() does
		// res = character**d mod n
		mpz_powm_sec(res.get_mpz_t(), res.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());

		separate_tokens(message, res.get_str());
	}

	calculate_s_vector (S, subkeys[0], message.size());
	depermutate_message (S, message);
}

/*
 * Setups the data to call the decryption procedure.
 */
void decrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn) {
	mpz_class n, d, n1, res, block;
	std::vector<mpz_class> encrypted_message;
	std::vector<mpz_class> subkeys;

	std::string message = "";

	// Key and encrypted message files
	std::ifstream key_f, encrypted_message_f;
	// Decrypted message file
	std::ofstream message_f;

	// Reading the key from key_fn
	key_f.open(key_fn, std::ios::in);
	key_f >> n;
	key_f >> d;
	key_f >> n1;
	key_f.close();

	res = n.get_str().substr(0, 8);
	subkeys.push_back(res);
	res = n1.get_str().substr(0, 8);
	subkeys.push_back(res);

	// Reading the message from message_fn
	encrypted_message_f.open(encrypted_message_fn, std::ios::in | std::ios::binary);
	do {
		encrypted_message_f >> block;
		encrypted_message.push_back(block);
	} while (!encrypted_message_f.eof());
	// The last block at 'message' will be EOF, so we need to get rid of him
	encrypted_message_f.close();
	block = 0;

	// Decrypting the message with our decryption function
	eml_decrypt(encrypted_message, n, d, n1, subkeys, message);

	// Removing the values from the memory for security
	n = 0;
	d = 0;
	n1 = 0;
	res = 0;

	// Writes the message in the message file
	message_f.open(message_fn, std::ios::out);
	message_f << message;
	message_f.close();
}

/*
 * Divides a message in blocks to encrypt.
 */
void separate_chunks (std::string &message, std::vector<mpz_class> &chunks, int chunk_size) {
	std::string temp;
	std::string chunk;
	std::string delimiter = std::to_string(DELIMITER);
	mpz_class c;

	for (unsigned long long int i = 0; i < message.size(); i += chunk_size) {
		temp = message.substr(i, chunk_size);
		chunk = "";

		for (unsigned int j = 0; j < temp.size(); j++) {
			// Since we will convert to string, we need a delimiter to
			// be able to convert back to characters,
			// so we put, after every char, a delimiter.
			chunk += delimiter + std::to_string((unsigned char) temp[j]);
		}

		chunk += delimiter;

		// Converting to mpz_class
		c = chunk;

		chunks.push_back(c);
	}
}

/*
 * EML RSA encryption algorithm.
 */
void eml_encrypt (std::string &message, mpz_class &n, mpz_class &e, mpz_class &n1, std::vector<mpz_class> &subkeys, std::string &encrypted_message) {
	mpz_class res;
	std::vector<mpz_class> chunks;
	std::vector<long int> S; // S vector from RC4 algorithm

	calculate_s_vector (S, subkeys[0], message.size());
	permutate_message (S, message);

	separate_chunks (message, chunks, CHUNK_SIZE);

	for (mpz_class &c : chunks) {
		// We read the character as a unsigned char because the RSA needs the message to
		// be within 1 < character < n-1
		// Treating it as positive, we can encrypt any kind of file, since some
		// characters can be negative in images, for example
		res = c;
		// mpz_powm() doesn't prevent timing attacks, but mpz_powm_sec() does
		// res = res^e mod n
		mpz_powm_sec(res.get_mpz_t(), res.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
		// Replacing the message characters to improve security
		c = 0;

		// Executing consecutives XOR operations
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[1].get_mpz_t());
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[0].get_mpz_t());
		// Applying Caesar's Cypher with the second generated key
		res = res + n1;
		// Executing consecutives XOR operations
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[1].get_mpz_t());
		mpz_xor(res.get_mpz_t(), res.get_mpz_t(), subkeys[0].get_mpz_t());

		encrypted_message += res.get_str() + " ";
	}

	// There is some garbage at the end, so we remove it
	encrypted_message.pop_back();
}

/*
 * Setups the data to call the encryption procedure.
 */
void encrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn) {
	mpz_class n, n1, e, res, character;
	std::vector<mpz_class> subkeys;

	std::string message = "";
	std::string encrypted_message = "";
	std::string temp = "";

	// Key and message files
	std::ifstream key_f, message_f;
	std::ofstream encrypted_message_f;

	// Reading the key from key_fn
	key_f.open(key_fn, std::ios::in);
	key_f >> n;
	key_f >> e;
	key_f >> n1;
	key_f.close();

	// Generating subkeys using n and n1
	res = n.get_str().substr(0, 8);
	subkeys.push_back(res);
	res = n1.get_str().substr(0, 8);
	subkeys.push_back(res);

	// Reading the message from message_fn
	message_f.open(message_fn, std::ios::in);
	do {
		message += message_f.get();
	} while (!message_f.eof());
	// The last character at 'message' will be EOF, so we need to get rid of him
	message.pop_back();
	message_f.close();

	// Encrypting the message with our encryption function
	eml_encrypt(message, n, e, n1, subkeys, encrypted_message);

	// Removing the values from the memory for security
	n = 0;
	e = 0;
	n1 = 0;
	res = 0;

	encrypted_message_f.open(encrypted_message_fn, std::ios::out | std::ios::binary);
	encrypted_message_f << encrypted_message;
	encrypted_message_f.close();
}

/*
 * Generates a random number with specific_bits_length.
 */
mpz_class generate_rand_number(const unsigned int size, bool specific_bits_length){
	// Inferior limit (bits number)
	mpz_class min;
	mpz_ui_pow_ui(min.get_mpz_t(), 2, size-1);

	// Superior limit(numero de bits)
	mpz_class max;
	mpz_ui_pow_ui(max.get_mpz_t(), 2, size);
	
	mpz_class randnumber = rnd.get_z_range(max-min);

	//Se o modo for 2, o intervalo de sorteio eh: (0 - 2^size)
	if(!specific_bits_length) min = 0;
	
	return (min+randnumber);
}

/*
 * Generates a random number with specific_bits_length, given a seed.
 */
mpz_class generate_rand_number(const unsigned int size, unsigned long int seed, bool specific_bits_length){
	// Inferior limit (bits number)
	mpz_class min;
	mpz_ui_pow_ui(min.get_mpz_t(), 2, size-1);

	// Superior limit(numero de bits)
	mpz_class max;
	mpz_ui_pow_ui(max.get_mpz_t(), 2, size);
	
	mpz_class randnumber = rnd.get_z_range(max-min);

	// Verify if the generated number must have specific bit size
	if(!specific_bits_length) min = 0;
	
	return (min+randnumber);
}

/*
 * Generate a random prime number.
 */
mpz_class generate_rand_prime(const unsigned int size, unsigned long int seed){
	mpz_class candidate;
	mpz_class nx_prime;
	bool specific_bits_length = true;

	// Generates a random candidate number with specific size
	candidate = generate_rand_number(size, seed, specific_bits_length);

	// Check the primality of the candidate number with "Miller-Rabin" algorithm
	if(mpz_probab_prime_p(candidate.get_mpz_t(), REPEAT_MILLER_RABIN) == 0){	

		// If candidate isn't a prime, then select the next prime number greater than candidate 
		mpz_nextprime(nx_prime.get_mpz_t(), candidate.get_mpz_t());

		// Remove previous value of candidate for secury
		candidate = 0;
		return nx_prime;
	}

	return candidate;
}

/*
 * Find 'e' given that it is in ]1, totient[.
 */
mpz_class select_e(mpz_class tot){
	mpz_class e;
	mpz_class coprimes;
	bool specific_bits_length = false;
	
	// Select an integer "e" in the range of 1 < e < tot, "e" and tot are coprimes
	do{
		// "KEY_LENGTH_BITS - 1" ensures that "e" will have a smaller value than the totient "tot" 
		// because of its smaller size in bits
		e = generate_rand_number(KEY_LENGTH_BITS-1, specific_bits_length);

		// Verifies if "e" and "tot" are coprimes 
		mpz_gcd(coprimes.get_mpz_t(), e.get_mpz_t(), tot.get_mpz_t());
	}while(mpz_cmp_ui(coprimes.get_mpz_t(),1) != 0);

	coprimes = 0;	
	return e;
}

/*
 * Calculate d*e congruent 1 (mod totient).
 */
mpz_class modular_minverse(mpz_class e, mpz_class tot){
	mpz_class d;
	
	// Calculus of "d" as modular multiplicative inverse of e(modulo(tot))
	mpz_invert(d.get_mpz_t(), e.get_mpz_t(), tot.get_mpz_t());
	
	return d;
}

/*
 * Generates EML RSA keys.
 */
void generate_keys(unsigned long int seed, std::string &key_fn){
	rnd.seed(seed);

	// "p" and "q" are two prime numbers with the size "KEY_LENGTH_BITS"
	mpz_class p = generate_rand_prime(KEY_LENGTH_BITS, seed);
	mpz_class q = generate_rand_prime(KEY_LENGTH_BITS, seed);
	// Generating the second key
	mpz_class n1 = generate_rand_prime((KEY_LENGTH_BITS), seed);

	// "n" saves the value of p*q
	mpz_class n = p * q;

	// "Tot" contains the totient value lcm[(p-1)*(q-1)]
	mpz_class tot;
	mpz_class aux1 = p-1;
	mpz_class aux2 = q-1;
	p = 0;
	q = 0;

	mpz_lcm(tot.get_mpz_t(), aux1.get_mpz_t(), aux2.get_mpz_t());
	aux1 = 0;
	aux2 = 0;

	// Select an integer "e" in the range of 1 < e < tot, "e" and tot are coprimes
	mpz_class e = select_e(tot);

	// Calculus of "d" as modular multiplicative inverse of e(modulo(tot))
	mpz_class d = modular_minverse(e, tot);
 	tot = 0;

	// Create file with the public key
	std::string key_pub_fn = key_fn;
	key_pub_fn += ".pub";

	std::ofstream key_pub_f;
	key_pub_f.open(key_pub_fn, std::ios::out);
	key_pub_f << n;
	key_pub_f << "\n";
	key_pub_f << e;
	key_pub_f << "\n";
	key_pub_f << n1;
	key_pub_f.close();

	e = 0;

	// Create file with the private key
	std::string key_prv_fn = key_fn;
	key_prv_fn += ".prv";

	std::ofstream key_prv_f;
	key_prv_f.open(key_prv_fn, std::ios::out);
	key_prv_f << n;
	key_prv_f << "\n";
	key_prv_f << d;
	key_prv_f << "\n";
	key_prv_f << n1;
	key_prv_f.close();

	n = 0;
	n1 = 0;
	d = 0;
}
